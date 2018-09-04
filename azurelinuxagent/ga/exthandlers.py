# Microsoft Azure Linux Agent
#
# Copyright Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and Openssl 1.0+
#

import datetime
import glob
import json
import operator
import os
import random
import re
import shutil
import stat
import subprocess
import time
import traceback
import zipfile

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.version as version

from azurelinuxagent.common.cgroups import CGroups, CGroupsTelemetry
from azurelinuxagent.common.errorstate import ErrorState, ERROR_STATE_DELTA_DEFAULT, ERROR_STATE_DELTA_INSTALL
from azurelinuxagent.common.event import add_event, WALAEventOperation, elapsed_milliseconds, report_event
from azurelinuxagent.common.exception import ExtensionError, ProtocolError, ProtocolNotFoundError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import ExtHandlerStatus, \
                                                    ExtensionStatus, \
                                                    ExtensionSubStatus, \
                                                    VMStatus, ExtHandler, \
                                                    get_properties, \
                                                    set_properties
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.processutil import capture_from_process
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION


# HandlerEnvironment.json schema version
HANDLER_ENVIRONMENT_VERSION = 1.0

EXTENSION_STATUS_ERROR = 'error'
VALID_EXTENSION_STATUS = ['transitioning', 'error', 'success', 'warning']

VALID_HANDLER_STATUS = ['Ready', 'NotReady', "Installing", "Unresponsive"]

HANDLER_PATTERN = "^([^-]+)-(\d+(?:\.\d+)*)"
HANDLER_NAME_PATTERN = re.compile(HANDLER_PATTERN+"$", re.IGNORECASE)
HANDLER_PKG_EXT = ".zip"
HANDLER_PKG_PATTERN = re.compile(HANDLER_PATTERN + r"\.zip$", re.IGNORECASE)


def validate_has_key(obj, key, fullname):
    if key not in obj:
        raise ExtensionError("Missing: {0}".format(fullname))


def validate_in_range(val, valid_range, name):
    if val not in valid_range:
        raise ExtensionError("Invalid {0}: {1}".format(name, val))


def parse_formatted_message(formatted_message):
    if formatted_message is None:
        return None
    validate_has_key(formatted_message, 'lang', 'formattedMessage/lang')
    validate_has_key(formatted_message, 'message', 'formattedMessage/message')
    return formatted_message.get('message')


def parse_ext_substatus(substatus):
    # Check extension sub status format
    validate_has_key(substatus, 'status', 'substatus/status')
    validate_in_range(substatus['status'], VALID_EXTENSION_STATUS,
                      'substatus/status')
    status = ExtensionSubStatus()
    status.name = substatus.get('name')
    status.status = substatus.get('status')
    status.code = substatus.get('code', 0)
    formatted_message = substatus.get('formattedMessage')
    status.message = parse_formatted_message(formatted_message)
    return status


def parse_ext_status(ext_status, data):
    if data is None or len(data) is None:
        return
    # Currently, only the first status will be reported
    data = data[0]
    # Check extension status format
    validate_has_key(data, 'status', 'status')
    status_data = data['status']
    validate_has_key(status_data, 'status', 'status/status')

    status = status_data['status']
    if status not in VALID_EXTENSION_STATUS:
        status = EXTENSION_STATUS_ERROR

    applied_time = status_data.get('configurationAppliedTime')
    ext_status.configurationAppliedTime = applied_time
    ext_status.operation = status_data.get('operation')
    ext_status.status = status
    ext_status.code = status_data.get('code', 0)
    formatted_message = status_data.get('formattedMessage')
    ext_status.message = parse_formatted_message(formatted_message)
    substatus_list = status_data.get('substatus')
    if substatus_list is None:
        return
    for substatus in substatus_list:
        if substatus is not None:
            ext_status.substatusList.append(parse_ext_substatus(substatus))


def migrate_handler_state():
    """
    Migrate handler state and status (if they exist) from an agent-owned directory into the
    handler-owned config directory

    Notes:
     - The v2.0.x branch wrote all handler-related state into the handler-owned config
       directory (e.g., /var/lib/waagent/Microsoft.Azure.Extensions.LinuxAsm-2.0.1/config).
     - The v2.1.x branch original moved that state into an agent-owned handler
       state directory (e.g., /var/lib/waagent/handler_state).
     - This move can cause v2.1.x agents to multiply invoke a handler's install command. It also makes
       clean-up more difficult since the agent must remove the state as well as the handler directory.
    """
    handler_state_path = os.path.join(conf.get_lib_dir(), "handler_state")
    if not os.path.isdir(handler_state_path):
        return

    for handler_path in glob.iglob(os.path.join(handler_state_path, "*")):
        handler = os.path.basename(handler_path)
        handler_config_path = os.path.join(conf.get_lib_dir(), handler, "config")
        if os.path.isdir(handler_config_path):
            for file in ("State", "Status"):
                from_path = os.path.join(handler_state_path, handler, file.lower())
                to_path = os.path.join(handler_config_path, "Handler" + file)
                if os.path.isfile(from_path) and not os.path.isfile(to_path):
                    try:
                        shutil.move(from_path, to_path)
                    except Exception as e:
                        logger.warn(
                            "Exception occurred migrating {0} {1} file: {2}",
                            handler,
                            file,
                            str(e))

    try:
        shutil.rmtree(handler_state_path)
    except Exception as e:
        logger.warn("Exception occurred removing {0}: {1}", handler_state_path, str(e))
    return


class ExtHandlerState(object):
    NotInstalled = "NotInstalled"
    Installed = "Installed"
    Enabled = "Enabled"
    Failed = "Failed"


def get_exthandlers_handler():
    return ExtHandlersHandler()


class ExtHandlersHandler(object):
    def __init__(self):
        self.protocol_util = get_protocol_util()
        self.protocol = None
        self.ext_handlers = None
        self.last_etag = None
        self.log_report = False
        self.log_etag = True
        self.log_process = False

        self.report_status_error_state = ErrorState()
        self.get_artifact_error_state = ErrorState(min_timedelta=ERROR_STATE_DELTA_INSTALL)

    def run(self):
        self.ext_handlers, etag = None, None
        try:
            self.protocol = self.protocol_util.get_protocol()
            self.ext_handlers, etag = self.protocol.get_ext_handlers()
            self.get_artifact_error_state.reset()
        except Exception as e:
            msg = u"Exception retrieving extension handlers: {0}".format(ustr(e))
            detailed_msg = '{0} {1}'.format(msg, traceback.format_exc())

            self.get_artifact_error_state.incr()

            if self.get_artifact_error_state.is_triggered():
                add_event(AGENT_NAME,
                          version=CURRENT_VERSION,
                          op=WALAEventOperation.GetArtifactExtended,
                          is_success=False,
                          message="Failed to get extension artifact for over "
                                  "{0): {1}".format(self.get_artifact_error_state.min_timedelta, msg))
                self.get_artifact_error_state.reset()
            else:
                logger.warn(msg)

            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.ExtensionProcessing,
                      is_success=False,
                      message=detailed_msg)
            return

        try:
            msg = u"Handle extensions updates for incarnation {0}".format(etag)
            logger.verbose(msg)
            # Log status report success on new config
            self.log_report = True
            self.handle_ext_handlers(etag)
            self.last_etag = etag

            self.report_ext_handlers_status()
            self.cleanup_outdated_handlers()
        except Exception as e:
            msg = u"Exception processing extension handlers: {0}".format(
                ustr(e))
            logger.warn(msg)
            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.ExtensionProcessing,
                      is_success=False,
                      message=msg)
            return

    def cleanup_outdated_handlers(self):
        handlers = []
        pkgs = []

        # Build a collection of uninstalled handlers and orphaned packages
        # Note:
        # -- An orphaned package is one without a corresponding handler
        #    directory
        for item in os.listdir(conf.get_lib_dir()):
            path = os.path.join(conf.get_lib_dir(), item)

            if version.is_agent_package(path) or version.is_agent_path(path):
                continue

            if os.path.isdir(path):
                if re.match(HANDLER_NAME_PATTERN, item) is None:
                    continue
                try:
                    eh = ExtHandler()

                    separator = item.rfind('-')

                    eh.name = item[0:separator]
                    eh.properties.version = str(FlexibleVersion(item[separator+1:]))

                    handler = ExtHandlerInstance(eh, self.protocol)
                except Exception:
                    continue
                if handler.get_handler_state() != ExtHandlerState.NotInstalled:
                    continue
                handlers.append(handler)

            elif os.path.isfile(path) and \
                    not os.path.isdir(path[0:-len(HANDLER_PKG_EXT)]):
                if not re.match(HANDLER_PKG_PATTERN, item):
                    continue
                pkgs.append(path)

        # Then, remove the orphaned packages
        for pkg in pkgs:
            try:
                os.remove(pkg)
                logger.verbose("Removed orphaned extension package {0}".format(pkg))
            except OSError as e:
                logger.warn("Failed to remove orphaned package {0}: {1}".format(pkg, e.strerror))

        # Finally, remove the directories and packages of the
        # uninstalled handlers
        for handler in handlers:
            handler.rm_ext_handler_dir()
            pkg = os.path.join(conf.get_lib_dir(), handler.get_full_name() + HANDLER_PKG_EXT)
            if os.path.isfile(pkg):
                try:
                    os.remove(pkg)
                    logger.verbose("Removed extension package {0}".format(pkg))
                except OSError as e:
                    logger.warn("Failed to remove extension package {0}: {1}".format(pkg, e.strerror))
   
    def handle_ext_handlers(self, etag=None):
        if not conf.get_extensions_enabled():
            logger.verbose("Extension handling is disabled")
            return

        if self.ext_handlers.extHandlers is None or \
                len(self.ext_handlers.extHandlers) == 0:
            logger.verbose("No extension handler config found")
            return

        if conf.get_enable_overprovisioning():
            artifacts_profile = self.protocol.get_artifacts_profile()
            if artifacts_profile and artifacts_profile.is_on_hold():
                logger.info("Extension handling is on hold")
                return

        self.ext_handlers.extHandlers.sort(key=operator.methodcaller('sort_key'))
        for ext_handler in self.ext_handlers.extHandlers:
            # TODO: handle install in sequence, enable in parallel
            self.handle_ext_handler(ext_handler, etag)
    
    def handle_ext_handler(self, ext_handler, etag):
        ext_handler_i = ExtHandlerInstance(ext_handler, self.protocol)

        try:
            state = ext_handler.properties.state
            if ext_handler_i.decide_version(target_state=state) is None:
                version = ext_handler_i.ext_handler.properties.version
                name = ext_handler_i.ext_handler.name
                err_msg = "Unable to find version {0} in manifest for extension {1}".format(version, name)
                ext_handler_i.set_operation(WALAEventOperation.Download)
                ext_handler_i.set_handler_status(message=ustr(err_msg), code=-1)
                ext_handler_i.report_event(message=ustr(err_msg), is_success=False)
                return

            self.get_artifact_error_state.reset()
            if not ext_handler_i.is_upgrade and self.last_etag == etag:
                if self.log_etag:
                    ext_handler_i.logger.verbose("Version {0} is current for etag {1}",
                                                 ext_handler_i.pkg.version,
                                                 etag)
                    self.log_etag = False
                return

            self.log_etag = True

            ext_handler_i.logger.info("Target handler state: {0}", state)
            if state == u"enabled":
                self.handle_enable(ext_handler_i)
            elif state == u"disabled":
                self.handle_disable(ext_handler_i)
            elif state == u"uninstall":
                self.handle_uninstall(ext_handler_i)
            else:
                message = u"Unknown ext handler state:{0}".format(state)
                raise ExtensionError(message)
        except ExtensionError as e:
            self.handle_handle_ext_handler_error(ext_handler_i, e, e.code)
        except Exception as e:
            self.handle_handle_ext_handler_error(ext_handler_i, e)

    def handle_handle_ext_handler_error(self, ext_handler_i, e, code=-1):
        msg = ustr(e)
        ext_handler_i.set_handler_status(message=msg, code=code)

        self.get_artifact_error_state.incr()
        if self.get_artifact_error_state.is_triggered():
            report_event(op=WALAEventOperation.GetArtifactExtended,
                         message="Failed to get artifact for over "
                                 "{0}: {1}".format(self.get_artifact_error_state.min_timedelta, msg),
                         is_success=False)
            self.get_artifact_error_state.reset()
        else:
            ext_handler_i.logger.warn(msg)
    
    def handle_enable(self, ext_handler_i):
        self.log_process = True
        old_ext_handler_i = ext_handler_i.get_installed_ext_handler()

        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("[Enable] current handler state is: {0}",
                                  handler_state.lower())
        if handler_state == ExtHandlerState.NotInstalled:
            ext_handler_i.set_handler_state(ExtHandlerState.NotInstalled)
            ext_handler_i.download()
            ext_handler_i.update_settings()
            if old_ext_handler_i is None:
                ext_handler_i.install()
            elif ext_handler_i.version_ne(old_ext_handler_i):
                old_ext_handler_i.disable()
                ext_handler_i.copy_status_files(old_ext_handler_i)
                if ext_handler_i.version_gt(old_ext_handler_i):
                    ext_handler_i.update()
                else:
                    old_ext_handler_i.update(version=ext_handler_i.ext_handler.properties.version)
                old_ext_handler_i.uninstall()
                old_ext_handler_i.rm_ext_handler_dir()
                ext_handler_i.update_with_install()
        else:
            ext_handler_i.update_settings()

        ext_handler_i.enable() 

    def handle_disable(self, ext_handler_i):
        self.log_process = True
        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("[Disable] current handler state is: {0}",
                                  handler_state.lower())
        if handler_state == ExtHandlerState.Enabled:
            ext_handler_i.disable()

    def handle_uninstall(self, ext_handler_i):
        self.log_process = True
        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("[Uninstall] current handler state is: {0}",
                                  handler_state.lower())
        if handler_state != ExtHandlerState.NotInstalled:
            if handler_state == ExtHandlerState.Enabled:
                ext_handler_i.disable()
            ext_handler_i.uninstall()
        ext_handler_i.rm_ext_handler_dir()

    def report_ext_handlers_status(self):
        """
        Go through handler_state dir, collect and report status
        """
        vm_status = VMStatus(status="Ready", message="Guest Agent is running")
        if self.ext_handlers is not None:
            for ext_handler in self.ext_handlers.extHandlers:
                try:
                    self.report_ext_handler_status(vm_status, ext_handler)
                except ExtensionError as e:
                    add_event(
                        AGENT_NAME,
                        version=CURRENT_VERSION,
                        op=WALAEventOperation.ExtensionProcessing,
                        is_success=False,
                        message=ustr(e))

        logger.verbose("Report vm agent status")
        try:
            self.protocol.report_vm_status(vm_status)
            if self.log_report:
                logger.verbose("Completed vm agent status report")
            self.report_status_error_state.reset()
        except ProtocolNotFoundError as e:
            self.report_status_error_state.incr()
            message = "Failed to report vm agent status: {0}".format(e)
            logger.verbose(message)
        except ProtocolError as e:
            self.report_status_error_state.incr()
            message = "Failed to report vm agent status: {0}".format(e)
            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.ExtensionProcessing,
                      is_success=False,
                      message=message)

        if self.report_status_error_state.is_triggered():
            message = "Failed to report vm agent status for more than {0}"\
                .format(self.report_status_error_state.min_timedelta)

            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.ReportStatusExtended,
                      is_success=False,
                      message=message)

            self.report_status_error_state.reset()

    def report_ext_handler_status(self, vm_status, ext_handler):
        ext_handler_i = ExtHandlerInstance(ext_handler, self.protocol)
        
        handler_status = ext_handler_i.get_handler_status() 
        if handler_status is None:
            return

        handler_state = ext_handler_i.get_handler_state()
        if handler_state != ExtHandlerState.NotInstalled:
            try:
                active_exts = ext_handler_i.report_ext_status()
                handler_status.extensions.extend(active_exts)
            except ExtensionError as e:
                ext_handler_i.set_handler_status(message=ustr(e), code=e.code)

            try:
                heartbeat = ext_handler_i.collect_heartbeat()
                if heartbeat is not None:
                    handler_status.status = heartbeat.get('status')
            except ExtensionError as e:
                ext_handler_i.set_handler_status(message=ustr(e), code=e.code)

        vm_status.vmAgent.extensionHandlers.append(handler_status)


class ExtHandlerInstance(object):
    def __init__(self, ext_handler, protocol):
        self.ext_handler = ext_handler
        self.protocol = protocol
        self.operation = None
        self.pkg = None
        self.pkg_file = None
        self.is_upgrade = False
        self.logger = None
        self.set_logger()
        
        try:
            fileutil.mkdir(self.get_log_dir(), mode=0o755)
        except IOError as e:
            self.logger.error(u"Failed to create extension log dir: {0}", e)

        log_file = os.path.join(self.get_log_dir(), "CommandExecution.log")
        self.logger.add_appender(logger.AppenderType.FILE,
                                 logger.LogLevel.INFO, log_file)

    def decide_version(self, target_state=None):
        self.logger.verbose("Decide which version to use")
        try:
            pkg_list = self.protocol.get_ext_handler_pkgs(self.ext_handler)
        except ProtocolError as e:
            raise ExtensionError("Failed to get ext handler pkgs", e)

        # Determine the desired and installed versions
        requested_version = FlexibleVersion(str(self.ext_handler.properties.version))
        installed_version_string = self.get_installed_version()
        installed_version = requested_version \
            if installed_version_string is None \
            else FlexibleVersion(installed_version_string)

        # Divide packages
        # - Find the installed package (its version must exactly match)
        # - Find the internal candidate (its version must exactly match)
        # - Separate the public packages
        selected_pkg = None
        installed_pkg = None
        pkg_list.versions.sort(key=lambda p: FlexibleVersion(p.version))
        for pkg in pkg_list.versions:
            pkg_version = FlexibleVersion(pkg.version)
            if pkg_version == installed_version:
                installed_pkg = pkg
            if requested_version.matches(pkg_version):
                selected_pkg = pkg

        # Finally, update the version only if not downgrading
        # Note:
        #  - A downgrade, which will be bound to the same major version,
        #    is allowed if the installed version is no longer available
        if target_state == u"uninstall" or target_state == u"disabled":
            if installed_pkg is None:
                msg = "Failed to find installed version of {0} " \
                    "to uninstall".format(self.ext_handler.name)
                self.logger.warn(msg)
            self.pkg = installed_pkg
            self.ext_handler.properties.version = str(installed_version) \
                                    if installed_version is not None else None
        else:
            self.pkg = selected_pkg
            if self.pkg is not None:
                self.ext_handler.properties.version = str(selected_pkg.version)

        # Note if the selected package is different than that installed
        if installed_pkg is None \
                or (self.pkg is not None and FlexibleVersion(self.pkg.version) != FlexibleVersion(installed_pkg.version)):
            self.is_upgrade = True

        if self.pkg is not None:
            self.logger.verbose("Use version: {0}", self.pkg.version)
        self.set_logger()
        return self.pkg

    def set_logger(self):
        prefix = "[{0}]".format(self.get_full_name())
        self.logger = logger.Logger(logger.DEFAULT_LOGGER, prefix)

    def version_gt(self, other):
        self_version = self.ext_handler.properties.version
        other_version = other.ext_handler.properties.version
        return FlexibleVersion(self_version) > FlexibleVersion(other_version)

    def version_ne(self, other):
        self_version = self.ext_handler.properties.version
        other_version = other.ext_handler.properties.version
        return FlexibleVersion(self_version) != FlexibleVersion(other_version)

    def get_installed_ext_handler(self):
        lastest_version = self.get_installed_version()
        if lastest_version is None:
            return None
        
        installed_handler = ExtHandler()
        set_properties("ExtHandler", installed_handler, get_properties(self.ext_handler))
        installed_handler.properties.version = lastest_version
        return ExtHandlerInstance(installed_handler, self.protocol)

    def get_installed_version(self):
        lastest_version = None

        for path in glob.iglob(os.path.join(conf.get_lib_dir(), self.ext_handler.name + "-*")):
            if not os.path.isdir(path):
                continue

            separator = path.rfind('-')
            version_from_path = FlexibleVersion(path[separator+1:])
            state_path = os.path.join(path, 'config', 'HandlerState')

            if not os.path.exists(state_path) or \
                fileutil.read_file(state_path) == \
                    ExtHandlerState.NotInstalled:
                logger.verbose("Ignoring version of uninstalled extension: "
                    "{0}".format(path))
                continue

            if lastest_version is None or lastest_version < version_from_path:
                lastest_version = version_from_path

        return str(lastest_version) if lastest_version is not None else None
    
    def copy_status_files(self, old_ext_handler_i):
        self.logger.info("Copy status files from old plugin to new")
        old_ext_dir = old_ext_handler_i.get_base_dir()
        new_ext_dir = self.get_base_dir()

        old_ext_mrseq_file = os.path.join(old_ext_dir, "mrseq")
        if os.path.isfile(old_ext_mrseq_file):
            shutil.copy2(old_ext_mrseq_file, new_ext_dir)

        old_ext_status_dir = old_ext_handler_i.get_status_dir()
        new_ext_status_dir = self.get_status_dir()

        if os.path.isdir(old_ext_status_dir):
            for status_file in os.listdir(old_ext_status_dir):
                status_file = os.path.join(old_ext_status_dir, status_file)
                if os.path.isfile(status_file):
                    shutil.copy2(status_file, new_ext_status_dir)

    def set_operation(self, op):
        self.operation = op

    def report_event(self, message="", is_success=True, duration=0, log_event=True):
        ext_handler_version = self.ext_handler.properties.version
        add_event(name=self.ext_handler.name, version=ext_handler_version, message=message,
                  op=self.operation, is_success=is_success, duration=duration, log_event=log_event)

    def download(self):
        begin_utc = datetime.datetime.utcnow()
        self.logger.verbose("Download extension package")
        self.set_operation(WALAEventOperation.Download)

        if self.pkg is None:
            raise ExtensionError("No package uri found")
        
        uris_shuffled = self.pkg.uris
        random.shuffle(uris_shuffled)
        file_downloaded = False

        for uri in uris_shuffled:
            try:
                destination = os.path.join(conf.get_lib_dir(), os.path.basename(uri.uri) + ".zip")
                file_downloaded = self.protocol.download_ext_handler_pkg(uri.uri, destination)

                if file_downloaded and os.path.exists(destination):
                    self.pkg_file = destination
                    break

            except Exception as e:
                logger.warn("Error while downloading extension: {0}", ustr(e))
        
        if not file_downloaded:
            raise ExtensionError("Failed to download extension", code=1001)

        self.logger.verbose("Unzip extension package")
        try:
            zipfile.ZipFile(self.pkg_file).extractall(self.get_base_dir())
            os.remove(self.pkg_file)
        except IOError as e:
            fileutil.clean_ioerror(e, paths=[self.get_base_dir(), self.pkg_file])
            raise ExtensionError(u"Failed to unzip extension package", e, code=1001)

        # Add user execute permission to all files under the base dir
        for file in fileutil.get_all_files(self.get_base_dir()):
            fileutil.chmod(file, os.stat(file).st_mode | stat.S_IXUSR)

        duration = elapsed_milliseconds(begin_utc)
        self.report_event(message="Download succeeded", duration=duration)

        self.logger.info("Initialize extension directory")
        # Save HandlerManifest.json
        man_file = fileutil.search_file(self.get_base_dir(), 'HandlerManifest.json')

        if man_file is None:
            raise ExtensionError("HandlerManifest.json not found")
        
        try:
            man = fileutil.read_file(man_file, remove_bom=True)
            fileutil.write_file(self.get_manifest_file(), man)
        except IOError as e:
            fileutil.clean_ioerror(e, paths=[self.get_base_dir(), self.pkg_file])
            raise ExtensionError(u"Failed to save HandlerManifest.json", e)

        # Create status and config dir
        try:
            status_dir = self.get_status_dir()
            fileutil.mkdir(status_dir, mode=0o700)

            seq_no, status_path = self.get_status_file_path()
            if status_path is not None:
                now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                status = {
                    "version": 1.0,
                    "timestampUTC": now,
                    "status": {
                        "name": self.ext_handler.name,
                        "operation": "Enabling Handler",
                        "status": "transitioning",
                        "code": 0
                    }
                }
                fileutil.write_file(status_path, json.dumps(status))

            conf_dir = self.get_conf_dir()
            fileutil.mkdir(conf_dir, mode=0o700)

        except IOError as e:
            fileutil.clean_ioerror(e, paths=[self.get_base_dir(), self.pkg_file])
            raise ExtensionError(u"Failed to create status or config dir", e)

        # Save HandlerEnvironment.json
        self.create_handler_env()

    def enable(self):
        self.set_operation(WALAEventOperation.Enable)
        man = self.load_manifest()
        enable_cmd = man.get_enable_command()
        self.logger.info("Enable extension [{0}]".format(enable_cmd))
        self.launch_command(enable_cmd, timeout=300, extension_error_code=1009)
        self.set_handler_state(ExtHandlerState.Enabled)
        self.set_handler_status(status="Ready", message="Plugin enabled")

    def disable(self):
        self.set_operation(WALAEventOperation.Disable)
        man = self.load_manifest()
        disable_cmd = man.get_disable_command()
        self.logger.info("Disable extension [{0}]".format(disable_cmd))
        self.launch_command(disable_cmd, timeout=900,
                            extension_error_code=1010)
        self.set_handler_state(ExtHandlerState.Installed)
        self.set_handler_status(status="NotReady", message="Plugin disabled")

    def install(self):
        man = self.load_manifest()
        install_cmd = man.get_install_command()
        self.logger.info("Install extension [{0}]".format(install_cmd))
        self.set_operation(WALAEventOperation.Install)
        self.launch_command(install_cmd, timeout=900, extension_error_code=1007)
        self.set_handler_state(ExtHandlerState.Installed)

    def uninstall(self):
        try:
            self.set_operation(WALAEventOperation.UnInstall)
            man = self.load_manifest()
            uninstall_cmd = man.get_uninstall_command()
            self.logger.info("Uninstall extension [{0}]".format(uninstall_cmd))
            self.launch_command(uninstall_cmd)
        except ExtensionError as e:
            self.report_event(message=ustr(e), is_success=False)
    
    def rm_ext_handler_dir(self):
        try:
            base_dir = self.get_base_dir()
            if os.path.isdir(base_dir):
                self.logger.info("Remove extension handler directory: {0}",
                                 base_dir)
                shutil.rmtree(base_dir)
        except IOError as e:
            message = "Failed to remove extension handler directory: {0}".format(e)
            self.report_event(message=message, is_success=False)
            self.logger.warn(message)

    def update(self, version=None):
        if version is None:
            version = self.ext_handler.properties.version

        try:
            self.set_operation(WALAEventOperation.Update)
            man = self.load_manifest()
            update_cmd = man.get_update_command()
            self.logger.info("Update extension [{0}]".format(update_cmd))
            self.launch_command(update_cmd,
                                timeout=900,
                                extension_error_code=1008,
                                env={'VERSION': version})
        except ExtensionError:
            # prevent the handler update from being retried
            self.set_handler_state(ExtHandlerState.Failed)
            raise
    
    def update_with_install(self):
        man = self.load_manifest()
        if man.is_update_with_install():
            self.install()
        else:
            self.logger.info("UpdateWithInstall not set. "
                             "Skip install during upgrade.")
        self.set_handler_state(ExtHandlerState.Installed)

    def get_largest_seq_no(self):
        seq_no = -1
        conf_dir = self.get_conf_dir()
        for item in os.listdir(conf_dir):
            item_path = os.path.join(conf_dir, item)
            if os.path.isfile(item_path):
                try:
                    separator = item.rfind(".")
                    if separator > 0 and item[separator + 1:] == 'settings':
                        curr_seq_no = int(item.split('.')[0])
                        if curr_seq_no > seq_no:
                            seq_no = curr_seq_no
                except (ValueError, IndexError, TypeError):
                    self.logger.verbose("Failed to parse file name: {0}", item)
                    continue
        return seq_no

    def get_status_file_path(self, extension=None):
        path = None
        seq_no = self.get_largest_seq_no()

        # Issue 1116: use the sequence number from goal state where possible
        if extension is not None and extension.sequenceNumber is not None:
            try:
                gs_seq_no = int(extension.sequenceNumber)

                if gs_seq_no != seq_no:
                    add_event(AGENT_NAME,
                              version=CURRENT_VERSION,
                              op=WALAEventOperation.SequenceNumberMismatch,
                              is_success=False,
                              message="Goal state: {0}, disk: {1}".format(gs_seq_no, seq_no),
                              log_event=False)

                seq_no = gs_seq_no
            except ValueError:
                logger.error('Sequence number [{0}] does not appear to be valid'.format(extension.sequenceNumber))

        if seq_no > -1:
            path = os.path.join(
                        self.get_status_dir(),
                        "{0}.status".format(seq_no))

        return seq_no, path

    def collect_ext_status(self, ext):
        self.logger.verbose("Collect extension status")

        seq_no, ext_status_file = self.get_status_file_path(ext)
        if seq_no == -1:
            return None

        ext_status = ExtensionStatus(seq_no=seq_no)
        try:
            data_str = fileutil.read_file(ext_status_file)
            data = json.loads(data_str)
            parse_ext_status(ext_status, data)
        except IOError as e:
            ext_status.message = u"Failed to get status file {0}".format(e)
            ext_status.code = -1
            ext_status.status = "error"
        except ExtensionError as e:
            ext_status.message = u"Malformed status file {0}".format(e)
            ext_status.code = e.code
            ext_status.status = "error"
        except ValueError as e:
            ext_status.message = u"Malformed status file {0}".format(e)
            ext_status.code = -1
            ext_status.status = "error"

        return ext_status
    
    def report_ext_status(self):
        active_exts = []
        # TODO Refactor or remove this common code pattern (for each extension subordinate to an ext_handler, do X).
        for ext in self.ext_handler.properties.extensions:
            ext_status = self.collect_ext_status(ext)
            if ext_status is None:
                continue
            try:
                self.protocol.report_ext_status(self.ext_handler.name, ext.name, 
                                                ext_status)
                active_exts.append(ext.name)
            except ProtocolError as e:
                self.logger.error(u"Failed to report extension status: {0}", e)
        return active_exts
   
    def collect_heartbeat(self):
        man = self.load_manifest()
        if not man.is_report_heartbeat():
            return
        heartbeat_file = os.path.join(conf.get_lib_dir(),
                                      self.get_heartbeat_file())

        if not os.path.isfile(heartbeat_file):
            raise ExtensionError("Failed to get heart beat file")
        if not self.is_responsive(heartbeat_file):
            return {
                    "status": "Unresponsive",
                    "code": -1,
                    "message": "Extension heartbeat is not responsive"
            }
        try:
            heartbeat_json = fileutil.read_file(heartbeat_file)
            heartbeat = json.loads(heartbeat_json)[0]['heartbeat']
        except IOError as e:
            raise ExtensionError("Failed to get heartbeat file:{0}".format(e))
        except (ValueError, KeyError) as e:
            raise ExtensionError("Malformed heartbeat file: {0}".format(e))
        return heartbeat

    @staticmethod
    def is_responsive(heartbeat_file):
        """
        Was heartbeat_file updated within the last ten (10) minutes?

        :param heartbeat_file: str
        :return: bool
        """
        last_update = int(time.time() - os.stat(heartbeat_file).st_mtime)
        return last_update <= 600

    def launch_command(self, cmd, timeout=300, extension_error_code=1000, env=None):
        begin_utc = datetime.datetime.utcnow()
        self.logger.verbose("Launch command: [{0}]", cmd)
        base_dir = self.get_base_dir()

        if env is None:
            env = {}
        env.update(os.environ)

        try:
            # This should be .run(), but due to the wide variety
            # of Python versions we must support we must use .communicate().
            # Some extensions erroneously begin cmd with a slash; don't interpret those
            # as root-relative. (Issue #1170)
            full_path = os.path.join(base_dir, cmd.lstrip(os.path.sep))

            def pre_exec_function():
                """
                Change process state before the actual target process is started. Effectively, this runs between
                the fork() and the exec() of sub-process creation.
                :return:
                """
                os.setsid()
                CGroups.add_to_extension_cgroup(self.ext_handler.name)

            process = subprocess.Popen(full_path,
                                       shell=True,
                                       cwd=base_dir,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       env=env,
                                       preexec_fn=pre_exec_function)
        except OSError as e:
            raise ExtensionError("Failed to launch '{0}': {1}".format(full_path, e.strerror),
                                 code=extension_error_code)

        cg = CGroups.for_extension(self.ext_handler.name)
        CGroupsTelemetry.track_extension(self.ext_handler.name, cg)
        msg = capture_from_process(process, cmd, timeout, extension_error_code)

        ret = process.poll()
        if ret is None:
            raise ExtensionError("Process {0} was not terminated: {1}\n{2}".format(process.pid, cmd, msg),
                                 code=extension_error_code)
        if ret != 0:
            raise ExtensionError("Non-zero exit code: {0}, {1}\n{2}".format(ret, cmd, msg),
                                 code=extension_error_code)

        duration = elapsed_milliseconds(begin_utc)
        log_msg = "{0}\n{1}".format(cmd, "\n".join([line for line in msg.split('\n') if line != ""]))
        self.logger.verbose(log_msg)
        self.report_event(message=log_msg, duration=duration, log_event=False)

    def load_manifest(self):
        man_file = self.get_manifest_file()
        try:
            data = json.loads(fileutil.read_file(man_file))
        except (IOError, OSError) as e:
            raise ExtensionError('Failed to load manifest file ({0}): {1}'.format(man_file, e.strerror), code=1002)
        except ValueError:
            raise ExtensionError('Malformed manifest file ({0}).'.format(man_file), code=1003)

        return HandlerManifest(data[0])

    def update_settings_file(self, settings_file, settings):
        settings_file = os.path.join(self.get_conf_dir(), settings_file)
        try:
            fileutil.write_file(settings_file, settings)
        except IOError as e:
            fileutil.clean_ioerror(e,
                paths=[settings_file])
            raise ExtensionError(u"Failed to update settings file", e)

    def update_settings(self):
        if self.ext_handler.properties.extensions is None or \
                len(self.ext_handler.properties.extensions) == 0:
            # This is the behavior of waagent 2.0.x
            # The new agent has to be consistent with the old one.
            self.logger.info("Extension has no settings, write empty 0.settings")
            self.update_settings_file("0.settings", "")
            return
        
        for ext in self.ext_handler.properties.extensions:
            settings = {
                'publicSettings': ext.publicSettings,
                'protectedSettings': ext.protectedSettings,
                'protectedSettingsCertThumbprint': ext.certificateThumbprint
            }
            ext_settings = {
                "runtimeSettings": [{
                    "handlerSettings": settings
                }]
            }
            settings_file = "{0}.settings".format(ext.sequenceNumber)
            self.logger.info("Update settings file: {0}", settings_file)
            self.update_settings_file(settings_file, json.dumps(ext_settings))

    def create_handler_env(self):
        env = [{
            "name": self.ext_handler.name,
            "version": HANDLER_ENVIRONMENT_VERSION,
            "handlerEnvironment": {
                "logFolder": self.get_log_dir(),
                "configFolder": self.get_conf_dir(),
                "statusFolder": self.get_status_dir(),
                "heartbeatFile": self.get_heartbeat_file()
            }
        }]
        try:
            fileutil.write_file(self.get_env_file(), json.dumps(env))
        except IOError as e:
            fileutil.clean_ioerror(e,
                paths=[self.get_base_dir(), self.pkg_file])
            raise ExtensionError(u"Failed to save handler environment", e)

    def set_handler_state(self, handler_state):
        state_dir = self.get_conf_dir()
        state_file = os.path.join(state_dir, "HandlerState")
        try:
            if not os.path.exists(state_dir):
                fileutil.mkdir(state_dir, mode=0o700)
            fileutil.write_file(state_file, handler_state)
        except IOError as e:
            fileutil.clean_ioerror(e, paths=[state_file])
            self.logger.error("Failed to set state: {0}", e)
    
    def get_handler_state(self):
        state_dir = self.get_conf_dir()
        state_file = os.path.join(state_dir, "HandlerState")
        if not os.path.isfile(state_file):
            return ExtHandlerState.NotInstalled

        try:
            return fileutil.read_file(state_file)
        except IOError as e:
            self.logger.error("Failed to get state: {0}", e)
            return ExtHandlerState.NotInstalled
    
    def set_handler_status(self, status="NotReady", message="", code=0):
        state_dir = self.get_conf_dir()

        handler_status = ExtHandlerStatus()
        handler_status.name = self.ext_handler.name
        handler_status.version = str(self.ext_handler.properties.version)
        handler_status.message = message
        handler_status.code = code
        handler_status.status = status
        status_file = os.path.join(state_dir, "HandlerStatus")

        try:
            handler_status_json = json.dumps(get_properties(handler_status))
            if handler_status_json is not None:
                fileutil.write_file(status_file, handler_status_json)
            else:
                self.logger.error("Failed to create JSON document of handler status for {0} version {1}".format(
                    self.ext_handler.name,
                    self.ext_handler.properties.version))
        except (IOError, ValueError, ProtocolError) as e:
            fileutil.clean_ioerror(e, paths=[status_file])
            self.logger.error("Failed to save handler status: {0}, {1}", ustr(e), traceback.format_exc())
        
    def get_handler_status(self):
        state_dir = self.get_conf_dir()
        status_file = os.path.join(state_dir, "HandlerStatus")
        if not os.path.isfile(status_file):
            return None
        
        try:
            data = json.loads(fileutil.read_file(status_file))
            handler_status = ExtHandlerStatus() 
            set_properties("ExtHandlerStatus", handler_status, data)
            return handler_status
        except (IOError, ValueError) as e:
            self.logger.error("Failed to get handler status: {0}", e)

    def get_full_name(self):
        return "{0}-{1}".format(self.ext_handler.name, 
                                self.ext_handler.properties.version)
   
    def get_base_dir(self):
        return os.path.join(conf.get_lib_dir(), self.get_full_name())

    def get_status_dir(self):
        return os.path.join(self.get_base_dir(), "status")

    def get_conf_dir(self):
        return os.path.join(self.get_base_dir(), 'config')

    def get_heartbeat_file(self):
        return os.path.join(self.get_base_dir(), 'heartbeat.log')

    def get_manifest_file(self):
        return os.path.join(self.get_base_dir(), 'HandlerManifest.json')

    def get_env_file(self):
        return os.path.join(self.get_base_dir(), 'HandlerEnvironment.json')

    def get_log_dir(self):
        return os.path.join(conf.get_ext_log_dir(), self.ext_handler.name)


class HandlerEnvironment(object):
    def __init__(self, data):
        self.data = data

    def get_version(self):
        return self.data["version"]

    def get_log_dir(self):
        return self.data["handlerEnvironment"]["logFolder"]

    def get_conf_dir(self):
        return self.data["handlerEnvironment"]["configFolder"]

    def get_status_dir(self):
        return self.data["handlerEnvironment"]["statusFolder"]

    def get_heartbeat_file(self):
        return self.data["handlerEnvironment"]["heartbeatFile"]


class HandlerManifest(object):
    def __init__(self, data):
        if data is None or data['handlerManifest'] is None:
            raise ExtensionError('Malformed manifest file.')
        self.data = data

    def get_name(self):
        return self.data["name"]

    def get_version(self):
        return self.data["version"]

    def get_install_command(self):
        return self.data['handlerManifest']["installCommand"]

    def get_uninstall_command(self):
        return self.data['handlerManifest']["uninstallCommand"]

    def get_update_command(self):
        return self.data['handlerManifest']["updateCommand"]

    def get_enable_command(self):
        return self.data['handlerManifest']["enableCommand"]

    def get_disable_command(self):
        return self.data['handlerManifest']["disableCommand"]

    def is_report_heartbeat(self):
        return self.data['handlerManifest'].get('reportHeartbeat', False)

    def is_update_with_install(self):
        update_mode = self.data['handlerManifest'].get('updateMode')
        if update_mode is None:
            return True
        return update_mode.lower() == "updatewithinstall"
