# Microsoft Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#

import glob
import json
import os
import os.path
import re
import shutil
import stat
import subprocess
import time
import zipfile

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.restutil as restutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.version as version

from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ExtensionError, ProtocolError, HttpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.version import AGENT_VERSION
from azurelinuxagent.common.protocol.restapi import ExtHandlerStatus, \
                                                    ExtensionStatus, \
                                                    ExtensionSubStatus, \
                                                    Extension, \
                                                    VMStatus, ExtHandler, \
                                                    get_properties, \
                                                    set_properties
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.textutil import Version
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_AGENT, CURRENT_VERSION

#HandlerEnvironment.json schema version
HANDLER_ENVIRONMENT_VERSION = 1.0

VALID_EXTENSION_STATUS = ['transitioning', 'error', 'success', 'warning']

VALID_HANDLER_STATUS = ['Ready', 'NotReady', "Installing", "Unresponsive"]

HANDLER_PATTERN = "^([^-]+)-(\d+(?:\.\d+)*)"
HANDLER_NAME_PATTERN = re.compile(HANDLER_PATTERN+"$", re.IGNORECASE)
HANDLER_PKG_EXT = ".zip"
HANDLER_PKG_PATTERN = re.compile(HANDLER_PATTERN+"\\"+HANDLER_PKG_EXT+"$",
                                re.IGNORECASE)


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
    #Check extension sub status format
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
    #Currently, only the first status will be reported
    data = data[0]
    #Check extension status format
    validate_has_key(data, 'status', 'status')
    status_data = data['status']
    validate_has_key(status_data, 'status', 'status/status')
    
    validate_in_range(status_data['status'], VALID_EXTENSION_STATUS,
                      'status/status')

    applied_time = status_data.get('configurationAppliedTime')
    ext_status.configurationAppliedTime = applied_time
    ext_status.operation = status_data.get('operation')
    ext_status.status = status_data.get('status')
    ext_status.code = status_data.get('code', 0)
    formatted_message = status_data.get('formattedMessage')
    ext_status.message = parse_formatted_message(formatted_message)
    substatus_list = status_data.get('substatus')
    if substatus_list is None:
        return
    for substatus in substatus_list:
        if substatus is not None:
            ext_status.substatusList.append(parse_ext_substatus(substatus))

# This code migrates, if it exists, handler state and status from an
# agent-owned directory into the handler-owned config directory
#
# Notes:
#  - The v2.0.x branch wrote all handler-related state into the handler-owned
#    config directory (e.g., /var/lib/waagent/Microsoft.Azure.Extensions.LinuxAsm-2.0.1/config).
#  - The v2.1.x branch original moved that state into an agent-owned handler
#    state directory (e.g., /var/lib/waagent/handler_state).
#  - This move can cause v2.1.x agents to multiply invoke a handler's install
#    command. It also makes clean-up more difficult since the agent must
#    remove the state as well as the handler directory.
def migrate_handler_state():
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

    def run(self):
        self.ext_handlers, etag = None, None
        try:
            self.protocol = self.protocol_util.get_protocol()
            self.ext_handlers, etag = self.protocol.get_ext_handlers()
        except ProtocolError as e:
            msg = u"Exception retrieving extension handlers: {0}".format(
                ustr(e))
            logger.warn(msg)
            add_event(AGENT_NAME, version=CURRENT_VERSION, is_success=False, message=msg)
            return

        msg = u"Handle extensions updates for incarnation {0}".format(etag)
        logger.verbose(msg)
        # Log status report success on new config
        self.log_report = True
        self.handle_ext_handlers(etag)
        self.last_etag = etag

        self.report_ext_handlers_status()
        self.cleanup_outdated_handlers()

    def run_status(self):
        self.report_ext_handlers_status()
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
                except Exception as e:
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
                logger.verbose("Removed orphaned extension package "
                            "{0}".format(pkg))
            except Exception as e:
                logger.warn("Failed to remove orphaned package: {0}".format(
                                pkg))

        # Finally, remove the directories and packages of the
        # uninstalled handlers
        for handler in handlers:
            handler.rm_ext_handler_dir()
            pkg = os.path.join(conf.get_lib_dir(),
                    handler.get_full_name() + HANDLER_PKG_EXT)
            if os.path.isfile(pkg):
                try:
                    os.remove(pkg)
                    logger.verbose("Removed extension package "
                                "{0}".format(pkg))
                except Exception as e:
                    logger.warn("Failed to remove extension package: "
                                "{0}".format(pkg))
   
    def handle_ext_handlers(self, etag=None):
        if self.ext_handlers.extHandlers is None or \
                len(self.ext_handlers.extHandlers) == 0:
            logger.verbose("No extension handler config found")
            return

        if conf.get_enable_overprovisioning():
            artifacts_profile = self.protocol.get_artifacts_profile()
            if artifacts_profile and artifacts_profile.is_on_hold():
                logger.info("Extension handling is on hold")
                return

        for ext_handler in self.ext_handlers.extHandlers:
            # TODO: handle install in sequence, enable in parallel
            self.handle_ext_handler(ext_handler, etag)
    
    def handle_ext_handler(self, ext_handler, etag):
        ext_handler_i = ExtHandlerInstance(ext_handler, self.protocol)

        try:
            ext_handler_i.decide_version()
            if not ext_handler_i.is_upgrade and self.last_etag == etag:
                if self.log_etag:
                    ext_handler_i.logger.verbose("Version {0} is current for etag {1}",
                                                 ext_handler_i.pkg.version,
                                                 etag)
                    self.log_etag = False
                return

            self.log_etag = True

            state = ext_handler.properties.state
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
            ext_handler_i.set_handler_status(message=ustr(e), code=-1)
            ext_handler_i.report_event(message=ustr(e), is_success=False)
    
    def handle_enable(self, ext_handler_i):
        old_ext_handler_i = ext_handler_i.get_installed_ext_handler()
        if old_ext_handler_i is not None and \
           old_ext_handler_i.version_gt(ext_handler_i):
            raise ExtensionError(u"Downgrade not allowed")
        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("[Enable] current handler state is: {0}",
                                  handler_state.lower())
        if handler_state == ExtHandlerState.NotInstalled:
            ext_handler_i.set_handler_state(ExtHandlerState.NotInstalled)
            ext_handler_i.download()
            ext_handler_i.update_settings()
            if old_ext_handler_i is None:
                ext_handler_i.install()
            elif ext_handler_i.version_gt(old_ext_handler_i):
                old_ext_handler_i.disable()
                ext_handler_i.copy_status_files(old_ext_handler_i)
                ext_handler_i.update()
                old_ext_handler_i.uninstall()
                old_ext_handler_i.rm_ext_handler_dir()
                ext_handler_i.update_with_install()
        else:
            ext_handler_i.update_settings()

        ext_handler_i.enable() 

    def handle_disable(self, ext_handler_i):
        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("[Disable] current handler state is: {0}",
                                  handler_state.lower())
        if handler_state == ExtHandlerState.Enabled:
            ext_handler_i.disable()

    def handle_uninstall(self, ext_handler_i):
        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("[Uninstall] current handler state is: {0}",
                                  handler_state.lower())
        if handler_state != ExtHandlerState.NotInstalled:
            if handler_state == ExtHandlerState.Enabled:
                ext_handler_i.disable()
            ext_handler_i.uninstall()
        ext_handler_i.rm_ext_handler_dir()
    
    def report_ext_handlers_status(self):
        """Go through handler_state dir, collect and report status"""
        vm_status = VMStatus(status="Ready", message="Guest Agent is running")
        if self.ext_handlers is not None:
            for ext_handler in self.ext_handlers.extHandlers:
                try:
                    self.report_ext_handler_status(vm_status, ext_handler)
                except ExtensionError as e:
                    add_event(
                        AGENT_NAME,
                        version=CURRENT_VERSION,
                        is_success=False,
                        message=ustr(e))

        logger.verbose("Report vm agent status")
        try:
            self.protocol.report_vm_status(vm_status)
            if self.log_report:
                logger.verbose("Completed vm agent status report")
        except ProtocolError as e:
            message = "Failed to report vm agent status: {0}".format(e)
            add_event(AGENT_NAME, version=CURRENT_VERSION, is_success=False, message=message)

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
                ext_handler_i.set_handler_status(message=ustr(e), code=-1)

            try:
                heartbeat = ext_handler_i.collect_heartbeat()
                if heartbeat is not None:
                    handler_status.status = heartbeat.get('status')
            except ExtensionError as e:
                ext_handler_i.set_handler_status(message=ustr(e), code=-1)

        vm_status.vmAgent.extensionHandlers.append(handler_status)


class ExtHandlerInstance(object):
    def __init__(self, ext_handler, protocol):
        self.ext_handler = ext_handler
        self.protocol = protocol
        self.operation = None
        self.pkg = None
        self.is_upgrade = False

        prefix = "[{0}]".format(self.get_full_name())
        self.logger = logger.Logger(logger.DEFAULT_LOGGER, prefix)
        
        try:
            fileutil.mkdir(self.get_log_dir(), mode=0o755)
        except IOError as e:
            self.logger.error(u"Failed to create extension log dir: {0}", e)

        log_file = os.path.join(self.get_log_dir(), "CommandExecution.log")
        self.logger.add_appender(logger.AppenderType.FILE,
                                 logger.LogLevel.INFO, log_file)

    def decide_version(self):
        self.logger.verbose("Decide which version to use")
        try:
            pkg_list = self.protocol.get_ext_handler_pkgs(self.ext_handler)
        except ProtocolError as e:
            raise ExtensionError("Failed to get ext handler pkgs", e)

        # Determine the desired and installed versions
        requested_version = FlexibleVersion(self.ext_handler.properties.version)
        installed_version_string = self.get_installed_version()
        installed_version = requested_version \
            if installed_version_string is None \
            else FlexibleVersion(installed_version_string)

        # Divide packages
        # - Find the installed package (its version must exactly match)
        # - Find the internal candidate (its version must exactly match)
        # - Separate the public packages
        internal_pkg = None
        installed_pkg = None
        public_pkgs = []
        for pkg in pkg_list.versions:
            pkg_version = FlexibleVersion(pkg.version)
            if pkg_version == installed_version:
                installed_pkg = pkg
            if pkg.isinternal and pkg_version == requested_version:
                internal_pkg = pkg
            if not pkg.isinternal:
                public_pkgs.append(pkg)

        internal_version = FlexibleVersion(internal_pkg.version) \
                            if internal_pkg is not None \
                            else FlexibleVersion()
        public_pkgs.sort(key=lambda pkg: FlexibleVersion(pkg.version), reverse=True)

        # Determine the preferred version and type of upgrade occurring
        preferred_version = max(requested_version, installed_version)
        is_major_upgrade = preferred_version.major > installed_version.major
        allow_minor_upgrade = self.ext_handler.properties.upgradePolicy == 'auto'

        # Find the first public candidate which
        # - Matches the preferred major version
        # - Does not upgrade to a new, disallowed major version
        # - And only increments the minor version if allowed
        # Notes:
        # - The patch / hotfix version is not considered
        public_pkg = None
        for pkg in public_pkgs:
            pkg_version = FlexibleVersion(pkg.version)
            if pkg_version.major == preferred_version.major \
                and (not pkg.disallow_major_upgrade or not is_major_upgrade) \
                and (allow_minor_upgrade or pkg_version.minor == preferred_version.minor):
                public_pkg = pkg
                break

        # If there are no candidates, locate the highest public version whose
        # major matches that installed
        if internal_pkg is None and public_pkg is None:
            for pkg in public_pkgs:
                pkg_version = FlexibleVersion(pkg.version)
                if pkg_version.major == installed_version.major:
                    public_pkg = pkg
                    break

        public_version = FlexibleVersion(public_pkg.version) \
                            if public_pkg is not None \
                            else FlexibleVersion()

        # Select the candidate
        # - Use the public candidate if there is no internal candidate or
        #   the public is more recent (e.g., a hotfix patch)
        # - Otherwise use the internal candidate
        if internal_pkg is None or (public_pkg is not None and public_version > internal_version):
            selected_pkg = public_pkg
        else:
            selected_pkg = internal_pkg

        selected_version = FlexibleVersion(selected_pkg.version) \
                            if selected_pkg is not None \
                            else FlexibleVersion()

        # Finally, update the version only if not downgrading
        # Note:
        #  - A downgrade, which will be bound to the same major version,
        #    is allowed if the installed version is no longer available
        if selected_pkg is None \
            or (installed_pkg is not None and selected_version < installed_version):
            self.pkg = installed_pkg
            self.ext_handler.properties.version = installed_version
        else:
            self.pkg = selected_pkg
            self.ext_handler.properties.version = selected_pkg.version

        # Note if the selected package is greater than that installed
        if installed_pkg is None \
            or FlexibleVersion(self.pkg.version) > FlexibleVersion(installed_pkg.version):
            self.is_upgrade = True

        if self.pkg is None:
            raise ExtensionError("Failed to find any valid extension package")

        self.logger.verbose("Use version: {0}", self.pkg.version)
        return

    def version_gt(self, other):
        self_version = self.ext_handler.properties.version
        other_version = other.ext_handler.properties.version
        return Version(self_version) > Version(other_version)

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
            version = FlexibleVersion(path[separator+1:])
            state_path = os.path.join(path, 'config', 'HandlerState')

            if not os.path.exists(state_path) or \
                fileutil.read_file(state_path) == \
                    ExtHandlerState.NotInstalled:
                logger.verbose("Ignoring version of uninstalled extension: "
                    "{0}".format(path))
                continue

            if lastest_version is None or lastest_version < version:
                lastest_version = version

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

    def report_event(self, message="", is_success=True):
        version = self.ext_handler.properties.version
        add_event(name=self.ext_handler.name, version=version, message=message, 
                  op=self.operation, is_success=is_success)

    def download(self):
        self.logger.verbose("Download extension package")
        self.set_operation(WALAEventOperation.Download)
        if self.pkg is None:
            raise ExtensionError("No package uri found")
        
        package = None
        for uri in self.pkg.uris:
            try:
                package = self.protocol.download_ext_handler_pkg(uri.uri)
                if package is not None:
                    break
            except Exception as e:
                logger.warn("Error while downloading extension: {0}", e)
        
        if package is None:
            raise ExtensionError("Failed to download extension")

        self.logger.verbose("Unpack extension package")
        pkg_file = os.path.join(conf.get_lib_dir(),
                                os.path.basename(uri.uri) + ".zip")
        try:
            fileutil.write_file(pkg_file, bytearray(package), asbin=True)
            zipfile.ZipFile(pkg_file).extractall(self.get_base_dir())
        except IOError as e:
            raise ExtensionError(u"Failed to write and unzip plugin", e)

        #Add user execute permission to all files under the base dir
        for file in fileutil.get_all_files(self.get_base_dir()):
            fileutil.chmod(file, os.stat(file).st_mode | stat.S_IXUSR)

        self.report_event(message="Download succeeded")

        self.logger.info("Initialize extension directory")
        #Save HandlerManifest.json
        man_file = fileutil.search_file(self.get_base_dir(),
                                        'HandlerManifest.json')

        if man_file is None:
            raise ExtensionError("HandlerManifest.json not found")
        
        try:
            man = fileutil.read_file(man_file, remove_bom=True)
            fileutil.write_file(self.get_manifest_file(), man)
        except IOError as e:
            raise ExtensionError(u"Failed to save HandlerManifest.json", e)

        #Create status and config dir
        try:
            status_dir = self.get_status_dir()
            fileutil.mkdir(status_dir, mode=0o700)
            conf_dir = self.get_conf_dir()
            fileutil.mkdir(conf_dir, mode=0o700)
        except IOError as e:
            raise ExtensionError(u"Failed to create status or config dir", e)

        #Save HandlerEnvironment.json
        self.create_handler_env()

    def enable(self):
        self.set_operation(WALAEventOperation.Enable)
        man = self.load_manifest()
        enable_cmd = man.get_enable_command()
        self.logger.info("Enable extension [{0}]".format(enable_cmd))
        self.launch_command(enable_cmd, timeout=300)
        self.set_handler_state(ExtHandlerState.Enabled)
        self.set_handler_status(status="Ready", message="Plugin enabled")

    def disable(self):
        self.set_operation(WALAEventOperation.Disable)
        man = self.load_manifest()
        disable_cmd = man.get_disable_command()
        self.logger.info("Disable extension [{0}]".format(disable_cmd))
        self.launch_command(disable_cmd, timeout=900)
        self.set_handler_state(ExtHandlerState.Installed)
        self.set_handler_status(status="NotReady", message="Plugin disabled")

    def install(self):
        man = self.load_manifest()
        install_cmd = man.get_install_command()
        self.logger.info("Install extension [{0}]".format(install_cmd))
        self.set_operation(WALAEventOperation.Install)
        self.launch_command(install_cmd, timeout=900)
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

    def update(self):
        self.set_operation(WALAEventOperation.Update)
        man = self.load_manifest()
        update_cmd = man.get_update_command()
        self.logger.info("Update extension [{0}]".format(update_cmd))
        self.launch_command(update_cmd, timeout=900)
    
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
                    seperator = item.rfind(".")
                    if seperator > 0 and item[seperator + 1:] == 'settings':
                        curr_seq_no = int(item.split('.')[0])
                        if curr_seq_no > seq_no:
                            seq_no = curr_seq_no
                except Exception as e:
                    self.logger.verbose("Failed to parse file name: {0}", item)
                    continue
        return seq_no

    def collect_ext_status(self, ext):
        self.logger.verbose("Collect extension status")

        seq_no = self.get_largest_seq_no()
        if seq_no == -1:
            return None

        status_dir = self.get_status_dir()
        ext_status_file = "{0}.status".format(seq_no)
        ext_status_file = os.path.join(status_dir, ext_status_file)

        ext_status = ExtensionStatus(seq_no=seq_no)
        try:
            data_str = fileutil.read_file(ext_status_file)
            data = json.loads(data_str)
            parse_ext_status(ext_status, data)
        except IOError as e:
            ext_status.message = u"Failed to get status file {0}".format(e)
            ext_status.code = -1
            ext_status.status = "error"
        except (ExtensionError, ValueError) as e:
            ext_status.message = u"Malformed status file {0}".format(e)
            ext_status.code = -1
            ext_status.status = "error"

        return ext_status
    
    def report_ext_status(self):
        active_exts = []
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
 
    def is_responsive(self, heartbeat_file):
        last_update = int(time.time() - os.stat(heartbeat_file).st_mtime)
        return last_update <= 600    # updated within the last 10 min
   
    def launch_command(self, cmd, timeout=300):
        self.logger.verbose("Launch command: [{0}]", cmd)
        base_dir = self.get_base_dir()
        try:
            devnull = open(os.devnull, 'w')
            child = subprocess.Popen(base_dir + "/" + cmd,
                                     shell=True,
                                     cwd=base_dir,
                                     stdout=devnull,
                                     env=os.environ)
        except Exception as e:
            #TODO do not catch all exception
            raise ExtensionError("Failed to launch: {0}, {1}".format(cmd, e))

        retry = timeout
        while retry > 0 and child.poll() is None:
            time.sleep(1)
            retry -= 1
        if retry == 0:
            os.kill(child.pid, 9)
            raise ExtensionError("Timeout({0}): {1}".format(timeout, cmd))

        ret = child.wait()
        if ret == None or ret != 0:
            raise ExtensionError("Non-zero exit code: {0}, {1}".format(ret, cmd))

        self.report_event(message="Launch command succeeded: {0}".format(cmd))

    def load_manifest(self):
        man_file = self.get_manifest_file()
        try:
            data = json.loads(fileutil.read_file(man_file))
        except IOError as e:
            raise ExtensionError('Failed to load manifest file.')
        except ValueError as e:
            raise ExtensionError('Malformed manifest file.')

        return HandlerManifest(data[0])

    def update_settings_file(self, settings_file, settings):
        settings_file = os.path.join(self.get_conf_dir(), settings_file)
        try:
            fileutil.write_file(settings_file, settings)
        except IOError as e:
            raise ExtensionError(u"Failed to update settings file", e)

    def update_settings(self):
        if self.ext_handler.properties.extensions is None or \
                len(self.ext_handler.properties.extensions) == 0:
            #This is the behavior of waagent 2.0.x
            #The new agent has to be consistent with the old one.
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
                "runtimeSettings":[{
                    "handlerSettings": settings
                }]
            }
            settings_file = "{0}.settings".format(ext.sequenceNumber)
            self.logger.info("Update settings file: {0}", settings_file)
            self.update_settings_file(settings_file, json.dumps(ext_settings))

    def create_handler_env(self):
        env = [{
            "name": self.ext_handler.name,
            "version" : HANDLER_ENVIRONMENT_VERSION,
            "handlerEnvironment" : {
                "logFolder" : self.get_log_dir(),
                "configFolder" : self.get_conf_dir(),
                "statusFolder" : self.get_status_dir(),
                "heartbeatFile" : self.get_heartbeat_file()
            }
        }]
        try:
            fileutil.write_file(self.get_env_file(), json.dumps(env))
        except IOError as e:
            raise ExtensionError(u"Failed to save handler environment", e)

    def set_handler_state(self, handler_state):
        state_dir = self.get_conf_dir()
        try:
            if not os.path.exists(state_dir):
                fileutil.mkdir(state_dir, mode=0o700)

            state_file = os.path.join(state_dir, "HandlerState")
            fileutil.write_file(state_file, handler_state)
        except IOError as e:
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
        handler_status.version = self.ext_handler.properties.version
        handler_status.message = message
        handler_status.code = code
        handler_status.status = status
        status_file = os.path.join(state_dir, "HandlerStatus")

        try:
            fileutil.write_file(status_file, json.dumps(get_properties(handler_status)))
        except (IOError, ValueError, ProtocolError) as e:
            self.logger.error("Failed to save handler status: {0}", e)
        
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
        return os.path.join(conf.get_ext_log_dir(), self.ext_handler.name,
                            self.ext_handler.properties.version)

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

    def is_reboot_after_install(self):
        """
        Deprecated
        """
        return False

    def is_report_heartbeat(self):
        return self.data['handlerManifest'].get('reportHeartbeat', False)

    def is_update_with_install(self):
        update_mode = self.data['handlerManifest'].get('updateMode')
        if update_mode is None:
            return True
        return update_mode.lower() == "updatewithinstall"
