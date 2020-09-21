# Microsoft Azure Linux Agent # pylint: disable=C0302
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
import sys
import tempfile
import time
import traceback
import zipfile

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.version as version
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.datacontract import get_properties, set_properties
from azurelinuxagent.common.errorstate import ErrorState
from azurelinuxagent.common.event import add_event, elapsed_milliseconds, report_event, WALAEventOperation, \
    add_periodic, EVENTS_DIRECTORY
from azurelinuxagent.common.exception import ExtensionDownloadError, ExtensionError, ExtensionErrorCodes, \
    ExtensionOperationError, ExtensionUpdateError, ProtocolError, ProtocolNotFoundError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import ExtensionStatus, ExtensionSubStatus, ExtHandler, ExtHandlerStatus, \
    VMStatus
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION, DISTRO_NAME, DISTRO_VERSION, \
    GOAL_STATE_AGENT_VERSION, PY_VERSION_MAJOR, PY_VERSION_MICRO, PY_VERSION_MINOR

_HANDLER_NAME_PATTERN = r'^([^-]+)'
_HANDLER_VERSION_PATTERN = r'(\d+(?:\.\d+)*)'
_HANDLER_PATTERN = _HANDLER_NAME_PATTERN + r"-" + _HANDLER_VERSION_PATTERN #r'^([^-]+)-(\d+(?:\.\d+)*)'
_HANDLER_PKG_PATTERN = re.compile(_HANDLER_PATTERN + r'\.zip$', re.IGNORECASE)
_DEFAULT_EXT_TIMEOUT_MINUTES = 90

_VALID_HANDLER_STATUS = ['Ready', 'NotReady', "Installing", "Unresponsive"]

HANDLER_NAME_PATTERN = re.compile(_HANDLER_NAME_PATTERN, re.IGNORECASE)
HANDLER_COMPLETE_NAME_PATTERN = re.compile(_HANDLER_PATTERN + r'$', re.IGNORECASE)
HANDLER_PKG_EXT = ".zip"

AGENT_STATUS_FILE = "waagent_status.json"
NUMBER_OF_DOWNLOAD_RETRIES = 5

# This is the default value for the env variables, whenever we call a command which is not an update scenario, we
# set the env variable value to NOT_RUN to reduce ambiguity for the extension publishers
NOT_RUN = "NOT_RUN"

# Max size of individual status file
_MAX_STATUS_FILE_SIZE_IN_BYTES = 128 * 1024  # 128K

# Truncating length of fields.
_MAX_STATUS_MESSAGE_LENGTH = 1024  # 1k message allowed to be shown in the portal.
_MAX_SUBSTATUS_FIELD_LENGTH = 10 * 1024  # Making 10K; allowing fields to have enough debugging information..
_TRUNCATED_SUFFIX = u" ... [TRUNCATED]"

# Status file specific retries and delays.
_NUM_OF_STATUS_FILE_RETRIES = 5
_STATUS_FILE_RETRY_DELAY = 2  # seconds

_ENABLE_EXTENSION_TELEMETRY_PIPELINE = False

def is_extension_telemetry_pipeline_enabled():
    return _ENABLE_EXTENSION_TELEMETRY_PIPELINE


class ValidHandlerStatus(object): # pylint: disable=R0903
    transitioning = "transitioning"
    warning = "warning"
    error = "error"
    success = "success"
    STRINGS = ['transitioning', 'warning', 'error', 'success']


_EXTENSION_TERMINAL_STATUSES = [ValidHandlerStatus.error, ValidHandlerStatus.success]


class ExtCommandEnvVariable(object): # pylint: disable=R0903
    Prefix = "AZURE_GUEST_AGENT"
    DisableReturnCode = "%s_DISABLE_CMD_EXIT_CODE" % Prefix
    UninstallReturnCode = "%s_UNINSTALL_CMD_EXIT_CODE" % Prefix
    ExtensionPath = "%s_EXTENSION_PATH" % Prefix
    ExtensionVersion = "%s_EXTENSION_VERSION" % Prefix
    ExtensionSeqNumber = "ConfigSequenceNumber"  # At par with Windows Guest Agent
    UpdatingFromVersion = "%s_UPDATING_FROM_VERSION" % Prefix


def get_traceback(e): # pylint: disable=R1710,C0103
    if sys.version_info[0] == 3: # pylint: disable=R1705
        return e.__traceback__
    elif sys.version_info[0] == 2:
        ex_type, ex, tb = sys.exc_info() # pylint: disable=W0612,C0103
        return tb


def validate_has_key(obj, key, full_key_path):
    if key not in obj:
        raise ExtensionStatusError(msg="Invalid status format by extension: Missing {0} key".format(full_key_path),
                                   code=ExtensionStatusError.StatusFileMalformed)


def validate_in_range(val, valid_range, name):
    if val not in valid_range:
        raise ExtensionStatusError(msg="Invalid value {0} in range {1} at the node {2}".format(val, valid_range, name),
                                   code=ExtensionStatusError.StatusFileMalformed)


def parse_formatted_message(formatted_message):
    if formatted_message is None:
        return None
    validate_has_key(formatted_message, 'lang', 'formattedMessage/lang')
    validate_has_key(formatted_message, 'message', 'formattedMessage/message')
    return formatted_message.get('message')


def parse_ext_substatus(substatus):
    # Check extension sub status format
    validate_has_key(substatus, 'status', 'substatus/status')
    validate_in_range(substatus['status'], ValidHandlerStatus.STRINGS, 'substatus/status')
    status = ExtensionSubStatus()
    status.name = substatus.get('name')
    status.status = substatus.get('status')
    status.code = substatus.get('code', 0)
    formatted_message = substatus.get('formattedMessage')
    status.message = parse_formatted_message(formatted_message)
    return status


def parse_ext_status(ext_status, data):
    if data is None:
        return
    if not isinstance(data, list):
        data_string = ustr(data)[:4096]
        raise ExtensionStatusError(msg="The extension status must be an array: {0}".format(data_string), code=ExtensionStatusError.StatusFileMalformed)
    if not data:
        return

    # Currently, only the first status will be reported
    data = data[0]
    # Check extension status format
    validate_has_key(data, 'status', 'status')
    status_data = data['status']
    validate_has_key(status_data, 'status', 'status/status')

    status = status_data['status']
    if status not in ValidHandlerStatus.STRINGS:
        status = ValidHandlerStatus.error

    applied_time = status_data.get('configurationAppliedTime')
    ext_status.configurationAppliedTime = applied_time
    ext_status.operation = status_data.get('operation')
    ext_status.status = status
    ext_status.code = status_data.get('code', 0)
    formatted_message = status_data.get('formattedMessage')
    ext_status.message = parse_formatted_message(formatted_message)
    substatus_list = status_data.get('substatus', [])
    # some extensions incorrectly report an empty substatus with a null value
    if substatus_list is None:
        substatus_list = []
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
            for file in ("State", "Status"): # pylint: disable=redefined-builtin
                from_path = os.path.join(handler_state_path, handler, file.lower())
                to_path = os.path.join(handler_config_path, "Handler" + file)
                if os.path.isfile(from_path) and not os.path.isfile(to_path):
                    try:
                        shutil.move(from_path, to_path)
                    except Exception as e: # pylint: disable=C0103
                        logger.warn(
                            "Exception occurred migrating {0} {1} file: {2}",
                            handler,
                            file,
                            str(e))

    try:
        shutil.rmtree(handler_state_path)
    except Exception as e: # pylint: disable=C0103
        logger.warn("Exception occurred removing {0}: {1}", handler_state_path, str(e))
    return


class ExtHandlerState(object): # pylint: disable=R0903
    NotInstalled = "NotInstalled"
    Installed = "Installed"
    Enabled = "Enabled"
    FailedUpgrade = "FailedUpgrade"


class ExtensionRequestedState(object): # pylint: disable=R0903
    """
    This is the state of the Extension as requested by the Goal State.
    CRP only supports 2 states as of now - Enabled and Uninstall
    Disabled was used for older XML extensions and we keep it to support backward compatibility.
    """
    Enabled = u"enabled"
    Disabled = u"disabled"
    Uninstall = u"uninstall"


def get_exthandlers_handler(protocol):
    return ExtHandlersHandler(protocol)


def list_agent_lib_directory(skip_agent_package=True):
    lib_dir = conf.get_lib_dir()
    for name in os.listdir(lib_dir):
        path = os.path.join(lib_dir, name)

        if skip_agent_package and (version.is_agent_package(path) or version.is_agent_path(path)):
            continue

        yield name, path


class ExtHandlersHandler(object):
    def __init__(self, protocol):
        self.protocol = protocol
        self.ext_handlers = None
        self.last_etag = None
        self.log_report = False
        self.log_etag = True
        self.log_process = False

        self.report_status_error_state = ErrorState()

    def run(self):

        try:
            self.ext_handlers, etag = self.protocol.get_ext_handlers()
            msg = u"Handle extensions updates for incarnation {0}".format(etag)
            logger.verbose(msg)
            # Log status report success on new config
            self.log_report = True

            if self._extension_processing_allowed():
                self.handle_ext_handlers(etag)
                self.last_etag = etag

            self.report_ext_handlers_status()
            self._cleanup_outdated_handlers()
        except Exception as e: # pylint: disable=C0103
            msg = u"Exception processing extension handlers: {0}".format(ustr(e))
            detailed_msg = '{0} {1}'.format(msg, traceback.extract_tb(get_traceback(e)))
            logger.warn(msg)
            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.ExtensionProcessing,
                      is_success=False,
                      message=detailed_msg)
            return

    @staticmethod
    def get_ext_handler_instance_from_path(name, path, protocol, skip_handlers=None):
        if not os.path.isdir(path) or re.match(HANDLER_NAME_PATTERN, name) is None:
            return None
        separator = name.rfind('-')
        handler_name = name[0:separator]
        if skip_handlers is not None and handler_name in skip_handlers:
            # Handler in skip_handlers list, not parsing it
            return None

        eh = ExtHandler(name=handler_name) # pylint: disable=C0103
        eh.properties.version = str(FlexibleVersion(name[separator + 1:]))

        return ExtHandlerInstance(eh, protocol)

    def _cleanup_outdated_handlers(self): # pylint: disable=R0912
        handlers = []
        pkgs = []
        ext_handlers_in_gs = [ext_handler.name for ext_handler in self.ext_handlers.extHandlers]

        # Build a collection of uninstalled handlers and orphaned packages
        # Note:
        # -- An orphaned package is one without a corresponding handler
        #    directory

        for item, path in list_agent_lib_directory(skip_agent_package=True):
            try:
                handler_instance = ExtHandlersHandler.get_ext_handler_instance_from_path(name=item,
                                                                                         path=path,
                                                                                         protocol=self.protocol,
                                                                                         skip_handlers=ext_handlers_in_gs)
                if handler_instance is not None:
                    # Since this handler name doesn't exist in the GS, marking it for deletion
                    handlers.append(handler_instance)
                    continue
            except Exception:
                continue

            if os.path.isfile(path) and \
                    not os.path.isdir(path[0:-len(HANDLER_PKG_EXT)]):
                if not re.match(_HANDLER_PKG_PATTERN, item):
                    continue
                pkgs.append(path)

        # Then, remove the orphaned packages
        for pkg in pkgs:
            try:
                os.remove(pkg)
                logger.verbose("Removed orphaned extension package {0}".format(pkg))
            except OSError as e: # pylint: disable=C0103
                logger.warn("Failed to remove orphaned package {0}: {1}".format(pkg, e.strerror))

        # Finally, remove the directories and packages of the orphaned handlers, i.e. Any extension directory that
        # is still in the FileSystem but not in the GoalState
        for handler in handlers:
            handler.remove_ext_handler()
            pkg = os.path.join(conf.get_lib_dir(), handler.get_full_name() + HANDLER_PKG_EXT)
            if os.path.isfile(pkg):
                try:
                    os.remove(pkg)
                    logger.verbose("Removed extension package {0}".format(pkg))
                except OSError as e: # pylint: disable=C0103
                    logger.warn("Failed to remove extension package {0}: {1}".format(pkg, e.strerror))

    def _extension_processing_allowed(self):
        if not conf.get_extensions_enabled():
            logger.verbose("Extension handling is disabled")
            return False

        if conf.get_enable_overprovisioning():
            artifacts_profile = self.protocol.get_artifacts_profile()
            if artifacts_profile and artifacts_profile.is_on_hold():
                logger.info("Extension handling is on hold")
                return False

        return True

    def handle_ext_handlers(self, etag=None):
        if self.ext_handlers.extHandlers is None or \
                len(self.ext_handlers.extHandlers) == 0: # pylint: disable=len-as-condition
            logger.verbose("No extension handler config found")
            return

        wait_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=_DEFAULT_EXT_TIMEOUT_MINUTES)
        max_dep_level = max([handler.sort_key() for handler in self.ext_handlers.extHandlers])

        self.ext_handlers.extHandlers.sort(key=operator.methodcaller('sort_key'))
        for ext_handler in self.ext_handlers.extHandlers:
            self.handle_ext_handler(ext_handler, etag)

            # Wait for the extension installation until it is handled.
            # This is done for the install and enable. Not for the uninstallation.
            # If handled successfully, proceed with the current handler.
            # Otherwise, skip the rest of the extension installation.
            dep_level = ext_handler.sort_key()
            if dep_level >= 0 and dep_level < max_dep_level: # pylint: disable=R1716
                if not self.wait_for_handler_successful_completion(ext_handler, wait_until):
                    logger.warn("An extension failed or timed out, will skip processing the rest of the extensions")
                    break

    def wait_for_handler_successful_completion(self, ext_handler, wait_until):
        '''
        Check the status of the extension being handled.
        Wait until it has a terminal state or times out.
        Return True if it is handled successfully. False if not.
        '''
        handler_i = ExtHandlerInstance(ext_handler, self.protocol)
        for ext in ext_handler.properties.extensions:
            ext_completed, status = handler_i.is_ext_handling_complete(ext)

            # Keep polling for the extension status until it becomes success or times out
            while not ext_completed and datetime.datetime.utcnow() <= wait_until:
                time.sleep(5)
                ext_completed, status = handler_i.is_ext_handling_complete(ext)

            # In case of timeout or terminal error state, we log it and return false
            # so that the extensions waiting on this one can be skipped processing
            if datetime.datetime.utcnow() > wait_until:
                msg = "Extension {0} did not reach a terminal state within the allowed timeout. Last status was {1}".format(
                    ext.name, status)
                logger.warn(msg)
                add_event(AGENT_NAME,
                          version=CURRENT_VERSION,
                          op=WALAEventOperation.ExtensionProcessing,
                          is_success=False,
                          message=msg)
                return False

            if status != ValidHandlerStatus.success:
                msg = "Extension {0} did not succeed. Status was {1}".format(ext.name, status)
                logger.warn(msg)
                add_event(AGENT_NAME,
                          version=CURRENT_VERSION,
                          op=WALAEventOperation.ExtensionProcessing,
                          is_success=False,
                          message=msg)
                return False

        return True

    def handle_ext_handler(self, ext_handler, etag):
        ext_handler_i = ExtHandlerInstance(ext_handler, self.protocol)

        try:
            if self.last_etag == etag:
                if self.log_etag:
                    ext_handler_i.logger.verbose("Incarnation {0} did not change, not processing GoalState", etag)
                    self.log_etag = False
                return

            state = ext_handler.properties.state

            # The Guest Agent currently only supports 1 installed version per extension on the VM.
            # If the extension version is unregistered and the customers wants to uninstall the extension,
            # we should let it go through even if the installed version doesnt exist in Handler manifest (PIR) anymore.
            # If target state is enabled and version not found in manifest, do not process the extension.
            if ext_handler_i.decide_version(target_state=state) is None and state == ExtensionRequestedState.Enabled:
                version = ext_handler_i.ext_handler.properties.version # pylint: disable=W0621
                name = ext_handler_i.ext_handler.name
                err_msg = "Unable to find version {0} in manifest for extension {1}".format(version, name)
                ext_handler_i.set_operation(WALAEventOperation.Download)
                ext_handler_i.set_handler_status(message=ustr(err_msg), code=-1)
                ext_handler_i.report_event(message=ustr(err_msg), is_success=False)
                return

            self.log_etag = True

            ext_handler_i.logger.info("Target handler state: {0} [incarnation {1}]", state, etag)
            if state == ExtensionRequestedState.Enabled:
                self.handle_enable(ext_handler_i)
            elif state == ExtensionRequestedState.Disabled:
                self.handle_disable(ext_handler_i)
            elif state == ExtensionRequestedState.Uninstall:
                self.handle_uninstall(ext_handler_i)
            else:
                message = u"Unknown ext handler state:{0}".format(state)
                raise ExtensionError(message)
        except ExtensionUpdateError as e: # pylint: disable=C0103
            # Not reporting the error as it has already been reported from the old version
            self.handle_ext_handler_error(ext_handler_i, e, e.code, report_telemetry_event=False)
        except ExtensionDownloadError as e: # pylint: disable=C0103
            self.handle_ext_handler_download_error(ext_handler_i, e, e.code)
        except ExtensionError as e: # pylint: disable=C0103
            self.handle_ext_handler_error(ext_handler_i, e, e.code)
        except Exception as e: # pylint: disable=C0103
            self.handle_ext_handler_error(ext_handler_i, e)

    def handle_ext_handler_error(self, ext_handler_i, e, code=-1, report_telemetry_event=True): # pylint: disable=C0103
        msg = ustr(e)
        ext_handler_i.set_handler_status(message=msg, code=code)

        if report_telemetry_event:
            ext_handler_i.report_event(message=msg, is_success=False, log_event=True)

    def handle_ext_handler_download_error(self, ext_handler_i, e, code=-1): # pylint: disable=C0103
        msg = ustr(e)
        ext_handler_i.set_handler_status(message=msg, code=code)

        report_event(op=WALAEventOperation.Download, is_success=False, log_event=True,
                     message="Failed to download artifacts: {0}".format(msg))

    def handle_enable(self, ext_handler_i):
        self.log_process = True
        uninstall_exit_code = None
        old_ext_handler_i = ext_handler_i.get_installed_ext_handler()

        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("[Enable] current handler state is: {0}",
                                  handler_state.lower())
        # We go through the entire process of downloading and initializing the extension if it's either a fresh
        # extension or if it's a retry of a previously failed upgrade.
        if handler_state == ExtHandlerState.NotInstalled or handler_state == ExtHandlerState.FailedUpgrade: # pylint: disable=R1714
            ext_handler_i.set_handler_state(ExtHandlerState.NotInstalled)
            ext_handler_i.download()
            ext_handler_i.initialize()
            ext_handler_i.update_settings()
            if old_ext_handler_i is None:
                ext_handler_i.install()
            elif ext_handler_i.version_ne(old_ext_handler_i):
                uninstall_exit_code = ExtHandlersHandler._update_extension_handler_and_return_if_failed(
                    old_ext_handler_i, ext_handler_i)
        else:
            ext_handler_i.update_settings()

        ext_handler_i.enable(uninstall_exit_code=uninstall_exit_code)

    @staticmethod
    def _update_extension_handler_and_return_if_failed(old_ext_handler_i, ext_handler_i):

        def execute_old_handler_command_and_return_if_succeeds(func):
            """
            Created a common wrapper to execute all commands that need to be executed from the old handler
            so that it can have a common exception handling mechanism
            :param func: The command to be executed on the old handler
            :return: True if command execution succeeds and False if it fails
            """
            continue_on_update_failure = False
            exit_code = 0
            try:
                continue_on_update_failure = ext_handler_i.load_manifest().is_continue_on_update_failure()
                func()
            except ExtensionError as e: # pylint: disable=C0103
                # Reporting the event with the old handler and raising a new ExtensionUpdateError to set the
                # handler status on the new version
                msg = "%s; ContinueOnUpdate: %s" % (ustr(e), continue_on_update_failure)
                old_ext_handler_i.report_event(message=msg, is_success=False)
                if not continue_on_update_failure:
                    raise ExtensionUpdateError(msg)

                exit_code = e.code
                if isinstance(e, ExtensionOperationError):
                    exit_code = e.exit_code # pylint: disable=E1101

                logger.info("Continue on Update failure flag is set, proceeding with update")
            return exit_code

        disable_exit_code = NOT_RUN
        # We only want to disable the old handler if it is currently enabled; no
        # other state makes sense.
        if old_ext_handler_i.get_handler_state() == ExtHandlerState.Enabled:
            disable_exit_code = execute_old_handler_command_and_return_if_succeeds(
                func=lambda: old_ext_handler_i.disable()) # pylint: disable=W0108

        ext_handler_i.copy_status_files(old_ext_handler_i)
        if ext_handler_i.version_gt(old_ext_handler_i):
            ext_handler_i.update(disable_exit_code=disable_exit_code,
                                 updating_from_version=old_ext_handler_i.ext_handler.properties.version)
        else:
            updating_from_version = ext_handler_i.ext_handler.properties.version
            old_ext_handler_i.update(version=updating_from_version,
                                     disable_exit_code=disable_exit_code, updating_from_version=updating_from_version)
        uninstall_exit_code = execute_old_handler_command_and_return_if_succeeds(
            func=lambda: old_ext_handler_i.uninstall()) # pylint: disable=W0108
        old_ext_handler_i.remove_ext_handler()
        ext_handler_i.update_with_install(uninstall_exit_code=uninstall_exit_code)
        return uninstall_exit_code

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

            # Try uninstalling the extension and swallow any exceptions in case of failures after logging them
            try:
                ext_handler_i.uninstall()
            except ExtensionError as e: # pylint: disable=C0103
                ext_handler_i.report_event(message=ustr(e), is_success=False)

        ext_handler_i.remove_ext_handler()

    def report_ext_handlers_status(self):
        """
        Go through handler_state dir, collect and report status
        """
        vm_status = VMStatus(status="Ready", message="Guest Agent is running")
        if self.ext_handlers is not None:
            for ext_handler in self.ext_handlers.extHandlers:
                try:
                    self.report_ext_handler_status(vm_status, ext_handler)
                except ExtensionError as e: # pylint: disable=C0103
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
        except ProtocolNotFoundError as e: # pylint: disable=C0103
            self.report_status_error_state.incr()
            message = "Failed to report vm agent status: {0}".format(e)
            logger.verbose(message)
        except ProtocolError as e: # pylint: disable=C0103
            self.report_status_error_state.incr()
            message = "Failed to report vm agent status: {0}".format(e)
            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.ExtensionProcessing,
                      is_success=False,
                      message=message)

        if self.report_status_error_state.is_triggered():
            message = "Failed to report vm agent status for more than {0}" \
                .format(self.report_status_error_state.min_timedelta)

            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.ReportStatusExtended,
                      is_success=False,
                      message=message)

            self.report_status_error_state.reset()

        self.write_ext_handlers_status_to_info_file(vm_status)

    @staticmethod
    def write_ext_handlers_status_to_info_file(vm_status):
        status_path = os.path.join(conf.get_lib_dir(), AGENT_STATUS_FILE)

        agent_details = {
            "agent_name": AGENT_NAME,
            "current_version": str(CURRENT_VERSION),
            "goal_state_version": str(GOAL_STATE_AGENT_VERSION),
            "distro_details": "{0}:{1}".format(DISTRO_NAME, DISTRO_VERSION),
            "last_successful_status_upload_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python_version": "Python: {0}.{1}.{2}".format(PY_VERSION_MAJOR, PY_VERSION_MINOR, PY_VERSION_MICRO)
        }

        # Convert VMStatus class to Dict.
        data = get_properties(vm_status)

        # The above class contains vmAgent.extensionHandlers
        # (more info: azurelinuxagent.common.protocol.restapi.VMAgentStatus)
        handler_statuses = data['vmAgent']['extensionHandlers']
        for handler_status in handler_statuses:
            try:
                handler_status.pop('code', None)
                handler_status.pop('message', None)
                handler_status.pop('extensions', None)
            except KeyError:
                pass

        agent_details['extensions_status'] = handler_statuses
        agent_details_json = json.dumps(agent_details)

        fileutil.write_file(status_path, agent_details_json)

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
            except ExtensionError as e: # pylint: disable=C0103
                ext_handler_i.set_handler_status(message=ustr(e), code=e.code)

            try:
                heartbeat = ext_handler_i.collect_heartbeat()
                if heartbeat is not None:
                    handler_status.status = heartbeat.get('status')
            except ExtensionError as e: # pylint: disable=C0103
                ext_handler_i.set_handler_status(message=ustr(e), code=e.code)

        vm_status.vmAgent.extensionHandlers.append(handler_status)


class ExtHandlerInstance(object): # pylint: disable=R0904
    def __init__(self, ext_handler, protocol):
        self.ext_handler = ext_handler
        self.protocol = protocol
        self.operation = None
        self.pkg = None
        self.pkg_file = None
        self.logger = None
        self.set_logger()

        try:
            fileutil.mkdir(self.get_log_dir(), mode=0o755)
        except IOError as e: # pylint: disable=C0103
            self.logger.error(u"Failed to create extension log dir: {0}", e)

        log_file = os.path.join(self.get_log_dir(), "CommandExecution.log")
        self.logger.add_appender(logger.AppenderType.FILE,
                                 logger.LogLevel.INFO, log_file)

    def decide_version(self, target_state=None):
        self.logger.verbose("Decide which version to use")
        try:
            pkg_list = self.protocol.get_ext_handler_pkgs(self.ext_handler)
        except ProtocolError as e: # pylint: disable=C0103
            raise ExtensionError("Failed to get ext handler pkgs", e)
        except ExtensionDownloadError:
            self.set_operation(WALAEventOperation.Download)
            raise

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
        if target_state in (ExtensionRequestedState.Uninstall, ExtensionRequestedState.Disabled):
            if installed_pkg is None:
                msg = "Failed to find installed version: {0} of Handler: {1}  in handler manifest to uninstall.".format(
                    installed_version, self.ext_handler.name)
                self.logger.warn(msg)
            self.pkg = installed_pkg
            self.ext_handler.properties.version = str(installed_version) \
                if installed_version is not None else None
        else:
            self.pkg = selected_pkg
            if self.pkg is not None:
                self.ext_handler.properties.version = str(selected_pkg.version)

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
        latest_version = self.get_installed_version()
        if latest_version is None:
            return None

        installed_handler = ExtHandler()
        set_properties("ExtHandler", installed_handler, get_properties(self.ext_handler))
        installed_handler.properties.version = latest_version
        return ExtHandlerInstance(installed_handler, self.protocol)

    def get_installed_version(self):
        latest_version = None

        for path in glob.iglob(os.path.join(conf.get_lib_dir(), self.ext_handler.name + "-*")):
            if not os.path.isdir(path):
                continue

            separator = path.rfind('-')
            version_from_path = FlexibleVersion(path[separator + 1:])
            state_path = os.path.join(path, 'config', 'HandlerState')

            if not os.path.exists(state_path) or fileutil.read_file(state_path) == ExtHandlerState.NotInstalled \
                    or fileutil.read_file(state_path) == ExtHandlerState.FailedUpgrade:
                logger.verbose("Ignoring version of uninstalled or failed extension: "
                               "{0}".format(path))
                continue

            if latest_version is None or latest_version < version_from_path:
                latest_version = version_from_path

        return str(latest_version) if latest_version is not None else None

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

    def set_operation(self, op): # pylint: disable=C0103
        self.operation = op

    def report_event(self, message="", is_success=True, duration=0, log_event=True):
        ext_handler_version = self.ext_handler.properties.version
        add_event(name=self.ext_handler.name, version=ext_handler_version, message=message,
                  op=self.operation, is_success=is_success, duration=duration, log_event=log_event)

    def _download_extension_package(self, source_uri, target_file):
        self.logger.info("Downloading extension package: {0}", source_uri)
        try:
            if not self.protocol.download_ext_handler_pkg(source_uri, target_file):
                raise Exception("Failed to download extension package - no error information is available")
        except Exception as exception:
            self.logger.info("Error downloading extension package: {0}", ustr(exception))
            if os.path.exists(target_file):
                os.remove(target_file)
            return False
        return True

    def _unzip_extension_package(self, source_file, target_directory):
        self.logger.info("Unzipping extension package: {0}", source_file)
        try:
            zipfile.ZipFile(source_file).extractall(target_directory)
        except Exception as exception:
            logger.info("Error while unzipping extension package: {0}", ustr(exception))
            os.remove(source_file)
            if os.path.exists(target_directory):
                shutil.rmtree(target_directory)
            return False
        return True

    def download(self):
        begin_utc = datetime.datetime.utcnow()
        self.set_operation(WALAEventOperation.Download)

        if self.pkg is None or self.pkg.uris is None or len(self.pkg.uris) == 0: # pylint: disable=len-as-condition
            raise ExtensionDownloadError("No package uri found")

        destination = os.path.join(conf.get_lib_dir(), self.get_extension_package_zipfile_name())

        package_exists = False
        if os.path.exists(destination):
            self.logger.info("Using existing extension package: {0}", destination)
            if self._unzip_extension_package(destination, self.get_base_dir()):
                package_exists = True
            else:
                self.logger.info("The existing extension package is invalid, will ignore it.")

        if not package_exists:
            downloaded = False
            i = 0
            while i < NUMBER_OF_DOWNLOAD_RETRIES:
                uris_shuffled = self.pkg.uris
                random.shuffle(uris_shuffled)

                for uri in uris_shuffled:
                    if not self._download_extension_package(uri.uri, destination):
                        continue

                    if self._unzip_extension_package(destination, self.get_base_dir()):
                        downloaded = True
                        break

                if downloaded:
                    break

                self.logger.info("Failed to download the extension package from all uris, will retry after a minute")
                time.sleep(60)
                i += 1

            if not downloaded:
                raise ExtensionDownloadError("Failed to download extension",
                                             code=ExtensionErrorCodes.PluginManifestDownloadError)

            duration = elapsed_milliseconds(begin_utc)
            self.report_event(message="Download succeeded", duration=duration)

        self.pkg_file = destination

    def initialize(self):
        self.logger.info("Initializing extension {0}".format(self.get_full_name()))

        # Add user execute permission to all files under the base dir
        for file in fileutil.get_all_files(self.get_base_dir()): # pylint: disable=redefined-builtin
            fileutil.chmod(file, os.stat(file).st_mode | stat.S_IXUSR)

        # Save HandlerManifest.json
        man_file = fileutil.search_file(self.get_base_dir(), 'HandlerManifest.json')

        if man_file is None:
            raise ExtensionDownloadError("HandlerManifest.json not found")

        try:
            man = fileutil.read_file(man_file, remove_bom=True)
            fileutil.write_file(self.get_manifest_file(), man)
        except IOError as e: # pylint: disable=C0103
            fileutil.clean_ioerror(e, paths=[self.get_base_dir(), self.pkg_file])
            raise ExtensionDownloadError(u"Failed to save HandlerManifest.json", e)

        # Create status and config dir
        try:
            status_dir = self.get_status_dir()
            fileutil.mkdir(status_dir, mode=0o700)

            conf_dir = self.get_conf_dir()
            fileutil.mkdir(conf_dir, mode=0o700)

            if is_extension_telemetry_pipeline_enabled():
                fileutil.mkdir(self.get_extension_events_dir(), mode=0o700)

            seq_no, status_path = self.get_status_file_path() # pylint: disable=W0612
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

        except IOError as e: # pylint: disable=C0103
            fileutil.clean_ioerror(e, paths=[self.get_base_dir(), self.pkg_file])
            raise ExtensionDownloadError(u"Failed to initialize extension '{0}'".format(self.get_full_name()), e)

        # Save HandlerEnvironment.json
        self.create_handler_env()

    def enable(self, uninstall_exit_code=None):
        uninstall_exit_code = str(uninstall_exit_code) if uninstall_exit_code is not None else NOT_RUN
        env = {ExtCommandEnvVariable.UninstallReturnCode: uninstall_exit_code}

        self.set_operation(WALAEventOperation.Enable)
        man = self.load_manifest()
        enable_cmd = man.get_enable_command()
        self.logger.info("Enable extension [{0}]".format(enable_cmd))
        self.launch_command(enable_cmd, timeout=300,
                            extension_error_code=ExtensionErrorCodes.PluginEnableProcessingFailed, env=env)
        self.set_handler_state(ExtHandlerState.Enabled)
        self.set_handler_status(status="Ready", message="Plugin enabled")

    def disable(self):
        self.set_operation(WALAEventOperation.Disable)
        man = self.load_manifest()
        disable_cmd = man.get_disable_command()
        self.logger.info("Disable extension [{0}]".format(disable_cmd))
        self.launch_command(disable_cmd, timeout=900,
                            extension_error_code=ExtensionErrorCodes.PluginDisableProcessingFailed)
        self.set_handler_state(ExtHandlerState.Installed)
        self.set_handler_status(status="NotReady", message="Plugin disabled")

    def install(self, uninstall_exit_code=None):
        uninstall_exit_code = str(uninstall_exit_code) if uninstall_exit_code is not None else NOT_RUN
        env = {ExtCommandEnvVariable.UninstallReturnCode: uninstall_exit_code}

        man = self.load_manifest()
        install_cmd = man.get_install_command()
        self.logger.info("Install extension [{0}]".format(install_cmd))
        self.set_operation(WALAEventOperation.Install)
        self.launch_command(install_cmd, timeout=900,
                            extension_error_code=ExtensionErrorCodes.PluginInstallProcessingFailed, env=env)
        self.set_handler_state(ExtHandlerState.Installed)

    def uninstall(self):
        self.set_operation(WALAEventOperation.UnInstall)
        man = self.load_manifest()
        uninstall_cmd = man.get_uninstall_command()
        self.logger.info("Uninstall extension [{0}]".format(uninstall_cmd))
        self.launch_command(uninstall_cmd)

    def remove_ext_handler(self):
        try:
            zip_filename = os.path.join(conf.get_lib_dir(), self.get_extension_package_zipfile_name())
            if os.path.exists(zip_filename):
                os.remove(zip_filename)
                self.logger.verbose("Deleted the extension zip at path {0}", zip_filename)

            base_dir = self.get_base_dir()
            if os.path.isdir(base_dir):
                self.logger.info("Remove extension handler directory: {0}", base_dir)

                # some extensions uninstall asynchronously so ignore error 2 while removing them
                def on_rmtree_error(_, __, exc_info):
                    _, exception, _ = exc_info
                    if not isinstance(exception, OSError) or exception.errno != 2:  # [Errno 2] No such file or directory
                        raise exception

                shutil.rmtree(base_dir, onerror=on_rmtree_error)
        except IOError as e: # pylint: disable=C0103
            message = "Failed to remove extension handler directory: {0}".format(e)
            self.report_event(message=message, is_success=False)
            self.logger.warn(message)

    def update(self, version=None, disable_exit_code=None, updating_from_version=None): # pylint: disable=W0621
        if version is None:
            version = self.ext_handler.properties.version

        disable_exit_code = str(disable_exit_code) if disable_exit_code is not None else NOT_RUN
        env = {'VERSION': version, ExtCommandEnvVariable.DisableReturnCode: disable_exit_code,
               ExtCommandEnvVariable.UpdatingFromVersion: updating_from_version}

        try:
            self.set_operation(WALAEventOperation.Update)
            man = self.load_manifest()
            update_cmd = man.get_update_command()
            self.logger.info("Update extension [{0}]".format(update_cmd))
            self.launch_command(update_cmd,
                                timeout=900,
                                extension_error_code=ExtensionErrorCodes.PluginUpdateProcessingFailed,
                                env=env)
        except ExtensionError:
            # Mark the handler as Failed so we don't clean it up and can keep reporting its status
            self.set_handler_state(ExtHandlerState.FailedUpgrade)
            raise

    def update_with_install(self, uninstall_exit_code=None):
        man = self.load_manifest()
        if man.is_update_with_install():
            self.install(uninstall_exit_code=uninstall_exit_code)
        else:
            self.logger.info("UpdateWithInstall not set. "
                             "Skip install during upgrade.")
        self.set_handler_state(ExtHandlerState.Installed)

    def _get_largest_seq_no(self):
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
        seq_no = self._get_largest_seq_no()

        # Issue 1116: use the sequence number from goal state where possible
        if extension is not None and extension.sequenceNumber is not None:
            try:
                gs_seq_no = int(extension.sequenceNumber)

                if gs_seq_no != seq_no:
                    add_event(AGENT_NAME, version=CURRENT_VERSION, op=WALAEventOperation.SequenceNumberMismatch,
                              is_success=False, message="Goal state: {0}, disk: {1}".format(gs_seq_no, seq_no),
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
        self.logger.verbose("Collect extension status for {0}".format(ext.name))
        seq_no, ext_status_file = self.get_status_file_path(ext)
        if seq_no == -1:
            return None

        data = None
        data_str = None
        ext_status = ExtensionStatus(seq_no=seq_no)

        try:
            data_str, data = self._read_and_parse_json_status_file(ext_status_file)
        except ExtensionStatusError as e: # pylint: disable=C0103
            msg = ""
            if e.code == ExtensionStatusError.CouldNotReadStatusFile:
                ext_status.code = ExtensionErrorCodes.PluginUnknownFailure
                msg = u"We couldn't read any status for {0}-{1} extension, for the sequence number {2}. It failed due" \
                      u" to {3}".format(ext.name, self.ext_handler.properties.version, seq_no, e)
            elif ExtensionStatusError.InvalidJsonFile:
                ext_status.code = ExtensionErrorCodes.PluginSettingsStatusInvalid
                msg = u"The status reported by the extension {0}-{1}(Sequence number {2}), was in an " \
                      u"incorrect format and the agent could not parse it correctly. Failed due to {3}" \
                      .format(ext.name, self.ext_handler.properties.version, seq_no, e)

            # This log is periodic due to the verbose nature of the status check. Please make sure that the message
            # constructed above does not change very frequently and includes important info such as sequence number,
            # extension name to make sure that the log reflects changes in the extension sequence for which the
            # status is being sent.
            logger.periodic_warn(logger.EVERY_HALF_HOUR, u"[PERIODIC] " + msg)
            add_periodic(delta=logger.EVERY_HALF_HOUR, name=ext.name, version=self.ext_handler.properties.version,
                         op=WALAEventOperation.StatusProcessing, is_success=False, message=msg,
                         log_event=False)

            ext_status.message = msg
            ext_status.status = ValidHandlerStatus.error

            return ext_status

        # We did not encounter InvalidJsonFile/CouldNotReadStatusFile and thus the status file was correctly written
        # and has valid json.
        try:
            parse_ext_status(ext_status, data)
            if len(data_str) > _MAX_STATUS_FILE_SIZE_IN_BYTES:
                raise ExtensionStatusError(msg="For Extension Handler {0}-{1} for the sequence number {2}, the status "
                                               "file {3} of size {4} bytes is too big. Max Limit allowed is {5} bytes"
                                           .format(ext.name, self.ext_handler.properties.version, seq_no,
                                                   ext_status_file, len(data_str), _MAX_STATUS_FILE_SIZE_IN_BYTES),
                                           code=ExtensionStatusError.MaxSizeExceeded)
        except ExtensionStatusError as e: # pylint: disable=C0103
            msg = u"For Extension Handler {0}-{1} for the sequence number {2}, the status file {3}. " \
                  u"Encountered the following error: {4}".format(ext.name, self.ext_handler.properties.version, seq_no,
                                                                 ext_status_file, ustr(e))
            logger.periodic_warn(logger.EVERY_DAY, u"[PERIODIC] " + msg)
            add_periodic(delta=logger.EVERY_HALF_HOUR, name=ext.name, version=self.ext_handler.properties.version,
                         op=WALAEventOperation.StatusProcessing, is_success=False, message=msg, log_event=False)

            if e.code == ExtensionStatusError.MaxSizeExceeded:
                ext_status.message, field_size = self._truncate_message(ext_status.message, _MAX_STATUS_MESSAGE_LENGTH)
                ext_status.substatusList = self._process_substatus_list(ext_status.substatusList, field_size)

            elif e.code == ExtensionStatusError.StatusFileMalformed:
                ext_status.message = "Could not get a valid status from the extension {0}-{1}. Encountered the " \
                                     "following error: {2}".format(ext.name, self.ext_handler.properties.version,
                                                                   ustr(e))
                ext_status.code = ExtensionErrorCodes.PluginSettingsStatusInvalid
                ext_status.status = ValidHandlerStatus.error

        return ext_status

    def get_ext_handling_status(self, ext):
        seq_no, ext_status_file = self.get_status_file_path(ext)
        if seq_no < 0 or ext_status_file is None:
            return None

        # Missing status file is considered a non-terminal state here
        # so that extension sequencing can wait until it becomes existing
        if not os.path.exists(ext_status_file):
            status = "warning"
        else:
            ext_status = self.collect_ext_status(ext)
            status = ext_status.status if ext_status is not None else None

        return status

    def is_ext_handling_complete(self, ext):
        status = self.get_ext_handling_status(ext)

        # when seq < 0 (i.e. no new user settings), the handling is complete and return None status
        if status is None:
            return (True, None)

        # If not in terminal state, it is incomplete
        if status not in _EXTENSION_TERMINAL_STATUSES:
            return (False, status)

        # Extension completed, return its status
        return (True, status)

    def report_ext_status(self):
        active_exts = []
        # TODO Refactor or remove this common code pattern (for each extension subordinate to an ext_handler, do X). # pylint: disable=W0511
        for ext in self.ext_handler.properties.extensions:
            ext_status = self.collect_ext_status(ext)
            if ext_status is None:
                continue
            try:
                self.protocol.report_ext_status(self.ext_handler.name, ext.name,
                                                ext_status)
                active_exts.append(ext.name)
            except ProtocolError as e: # pylint: disable=C0103
                self.logger.error(u"Failed to report extension status: {0}", e)
        return active_exts

    def collect_heartbeat(self): # pylint: disable=R1710
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
        except IOError as e: # pylint: disable=C0103
            raise ExtensionError("Failed to get heartbeat file:{0}".format(e))
        except (ValueError, KeyError) as e: # pylint: disable=C0103
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

    def launch_command(self, cmd, timeout=300, extension_error_code=ExtensionErrorCodes.PluginProcessingError,
                       env=None):
        begin_utc = datetime.datetime.utcnow()
        self.logger.verbose("Launch command: [{0}]", cmd)

        base_dir = self.get_base_dir()

        with tempfile.TemporaryFile(dir=base_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=base_dir, mode="w+b") as stderr:
                if env is None:
                    env = {}
                env.update(os.environ)
                # Always add Extension Path and version to the current launch_command (Ask from publishers)
                env.update({ExtCommandEnvVariable.ExtensionPath: base_dir,
                            ExtCommandEnvVariable.ExtensionVersion: str(self.ext_handler.properties.version),
                            ExtCommandEnvVariable.ExtensionSeqNumber: str(self.get_seq_no())})

                try:
                    # Some extensions erroneously begin cmd with a slash; don't interpret those
                    # as root-relative. (Issue #1170)
                    full_path = os.path.join(base_dir, cmd.lstrip(os.path.sep))

                    process_output = CGroupConfigurator.get_instance().start_extension_command(
                        extension_name=self.get_full_name(),
                        command=full_path,
                        timeout=timeout,
                        shell=True,
                        cwd=base_dir,
                        env=env,
                        stdout=stdout,
                        stderr=stderr,
                        error_code=extension_error_code)

                except OSError as e: # pylint: disable=C0103
                    raise ExtensionError("Failed to launch '{0}': {1}".format(full_path, e.strerror),
                                         code=extension_error_code)

                duration = elapsed_milliseconds(begin_utc)
                log_msg = "{0}\n{1}".format(cmd, "\n".join([line for line in process_output.split('\n') if line != ""]))

                self.logger.verbose(log_msg)
                self.report_event(message=log_msg, duration=duration, log_event=False)

                return process_output

    def load_manifest(self):
        man_file = self.get_manifest_file()
        try:
            data = json.loads(fileutil.read_file(man_file))
        except (IOError, OSError) as e: # pylint: disable=C0103
            raise ExtensionError('Failed to load manifest file ({0}): {1}'.format(man_file, e.strerror),
                                 code=ExtensionErrorCodes.PluginHandlerManifestNotFound)
        except ValueError:
            raise ExtensionError('Malformed manifest file ({0}).'.format(man_file),
                                 code=ExtensionErrorCodes.PluginHandlerManifestDeserializationError)

        return HandlerManifest(data[0])

    def update_settings_file(self, settings_file, settings):
        settings_file = os.path.join(self.get_conf_dir(), settings_file)
        try:
            fileutil.write_file(settings_file, settings)
        except IOError as e: # pylint: disable=C0103
            fileutil.clean_ioerror(e,
                                   paths=[settings_file])
            raise ExtensionError(u"Failed to update settings file", e)

    def update_settings(self):
        if self.ext_handler.properties.extensions is None or \
                len(self.ext_handler.properties.extensions) == 0: # pylint: disable=len-as-condition
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
        handler_env = {
                HandlerEnvironment.logFolder: self.get_log_dir(), 
                HandlerEnvironment.configFolder: self.get_conf_dir(), 
                HandlerEnvironment.statusFolder: self.get_status_dir(), 
                HandlerEnvironment.heartbeatFile: self.get_heartbeat_file() 
            }

        if is_extension_telemetry_pipeline_enabled():
            handler_env[HandlerEnvironment.eventsFolder] = self.get_extension_events_dir()

        env = [{
            HandlerEnvironment.name: self.ext_handler.name,
            HandlerEnvironment.version: HandlerEnvironment.schemaVersion,
            HandlerEnvironment.handlerEnvironment: handler_env
        }]
        try:
            fileutil.write_file(self.get_env_file(), json.dumps(env))
        except IOError as e: # pylint: disable=C0103
            fileutil.clean_ioerror(e,
                                   paths=[self.get_base_dir(), self.pkg_file])
            raise ExtensionDownloadError(u"Failed to save handler environment", e)

    def set_handler_state(self, handler_state):
        state_dir = self.get_conf_dir()
        state_file = os.path.join(state_dir, "HandlerState")
        try:
            if not os.path.exists(state_dir):
                fileutil.mkdir(state_dir, mode=0o700)
            fileutil.write_file(state_file, handler_state)
        except IOError as e: # pylint: disable=C0103
            fileutil.clean_ioerror(e, paths=[state_file])
            self.logger.error("Failed to set state: {0}", e)

    def get_handler_state(self):
        state_dir = self.get_conf_dir()
        state_file = os.path.join(state_dir, "HandlerState")
        if not os.path.isfile(state_file):
            return ExtHandlerState.NotInstalled

        try:
            return fileutil.read_file(state_file)
        except IOError as e: # pylint: disable=C0103
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
                if not os.path.exists(state_dir):
                    fileutil.mkdir(state_dir, mode=0o700)
                fileutil.write_file(status_file, handler_status_json)
            else:
                self.logger.error("Failed to create JSON document of handler status for {0} version {1}".format(
                    self.ext_handler.name,
                    self.ext_handler.properties.version))
        except (IOError, ValueError, ProtocolError) as e: # pylint: disable=C0103
            fileutil.clean_ioerror(e, paths=[status_file])
            self.logger.error("Failed to save handler status: {0}, {1}", ustr(e), traceback.format_exc())

    def get_handler_status(self):
        state_dir = self.get_conf_dir()
        status_file = os.path.join(state_dir, "HandlerStatus")
        if not os.path.isfile(status_file):
            return None

        handler_status_contents = ""
        try:
            handler_status_contents = fileutil.read_file(status_file)
            data = json.loads(handler_status_contents)
            handler_status = ExtHandlerStatus()
            set_properties("ExtHandlerStatus", handler_status, data)
            return handler_status
        except (IOError, ValueError) as e: # pylint: disable=C0103
            self.logger.error("Failed to get handler status: {0}", e)
        except Exception as e: # pylint: disable=C0103
            error_msg = "Failed to get handler status message: {0}.\n Contents of file: {1}".format(
                ustr(e), handler_status_contents).replace('"', '\'')
            add_periodic(
                delta=logger.EVERY_HOUR,
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.ExtensionProcessing,
                is_success=False,
                message=error_msg)
            raise

    def get_extension_package_zipfile_name(self):
        return "{0}__{1}{2}".format(self.ext_handler.name,
                                    self.ext_handler.properties.version,
                                    HANDLER_PKG_EXT)

    def get_full_name(self):
        return "{0}-{1}".format(self.ext_handler.name,
                                self.ext_handler.properties.version)

    def get_base_dir(self):
        return os.path.join(conf.get_lib_dir(), self.get_full_name())

    def get_status_dir(self):
        return os.path.join(self.get_base_dir(), "status")

    def get_conf_dir(self):
        return os.path.join(self.get_base_dir(), 'config')

    def get_extension_events_dir(self):
        return os.path.join(self.get_log_dir(), EVENTS_DIRECTORY)

    def get_heartbeat_file(self):
        return os.path.join(self.get_base_dir(), 'heartbeat.log')

    def get_manifest_file(self):
        return os.path.join(self.get_base_dir(), 'HandlerManifest.json')

    def get_env_file(self):
        return os.path.join(self.get_base_dir(), HandlerEnvironment.fileName)

    def get_log_dir(self):
        return os.path.join(conf.get_ext_log_dir(), self.ext_handler.name)

    def get_seq_no(self):
        runtime_settings = self.ext_handler.properties.extensions
        # If no runtime_settings available for this ext_handler, then return 0 (this is the behavior we follow
        # for update_settings)
        if not runtime_settings or len(runtime_settings) == 0: # pylint: disable=len-as-condition
            return "0"
        # Currently for every runtime settings we use the same sequence number
        # (Check : def parse_plugin_settings(self, ext_handler, plugin_settings) in wire.py)
        # Will have to revisit once the feature to enable multiple runtime settings is rolled out by CRP
        return self.ext_handler.properties.extensions[0].sequenceNumber

    @staticmethod
    def _read_and_parse_json_status_file(ext_status_file):
        failed_to_read = False
        failed_to_parse_json = False
        raised_exception = None
        data_str = None
        data = None

        for attempt in range(_NUM_OF_STATUS_FILE_RETRIES): # pylint: disable=W0612
            try:
                data_str = fileutil.read_file(ext_status_file)
                data = json.loads(data_str)
                break
            except IOError as e: # pylint: disable=C0103
                failed_to_read = True
                raised_exception = e
            except (ValueError, TypeError) as e: # pylint: disable=C0103
                failed_to_parse_json = True
                raised_exception = e
            time.sleep(_STATUS_FILE_RETRY_DELAY)

        if failed_to_read: # pylint: disable=R1720
            raise ExtensionStatusError(msg=ustr(raised_exception), inner=raised_exception,
                                       code=ExtensionStatusError.CouldNotReadStatusFile)
        elif failed_to_parse_json:
            raise ExtensionStatusError(msg=ustr(raised_exception), inner=raised_exception,
                                       code=ExtensionStatusError.InvalidJsonFile)
        else:
            return data_str, data

    def _process_substatus_list(self, substatus_list, current_status_size=0):
        processed_substatus = []

        # Truncating the substatus to reduce the size, and preserve other fields of the text
        for substatus in substatus_list:
            substatus.name, field_size = self._truncate_message(substatus.name, _MAX_SUBSTATUS_FIELD_LENGTH)
            current_status_size += field_size

            substatus.message, field_size = self._truncate_message(substatus.message, _MAX_SUBSTATUS_FIELD_LENGTH)
            current_status_size += field_size

            if current_status_size <= _MAX_STATUS_FILE_SIZE_IN_BYTES:
                processed_substatus.append(substatus)
            else:
                break

        return processed_substatus

    @staticmethod
    def _truncate_message(field, truncate_size=_MAX_SUBSTATUS_FIELD_LENGTH): # pylint: disable=R1710
        if field is None: # pylint: disable=R1705
            return
        else:
            truncated_field = field if len(field) < truncate_size else field[:truncate_size] + _TRUNCATED_SUFFIX
            return truncated_field, len(truncated_field)


class HandlerEnvironment(object): # pylint: disable=R0903
    # HandlerEnvironment.json schema version
    schemaVersion = 1.0
    fileName = "HandlerEnvironment.json"
    handlerEnvironment = "handlerEnvironment"
    logFolder = "logFolder"
    configFolder = "configFolder"
    statusFolder = "statusFolder"
    heartbeatFile = "heartbeatFile"
    eventsFolder = "eventsFolder"
    name = "name"
    version = "version"


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

    def is_continue_on_update_failure(self):
        return self.data['handlerManifest'].get('continueOnUpdateFailure', False)


class ExtensionStatusError(ExtensionError):
    """
    When extension failed to provide a valid status file
    """
    CouldNotReadStatusFile = 1
    InvalidJsonFile = 2
    StatusFileMalformed = 3
    MaxSizeExceeded = 4

    def __init__(self, msg=None, inner=None, code=-1): # pylint: disable=W0235
        super(ExtensionStatusError, self).__init__(msg, inner, code)