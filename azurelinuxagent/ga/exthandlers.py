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
import copy
import datetime
import glob
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
from collections import defaultdict
from functools import partial

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common import version
from azurelinuxagent.common import event
from azurelinuxagent.common.agent_supported_feature import get_agent_supported_features_list_for_extensions, \
    SupportedFeatureNames, get_supported_feature_by_name, get_agent_supported_features_list_for_crp
from azurelinuxagent.common.utils.textutil import redact_sas_token
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.ga.policy.policy_engine import ExtensionPolicyEngine, ExtensionDisallowedError, \
    ExtensionSignaturePolicyError
from azurelinuxagent.common.datacontract import get_properties, set_properties
from azurelinuxagent.common.errorstate import ErrorState
from azurelinuxagent.common.event import add_event, elapsed_milliseconds, WALAEventOperation, \
    add_periodic, EVENTS_DIRECTORY
from azurelinuxagent.common.exception import ExtensionDownloadError, ExtensionError, ExtensionErrorCodes, \
    ExtensionOperationError, ExtensionUpdateError, ProtocolError, ProtocolNotFoundError, ExtensionsGoalStateError, \
    GoalStateAggregateStatusCodes, MultiConfigExtensionEnableError
from azurelinuxagent.common.future import ustr, UTC, is_file_not_found_error
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateSource
from azurelinuxagent.common.protocol.restapi import ExtensionStatus, ExtensionSubStatus, Extension, ExtHandlerStatus, \
    VMStatus, GoalStateAggregateStatus, ExtensionState, ExtensionRequestedState, ExtensionSettings
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.utils.archive import ARCHIVE_DIRECTORY_NAME
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.ga.signature_validation_util import validate_handler_manifest_signing_info, SignatureValidationError, \
    PackageValidationError, ManifestValidationError, signature_validation_enabled, validate_signature, \
    cleanup_package_with_invalid_signature, report_validation_event

_HANDLER_NAME_PATTERN = r'^([^-]+)'
_HANDLER_VERSION_PATTERN = r'(\d+(?:\.\d+)*)'
_HANDLER_PATTERN = _HANDLER_NAME_PATTERN + r"-" + _HANDLER_VERSION_PATTERN
_HANDLER_PKG_PATTERN = re.compile(_HANDLER_PATTERN + r'\.zip$', re.IGNORECASE)
_DEFAULT_EXT_TIMEOUT_MINUTES = 90

_VALID_HANDLER_STATUS = ['Ready', 'NotReady', "Installing", "Unresponsive"]

HANDLER_NAME_PATTERN = re.compile(_HANDLER_NAME_PATTERN, re.IGNORECASE)
HANDLER_COMPLETE_NAME_PATTERN = re.compile(_HANDLER_PATTERN + r'$', re.IGNORECASE)
HANDLER_PKG_EXT = ".zip"

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

# This is the default sequence number we use when there are no settings available for Handlers
_DEFAULT_SEQ_NO = "0"

# For extension disallowed errors (e.g. blocked by policy, extensions disabled), this mapping is used to generate
# user-friendly error messages and determine the appropriate terminal error code based on the blocked operation.
# Format: {<ExtensionRequestedState>: (<str>, <ExtensionErrorCodes>)}
# - The first element of the tuple is a user-friendly operation name included in error messages.
# - The second element of the tuple is the CRP terminal error code for the operation.
_EXT_DISALLOWED_ERROR_MAP = \
    {
        ExtensionRequestedState.Enabled: ('run', ExtensionErrorCodes.PluginEnableProcessingFailed),
        # TODO: CRP does not currently have a terminal error code for uninstall. Once this code is added, use
        #       it instead of PluginDisableProcessingFailed below.
        #
        # Note: currently, when uninstall is requested for an extension, CRP polls until the agent does not
        #       report status for that extension, or until timeout is reached. In the case of an extension disallowed
        #       error, agent reports failed status on behalf of the extension, which will cause CRP to poll for the full
        #       timeout, instead of failing fast.
        ExtensionRequestedState.Uninstall: ('uninstall', ExtensionErrorCodes.PluginDisableProcessingFailed),
        # "Disable" is an internal operation, users are unaware of it. We surface the term "uninstall" instead.
        ExtensionRequestedState.Disabled: ('uninstall', ExtensionErrorCodes.PluginDisableProcessingFailed),
    }


class ExtHandlerStatusValue(object):
    """
    Statuses for Extension Handlers
    """
    ready = "Ready"
    not_ready = "NotReady"


class ExtensionStatusValue(object):
    """
    Statuses for Extensions
    """
    transitioning = "transitioning"
    warning = "warning"
    error = "error"
    success = "success"
    STRINGS = ['transitioning', 'warning', 'error', 'success']


_EXTENSION_TERMINAL_STATUSES = [ExtensionStatusValue.error, ExtensionStatusValue.success]


class ExtCommandEnvVariable(object):
    Prefix = "AZURE_GUEST_AGENT"
    DisableReturnCode = "{0}_DISABLE_CMD_EXIT_CODE".format(Prefix)
    DisableReturnCodeMultipleExtensions = "{0}_DISABLE_CMD_EXIT_CODES_MULTIPLE_EXTENSIONS".format(Prefix)
    UninstallReturnCode = "{0}_UNINSTALL_CMD_EXIT_CODE".format(Prefix)
    ExtensionPath = "{0}_EXTENSION_PATH".format(Prefix)
    ExtensionVersion = "{0}_EXTENSION_VERSION".format(Prefix)
    ExtensionSeqNumber = "ConfigSequenceNumber"  # At par with Windows Guest Agent
    ExtensionName = "ConfigExtensionName"
    UpdatingFromVersion = "{0}_UPDATING_FROM_VERSION".format(Prefix)
    WireProtocolAddress = "{0}_WIRE_PROTOCOL_ADDRESS".format(Prefix)
    ExtensionSupportedFeatures = "{0}_EXTENSION_SUPPORTED_FEATURES".format(Prefix)


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
    validate_in_range(substatus['status'], ExtensionStatusValue.STRINGS, 'substatus/status')
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
    if status not in ExtensionStatusValue.STRINGS:
        status = ExtensionStatusValue.error

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
            for file in ("State", "Status"):  # pylint: disable=redefined-builtin
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
    FailedUpgrade = "FailedUpgrade"


class GoalStateStatus(object):
    """
    This is an Enum to define the State of the GoalState as a whole. This is reported as part of the
    'vmArtifactsAggregateStatus.goalStateAggregateStatus' in the status blob.
    Note: not to be confused with the State of the ExtHandler which reported as part of 'handlerAggregateStatus'
    """
    Success = "Success"
    Failed = "Failed"

    # The following field is not used now but would be needed once Status reporting is moved to a separate thread.
    Initialize = "Initialize"
    Transitioning = "Transitioning"


def get_exthandlers_handler(protocol):
    return ExtHandlersHandler(protocol)


def list_agent_lib_directory(skip_agent_package=True, ignore_names=None):
    lib_dir = conf.get_lib_dir()
    for name in os.listdir(lib_dir):
        path = os.path.join(lib_dir, name)

        if ignore_names is not None and any(ignore_names) and name in ignore_names:
            continue

        if skip_agent_package and (version.is_agent_package(path) or version.is_agent_path(path)):
            continue

        yield name, path


class ExtHandlersHandler(object):
    def __init__(self, protocol):
        self.protocol = protocol
        self.ext_handlers = None

        # Policy engine is initialized to a default "allow all" policy at agent start. This initialization should not raise errors.
        # The policy is updated on a per-goal state basis; the actual policy file is read later during extension processing.
        #
        # Note: the policy engine is a member of this class so it can be accessed for each operation. Disallowed extensions
        # should be blocked on a per-operation level, so certain operations can proceed when no extension code would be run.
        # For example, uninstall should be permitted on an extension that was never properly installed.
        self._policy_engine = ExtensionPolicyEngine()

        # Maintain a list of extension handler objects that are disallowed (e.g. blocked by policy, extensions disabled, etc.).
        # Extension status, if it exists, is always reported for the extensions in this list. List is reset for each goal state.
        self._disallowed_ext_handlers = []

        # The GoalState Aggregate status needs to report the last status of the GoalState. Since we only process
        # extensions on goal state change, we need to maintain its state.
        # Setting the status to None here. This would be overridden as soon as the first GoalState is processed
        self.__gs_aggregate_status = None
        # CRP Activity ID for the goal state that is being processed. Initialized once we start processing the goal state.
        self._gs_activity_id = '00000000-0000-0000-0000-000000000000'

        self.report_status_error_state = ErrorState()

    def __last_gs_unsupported(self):

        # Return if the last GoalState was unsupported
        return self.__gs_aggregate_status is not None and \
               self.__gs_aggregate_status.status == GoalStateStatus.Failed and \
               self.__gs_aggregate_status.code == GoalStateAggregateStatusCodes.GoalStateUnsupportedRequiredFeatures

    def run(self):
        try:
            gs = self.protocol.get_goal_state()
            egs = gs.extensions_goal_state
            self._gs_activity_id = egs.activity_id


            # self.ext_handlers needs to be initialized before returning, since status reporting depends on it; also
            # we make a deep copy of the extensions, since changes are made to self.ext_handlers while processing the extensions
            self.ext_handlers = copy.deepcopy(egs.extensions)

            if self._extensions_on_hold():
                return

            utc_start = datetime.datetime.now(UTC)
            error = None
            message = "ProcessExtensionsGoalState started [{0} channel: {1} source: {2} activity: {3} correlation {4} created: {5}]".format(
                egs.id, egs.channel, egs.source, egs.activity_id, egs.correlation_id, egs.created_on_timestamp)
            logger.info('')
            logger.info(message)
            add_event(op=WALAEventOperation.ExtensionProcessing, message=message)

            try:
                self.__process_and_handle_extensions(egs.svd_sequence_number, egs.id)
                self._cleanup_outdated_handlers()
            except Exception as e:
                error = u"Error processing extensions:{0}".format(textutil.format_exception(e))
            finally:
                duration = elapsed_milliseconds(utc_start)
                if error is None:
                    message = 'ProcessExtensionsGoalState completed [{0} {1} ms]\n'.format(egs.id, duration)
                    logger.info(message)
                else:
                    message = 'ProcessExtensionsGoalState failed [{0} {1} ms]\n{2}'.format(egs.id, duration, error)
                    logger.error(message)
                add_event(op=WALAEventOperation.ExtensionProcessing, is_success=(error is None), message=message, log_event=False, duration=duration)

        except Exception as error:
            msg = u"ProcessExtensionsInGoalState - Exception processing extension handlers:{0}".format(textutil.format_exception(error))
            logger.error(msg)
            add_event(op=WALAEventOperation.ExtensionProcessing, is_success=False, message=msg, log_event=False)

    def __get_unsupported_features(self):
        required_features = self.protocol.get_goal_state().extensions_goal_state.required_features
        supported_features = get_agent_supported_features_list_for_crp()
        return [feature for feature in required_features if feature not in supported_features]

    def __process_and_handle_extensions(self, svd_sequence_number, goal_state_id):
        try:
            # Verify we satisfy all required features, if any. If not, report failure here itself, no need to process anything further.
            unsupported_features = self.__get_unsupported_features()
            if any(unsupported_features):
                msg = "Failing GS {0} as Unsupported features found: {1}".format(goal_state_id, ', '.join(unsupported_features))
                logger.warn(msg)
                self.__gs_aggregate_status = GoalStateAggregateStatus(status=GoalStateStatus.Failed, seq_no=svd_sequence_number,
                                                                      code=GoalStateAggregateStatusCodes.GoalStateUnsupportedRequiredFeatures,
                                                                      message=msg)
                add_event(op=WALAEventOperation.GoalStateUnsupportedFeatures,
                          is_success=False,
                          message=msg,
                          log_event=False)
            else:
                self.handle_ext_handlers(goal_state_id)
                self.__gs_aggregate_status = GoalStateAggregateStatus(status=GoalStateStatus.Success, seq_no=svd_sequence_number,
                                                                      code=GoalStateAggregateStatusCodes.Success,
                                                                      message="GoalState executed successfully")
        except Exception as error:
            msg = "Unexpected error when processing goal state:{0}".format(textutil.format_exception(error))
            self.__gs_aggregate_status = GoalStateAggregateStatus(status=GoalStateStatus.Failed, seq_no=svd_sequence_number,
                                                                  code=GoalStateAggregateStatusCodes.GoalStateUnknownFailure,
                                                                  message=msg)
            logger.warn(msg)
            add_event(op=WALAEventOperation.ExtensionProcessing,
                      is_success=False,
                      message=msg,
                      log_event=False)

    @staticmethod
    def get_ext_handler_instance_from_path(name, path, protocol, skip_handlers=None):
        if not os.path.isdir(path) or re.match(HANDLER_NAME_PATTERN, name) is None:
            return None
        separator = name.rfind('-')
        handler_name = name[0:separator]
        if skip_handlers is not None and handler_name in skip_handlers:
            # Handler in skip_handlers list, not parsing it
            return None

        eh = Extension(name=handler_name)
        eh.version = str(FlexibleVersion(name[separator + 1:]))

        return ExtHandlerInstance(eh, protocol)

    def _cleanup_outdated_handlers(self):
        # Skip cleanup if the previous GS was Unsupported
        if self.__last_gs_unsupported():
            return

        handlers = []
        pkgs = []
        ext_handlers_in_gs = [ext_handler.name for ext_handler in self.ext_handlers]

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
            except OSError as e:
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
                except OSError as e:
                    logger.warn("Failed to remove extension package {0}: {1}".format(pkg, e.strerror))

    def _extensions_on_hold(self):
        if conf.get_enable_overprovisioning():
            if self.protocol.get_goal_state().extensions_goal_state.on_hold:
                msg = "Extension handling is on hold"
                logger.info(msg)
                add_event(op=WALAEventOperation.ExtensionProcessing, message=msg)
                return True

        return False

    @staticmethod
    def __get_dependency_level(tup):
        (extension, handler) = tup
        if extension is not None:
            return extension.dependency_level_sort_key(handler.state)
        return handler.dependency_level_sort_key()

    def __get_sorted_extensions_for_processing(self):
        all_extensions = []
        for handler in self.ext_handlers:
            if any(handler.settings):
                all_extensions.extend([(ext, handler) for ext in handler.settings])
            else:
                # We need to process the Handler even if no settings specified from CRP (legacy behavior)
                logger.info("No extension/run-time settings settings found for {0}".format(handler.name))
                all_extensions.append((None, handler))

        all_extensions.sort(key=self.__get_dependency_level)

        return all_extensions

    def handle_ext_handlers(self, goal_state_id):
        if not self.ext_handlers:
            logger.info("No extension handlers found, not processing anything.")
            return

        wait_until = datetime.datetime.now(UTC) + datetime.timedelta(minutes=_DEFAULT_EXT_TIMEOUT_MINUTES)

        all_extensions = self.__get_sorted_extensions_for_processing()
        # Since all_extensions are sorted based on sort_key, the last element would be the maximum based on the sort_key
        max_dep_level = self.__get_dependency_level(all_extensions[-1]) if any(all_extensions) else 0

        depends_on_err_msg = None
        extensions_enabled = conf.get_extensions_enabled()

        # Read policy file and update policy in engine. If an error is thrown during policy update, we block all extensions
        # and report the error via handler status for each extension.
        policy_error = None
        try:
            self._policy_engine.update_policy(self.protocol.get_goal_state().history)
        except Exception as ex:
            policy_error = ex

        for extension, ext_handler in all_extensions:

            handler_i = ExtHandlerInstance(ext_handler, self.protocol, extension=extension)

            # Get terminal error code to use if extensions are disabled or a policy error occurred.
            _, error_code = _EXT_DISALLOWED_ERROR_MAP.get(ext_handler.state)

            # In case of extensions disabled, we skip processing extensions. But CRP is still waiting for some status
            # back for the skipped extensions. In order to propagate the status back to CRP, we will report status back
            # here with an error message.
            if not extensions_enabled:
                ext_full_name = handler_i.get_extension_full_name(extension)
                agent_conf_file_path = get_osutil().get_agent_conf_file_path()
                msg = "Extension '{0}' will not be processed since extension processing is disabled. To enable extension " \
                      "processing, set Extensions.Enabled=y in '{1}'".format(ext_full_name, agent_conf_file_path)
                self.__handle_ext_disallowed_error(handler_i, error_code, report_op=WALAEventOperation.ExtensionProcessing,
                                                   message=msg, extension=extension)
                continue

            # If an error was thrown during policy update, skip further processing of the extension if user has enabled policy enforcement.
            # CRP is still waiting for status, so we report error status here.
            if policy_error is not None and self._policy_engine.policy_enforcement_enabled:
                msg = "Extension will not be processed due to an error verifying extension policy: {0}".format(ustr(policy_error))
                self.__handle_ext_disallowed_error(ext_handler_i=handler_i, error_code=error_code,
                                                   report_op=WALAEventOperation.ExtensionPolicy, message=msg,
                                                   extension=extension)
                continue

            # In case of depends-on errors, we skip processing extensions if there was an error processing dependent extensions.
            # But CRP is still waiting for some status back for the skipped extensions. In order to propagate the status back to CRP,
            # we will report status back here with the relevant error message for each of the dependent extension.
            if depends_on_err_msg is not None:

                # For MC extensions, report the HandlerStatus as is and create a new placeholder per extension if doesnt exist
                if handler_i.should_perform_multi_config_op(extension):
                    # Ensure some handler status exists for the Handler, if not, set it here
                    if handler_i.get_handler_status() is None:
                        handler_i.set_handler_status(message=depends_on_err_msg, code=-1)

                    handler_i.create_status_file(extension, status=ExtensionStatusValue.error, code=-1,
                                                 operation=WALAEventOperation.ExtensionProcessing,
                                                 message=depends_on_err_msg, overwrite=False)

                # For SC extensions, overwrite the HandlerStatus with the relevant message
                else:
                    handler_i.set_handler_status(message=depends_on_err_msg, code=-1)

                continue

            # Process the extension and get if it was successfully executed or not.
            extension_success = self.handle_ext_handler(handler_i, extension, goal_state_id)

            dep_level = self.__get_dependency_level((extension, ext_handler))
            if 0 <= dep_level < max_dep_level:
                extension_full_name = handler_i.get_extension_full_name(extension)
                try:
                    # Do no wait for extension status if the handler failed
                    if not extension_success:
                        raise Exception("Skipping processing of extensions since execution of dependent extension {0} failed".format(
                                extension_full_name))

                    # Wait for the extension installation until it is handled.
                    # This is done for the install and enable. Not for the uninstallation.
                    # If handled successfully, proceed with the current handler.
                    # Otherwise, skip the rest of the extension installation.
                    self.wait_for_handler_completion(handler_i, wait_until, extension=extension)

                except Exception as error:
                    logger.warn(
                        "Dependent extension {0} failed or timed out, will skip processing the rest of the extensions".format(
                            extension_full_name))
                    depends_on_err_msg = ustr(error)
                    add_event(name=extension_full_name,
                              version=handler_i.ext_handler.version,
                              op=WALAEventOperation.ExtensionProcessing,
                              is_success=False,
                              message=depends_on_err_msg)

    @staticmethod
    def wait_for_handler_completion(handler_i, wait_until, extension=None):
        """
        Check the status of the extension being handled. Wait until it has a terminal state or times out.
        :raises: Exception if it is not handled successfully.
        """
        extension_name = handler_i.get_extension_full_name(extension)

        # If the handler had no settings, we should not wait at all for handler to report status.
        if extension is None:
            logger.info("No settings found for {0}, not waiting for it's status".format(extension_name))
            return

        try:
            ext_completed, status = False, None

            # Keep polling for the extension status until it succeeds or times out
            while datetime.datetime.now(UTC) <= wait_until:
                ext_completed, status = handler_i.is_ext_handling_complete(extension)
                if ext_completed:
                    break
                time.sleep(5)

        except Exception as e:
            msg = "Failed to wait for Handler completion due to unknown error. Marking the dependent extension as failed: {0}, {1}".format(
                extension_name, textutil.format_exception(e))
            raise Exception(msg)

        # In case of timeout or terminal error state, we log it and raise
        # Incase extension reported status at the last sec, we should prioritize reporting status over timeout
        if not ext_completed and datetime.datetime.now(UTC) > wait_until:
            msg = "Dependent Extension {0} did not reach a terminal state within the allowed timeout. Last status was {1}".format(
                extension_name, status)
            raise Exception(msg)

        if status != ExtensionStatusValue.success:
            msg = "Dependent Extension {0} did not succeed. Status was {1}".format(extension_name, status)
            raise Exception(msg)

    def handle_ext_handler(self, ext_handler_i, extension, goal_state_id):
        """
        Execute the requested command for the handler and return if success
        :param ext_handler_i: The ExtHandlerInstance object to execute the command on
        :param extension: The extension settings on which to run the command on
        :param goal_state_id: ID of the current GoalState
        :return: True if the operation was successful, False if not
        """

        try:
            # Ensure the extension config was valid
            if ext_handler_i.ext_handler.is_invalid_setting:
                raise ExtensionsGoalStateError(ext_handler_i.ext_handler.invalid_setting_reason)

            handler_state = ext_handler_i.ext_handler.state

            # The Guest Agent currently only supports 1 installed version per extension on the VM.
            # If the extension version is unregistered and the customers wants to uninstall the extension,
            # we should let it go through even if the installed version doesnt exist in Handler manifest (PIR) anymore.
            # If target state is enabled and version not found in manifest, do not process the extension.
            if ext_handler_i.decide_version(target_state=handler_state, extension=extension, gs_activity_id=self._gs_activity_id) is None and handler_state == ExtensionRequestedState.Enabled:
                handler_version = ext_handler_i.ext_handler.version
                name = ext_handler_i.ext_handler.name
                err_msg = "Unable to find version {0} in manifest for extension {1}".format(handler_version, name)
                ext_handler_i.set_operation(WALAEventOperation.Download)
                raise ExtensionError(msg=err_msg)

            # Handle everything on an extension level rather than Handler level
            ext_handler_i.logger.info("Target handler state: {0} [{1}]", handler_state, goal_state_id)
            if handler_state == ExtensionRequestedState.Enabled:
                self.handle_enable(ext_handler_i, extension)
            elif handler_state == ExtensionRequestedState.Disabled:
                # The "disabled" state is now deprecated. Send telemetry if it is still being used on any VMs
                event.info(WALAEventOperation.RequestedStateDisabled, 'Goal State is requesting "disabled" state on {0} [Activity ID: {1}]',  ext_handler_i.ext_handler.name, self._gs_activity_id)
                self.handle_disable(ext_handler_i, extension)
            elif handler_state == ExtensionRequestedState.Uninstall:
                self.handle_uninstall(ext_handler_i, extension=extension)
            else:
                message = u"Unknown ext handler state:{0}".format(handler_state)
                raise ExtensionError(message)

            return True
        except MultiConfigExtensionEnableError as error:
            ext_name = ext_handler_i.get_extension_full_name(extension)
            err_msg = "Error processing MultiConfig extension {0}: {1}".format(ext_name, ustr(error))
            # This error is only thrown for enable operation on MultiConfig extension.
            # Since these are maintained by the extensions, the expectation here is that they would update their status files appropriately with their errors.
            # The extensions should already have a placeholder status file, but incase they dont, setting one here to fail fast.
            ext_handler_i.create_status_file(extension, status=ExtensionStatusValue.error, code=error.code,
                                             operation=ext_handler_i.operation, message=err_msg, overwrite=False)
            add_event(name=ext_name, version=ext_handler_i.ext_handler.version, op=ext_handler_i.operation,
                      is_success=False, log_event=True, message=err_msg)
        except ExtensionsGoalStateError as error:
            # Catch and report Invalid ExtensionConfig errors here to fail fast rather than timing out after 90 min
            err_msg = "Ran into config errors: {0}. \nPlease retry again as another operation with updated settings".format(
                ustr(error))
            self.__handle_and_report_ext_handler_errors(ext_handler_i, error,
                                                        report_op=WALAEventOperation.InvalidExtensionConfig,
                                                        message=err_msg, extension=extension)
        except ExtensionUpdateError as error:
            # Not reporting the error as it has already been reported from the old version
            self.__handle_and_report_ext_handler_errors(ext_handler_i, error, ext_handler_i.operation, ustr(error),
                                                        report=False, extension=extension)
        except ExtensionDownloadError as error:
            msg = "Failed to download artifacts: {0}".format(ustr(error))
            self.__handle_and_report_ext_handler_errors(ext_handler_i, error, report_op=WALAEventOperation.Download,
                                                        message=msg, extension=extension)
        except ExtensionDisallowedError:
            operation, error_code = _EXT_DISALLOWED_ERROR_MAP.get(ext_handler_i.ext_handler.state)
            msg = (
                "Extension will not be processed: failed to {0} extension '{1}' because it is not specified as an allowed extension. "
                "To {0}, add the extension to the list of allowed extensions in the policy file ('{2}')."
            ).format(operation, ext_handler_i.ext_handler.name, conf.get_policy_file_path())
            self.__handle_ext_disallowed_error(ext_handler_i, error_code, report_op=WALAEventOperation.ExtensionPolicy, message=msg,
                                               extension=extension)
        except ExtensionSignaturePolicyError:
            operation, error_code = _EXT_DISALLOWED_ERROR_MAP.get(ext_handler_i.ext_handler.state)
            msg = (
                "Extension will not be processed: failed to {0} extension '{1}' because policy specifies that extension must be signed, "
                "but extension package signature could not be found. To {0}, set 'signatureRequired' to false in the policy file ('{2}')."
            ).format(operation, ext_handler_i.ext_handler.name, conf.get_policy_file_path())
            self.__handle_ext_disallowed_error(ext_handler_i, error_code, report_op=WALAEventOperation.ExtensionSignaturePolicy, message=msg,
                                               extension=extension)
        except PackageValidationError as error:
            code = ExtensionErrorCodes.PluginInstallProcessingFailed   # Signature validation is only done during extension install
            self.__handle_ext_disallowed_error(ext_handler_i, code, report_op=error.operation,
                                               message=ustr(error), extension=extension, duration=error.duration)
        except ExtensionError as error:
            self.__handle_and_report_ext_handler_errors(ext_handler_i, error, ext_handler_i.operation, ustr(error),
                                                        extension=extension)
        except Exception as error:
            error.code = -1
            self.__handle_and_report_ext_handler_errors(ext_handler_i, error, ext_handler_i.operation, ustr(error),
                                                        extension=extension)

        return False

    @staticmethod
    def __handle_and_report_ext_handler_errors(ext_handler_i, error, report_op, message, report=True, extension=None):
        # This function is only called for Handler level errors, we capture MultiConfig errors separately,
        #  so report only HandlerStatus here.
        ext_handler_i.set_handler_status(message=message, code=error.code)

        # If the handler supports multi-config, create a status file with failed status if no status file exists.
        # This is for correctly reporting errors back to CRP for failed Handler level operations for MultiConfig extensions.
        # In case of Handler failures, we will retry each time for each extension, so we need to create a status
        # file with failure since the extensions wont be called where they can create their status files.
        # This way we guarantee reporting back to CRP
        if ext_handler_i.should_perform_multi_config_op(extension):
            ext_handler_i.create_status_file(extension, status=ExtensionStatusValue.error, code=error.code,
                                             operation=report_op, message=message, overwrite=False)

        if report:
            name = ext_handler_i.get_extension_full_name(extension)
            handler_version = ext_handler_i.ext_handler.version
            add_event(name=name, version=handler_version, op=report_op, is_success=False, log_event=True,
                      message=message)

    def __handle_ext_disallowed_error(self, ext_handler_i, error_code, report_op, message, extension, duration=0):
        #
        # Handle and report errors for disallowed extensions (e.g. extensions blocked by policy or disabled via config).
        #
        # TODO: __handle_and_report_ext_handler_errors() is also used to report extension errors, but it does not create
        #       a status file for single-config extensions (see below as to why this is important). This function,
        #       __handle_ext_disallowed_error, implements what we believe is the correct behavior, but at this point we
        #       use it only for disallowed extensions scenarios. In a future release, consider merging the two functions
        #       after assessing any impact.
        #
        # Note: When CRP polls for extension status, it first looks at handler status and then looks for any extension
        #       status. If extension status is present, CRP uses it instead of the handler status, ensuring that the
        #       sequence number for the extension settings match the sequence number in the reported status. CRP polls
        #       asynchronously to the Agent and, on a new goal state, it can check the status blob before the Agent has
        #       reported status for that goal state, effectively checking the status of the previous goal state. This is
        #       not an issue when the extension reports status at the extension level, since CRP wil wait for the status
        #       for the correct sequence number. However, when the extension reports status *only* at the handler level
        #       (e.g if the extension has no settings, during install errors, if extension is disallowed, etc.) CRP can
        #       end up picking up a stale status. There is not a good solution for extensions with no settings, and CRP
        #       can report an error from a previous goal state. For install errors of extensions with settings, though,
        #       we work around this issue by reporting the error *both* at the handler level and at the extension level
        #       (although reporting at the handler level *should* be sufficient). By reporting at the extension level,
        #       CRP will enforce a match on the sequence number for the settings, and skip stale status blobs.

        # Keep a list of disallowed extensions so that report_ext_handler_status() can report status for them.
        self._disallowed_ext_handlers.append(ext_handler_i.ext_handler)

        ext_handler_i.set_handler_status(status=ExtHandlerStatusValue.not_ready, message=message, code=error_code)

        # Only report extension status for install errors of extensions with settings. Disable/uninstall errors are
        # reported at the handler status level only.
        if extension is not None and ext_handler_i.ext_handler.state == ExtensionRequestedState.Enabled:
            # Overwrite any existing status file to reflect the failure accurately.
            ext_handler_i.create_status_file(extension, status=ExtensionStatusValue.error, code=error_code,
                                             operation=ext_handler_i.operation, message=message, overwrite=True)

        name = ext_handler_i.get_extension_full_name(extension)
        handler_version = ext_handler_i.ext_handler.version
        add_event(name=name, version=handler_version, op=report_op, is_success=False, log_event=True,
                  message=message, duration=duration)

    def handle_enable(self, ext_handler_i, extension):
        """
             1- Ensure the handler is installed
             2- Check if extension is enabled or disabled and then process accordingly

        Before running any extension code, check extension policy. If extension is disallowed by policy,
        a PolicyError will be raised and enable will be blocked.
        """
        uninstall_exit_code = None
        old_ext_handler_i = ext_handler_i.get_installed_ext_handler()

        current_handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("[Enable] current handler state is: {0}", current_handler_state.lower())
        # We go through the entire process of downloading and initializing the extension if it's either a fresh
        # extension or if it's a retry of a previously failed upgrade.
        if current_handler_state == ExtHandlerState.NotInstalled or current_handler_state == ExtHandlerState.FailedUpgrade:

            # Check extension policy and raise error if disallowed (e.g., not in allowlist, unsigned when policy requires signature).
            extension_is_signed = ext_handler_i.ext_handler.encoded_signature != ""
            self._policy_engine.check_extension_policy(ext_handler_i.ext_handler.name, extension_is_signed)

            self.__setup_new_handler(ext_handler_i, extension, self.__should_ignore_signature_validation_errors(ext_handler_i))

            if old_ext_handler_i is None:
                ext_handler_i.install(extension=extension)
            elif ext_handler_i.version_ne(old_ext_handler_i):
                # This is a special case, we need to update the handler version here but to do that we need to also
                # disable each enabled extension of this handler.
                uninstall_exit_code = ExtHandlersHandler._update_extension_handler_and_return_if_failed(
                    old_ext_handler_i, ext_handler_i, extension)
        else:
            # Check extension policy and raise error if disallowed. Since the extension is not being re-downloaded, treat it
            # as signed if its signature was previously validated on download.
            extension_is_signed = ext_handler_i.signature_validated
            self._policy_engine.check_extension_policy(ext_handler_i.ext_handler.name, extension_is_signed)

            ext_handler_i.ensure_consistent_data_for_mc()
            ext_handler_i.update_settings(extension)

        self.__handle_extension(ext_handler_i, extension, uninstall_exit_code)

    @staticmethod
    def __setup_new_handler(ext_handler_i, extension, ignore_signature_validation_errors):
        ext_handler_i.set_handler_state(ExtHandlerState.NotInstalled)
        ext_handler_i.download(ignore_signature_validation_errors)
        ext_handler_i.initialize()
        ext_handler_i.update_settings(extension)

    @staticmethod
    def __handle_extension(ext_handler_i, extension, uninstall_exit_code):
        # Check if extension level settings provided for the handler, if not, call enable for the handler.
        # This is legacy behavior, we can have handlers with no settings.
        if extension is None:
            ext_handler_i.enable()
            return

        # MultiConfig: Handle extension level ops here
        ext_handler_i.logger.info("Requested extension state: {0}", extension.state)

        if extension.state == ExtensionState.Enabled:
            ext_handler_i.enable(extension, uninstall_exit_code=uninstall_exit_code)
        elif extension.state == ExtensionState.Disabled:
            # Only disable extension if the requested state == Disabled and current state is != Disabled
            if ext_handler_i.get_extension_state(extension) != ExtensionState.Disabled:
                # Extensions can only be disabled for Multi Config extensions. Disable operation for extension is
                # tantamount to uninstalling Handler so ignoring errors incase of Disable failure and deleting state.
                ext_handler_i.disable(extension, ignore_error=True)
            else:
                ext_handler_i.logger.info("Extension already disabled, not doing anything")
        else:
            raise ExtensionsGoalStateError(
                "Unknown requested state for Extension {0}: {1}".format(extension.name, extension.state))

    @staticmethod
    def _update_extension_handler_and_return_if_failed(old_ext_handler_i, ext_handler_i, extension=None):

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
            except ExtensionError as e:
                # Reporting the event with the old handler and raising a new ExtensionUpdateError to set the
                # handler status on the new version
                msg = "%s; ContinueOnUpdate: %s" % (ustr(e), continue_on_update_failure)
                old_ext_handler_i.report_event(message=msg, is_success=False)
                if not continue_on_update_failure:
                    # We need to populate correct error code here
                    # Without this, the superclass defaults to code -1, which may not accurately represent the error.
                    raise ExtensionUpdateError(msg, code=ExtensionErrorCodes.PluginUpdateProcessingFailed)

                exit_code = e.code
                if isinstance(e, ExtensionOperationError):
                    exit_code = e.exit_code  # pylint: disable=E1101

                logger.info("Continue on Update failure flag is set, proceeding with update")
            return exit_code

        disable_exit_codes = defaultdict(lambda: NOT_RUN)
        # We only want to disable the old handler if it is currently enabled; no other state makes sense.
        if old_ext_handler_i.get_handler_state() == ExtHandlerState.Enabled:

            # Corner case - If the old handler is a Single config Handler with no extensions at all,
            # we should just disable the handler
            if not old_ext_handler_i.supports_multi_config and not any(old_ext_handler_i.extensions):
                disable_exit_codes[
                    old_ext_handler_i.ext_handler.name] = execute_old_handler_command_and_return_if_succeeds(
                    func=partial(old_ext_handler_i.disable, extension=None))

            # Else we disable all enabled extensions of this handler
            # Note: If MC is supported this will disable only enabled_extensions else it will disable all extensions
            for old_ext in old_ext_handler_i.enabled_extensions:
                disable_exit_codes[old_ext.name] = execute_old_handler_command_and_return_if_succeeds(
                    func=partial(old_ext_handler_i.disable, extension=old_ext))

        ext_handler_i.copy_status_files(old_ext_handler_i)
        # Invoke the update method of the greater version, both on upgrades and downgrades
        if ext_handler_i.version_gt(old_ext_handler_i):
            ext_handler_i.update(
                updating_from_version=old_ext_handler_i.ext_handler.version,
                updating_to_version=ext_handler_i.ext_handler.version,
                extension=extension,
                disable_exit_codes=disable_exit_codes)
        else:
            old_ext_handler_i.update(
                updating_from_version=old_ext_handler_i.ext_handler.version,
                updating_to_version=ext_handler_i.ext_handler.version,
                extension=extension,
                disable_exit_codes=disable_exit_codes)
        uninstall_exit_code = execute_old_handler_command_and_return_if_succeeds(
            func=partial(old_ext_handler_i.uninstall, extension=extension))
        old_ext_handler_i.remove_ext_handler()
        ext_handler_i.update_with_install(uninstall_exit_code=uninstall_exit_code, extension=extension)
        return uninstall_exit_code

    def handle_disable(self, ext_handler_i, extension=None):
        """
            Disable is a legacy behavior, CRP doesn't support it, its only for XML based extensions.
            In case we get a disable request, just disable that extension.
        """
        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("[Disable] current handler state is: {0}", handler_state.lower())
        if handler_state == ExtHandlerState.Enabled:
            ext_handler_i.disable(extension)

    def handle_uninstall(self, ext_handler_i, extension):
        """
        To Uninstall the handler, first ensure all extensions are disabled
            1- Disable all enabled extensions first if Handler is Enabled and then Disable the handler
                (disabled extensions wont have any extensions dependent on them so we can just go
                ahead and remove all of them at once if HandlerState==Uninstall.
                CRP will only set the HandlerState to Uninstall if all its extensions are set to be disabled)
            2- Finally uninstall the handler

        Before running any extension code, check extension policy. If extension is disallowed by policy, a PolicyError will be raised and uninstall will be blocked.
        Note: if the extension was never installed, uninstall is allowed even for disallowed extensions because no extension code will be executed.
        """
        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("[Uninstall] current handler state is: {0}", handler_state.lower())
        if handler_state != ExtHandlerState.NotInstalled:
            # If extension is installed, check policy and raise an error if the extension is disallowed (e.g., not in allowlist, signature not previously validated when required).
            # Uninstall extension goal states do not include encoded signature, so if the extension signature was previously validated, we treat it as signed.
            extension_is_signed = ext_handler_i.signature_validated
            self._policy_engine.check_extension_policy(ext_handler_i.ext_handler.name, extension_is_signed)

            if handler_state == ExtHandlerState.Enabled:

                # Corner case - Single config Handler with no extensions at all
                # If there are no extension settings for Handler, we should just disable the handler
                if not ext_handler_i.supports_multi_config and not any(ext_handler_i.extensions):
                    ext_handler_i.disable()

                # If Handler is Enabled, there should be atleast 1 enabled extension for the handler
                # Note: If MC is supported this will disable only enabled_extensions else it will disable all extensions
                for enabled_ext in ext_handler_i.enabled_extensions:
                    ext_handler_i.disable(enabled_ext)

            # Try uninstalling the extension and swallow any exceptions in case of failures after logging them
            try:
                ext_handler_i.uninstall(extension=extension)
            except ExtensionError as e:
                ext_handler_i.report_event(message=ustr(e), is_success=False)

        ext_handler_i.remove_ext_handler()

    def __get_handlers_on_file_system(self, goal_state_changed):
        handlers_to_report = []
        # Ignoring the `history` and `events` directories as they're not handlers and are agent-generated
        for item, path in list_agent_lib_directory(skip_agent_package=True,
                                                   ignore_names=[EVENTS_DIRECTORY, ARCHIVE_DIRECTORY_NAME]):
            try:
                handler_instance = ExtHandlersHandler.get_ext_handler_instance_from_path(name=item,
                                                                                         path=path,
                                                                                         protocol=self.protocol)
                if handler_instance is not None:
                    ext_handler = handler_instance.ext_handler
                    # For each handler we need to add extensions to report their status.
                    # For Single Config, we just need to add one extension with name as Handler Name
                    # For Multi Config, walk the config directory and find all unique extension names
                    # and add them as extensions to the handler.
                    extensions_names = set()
                    # Settings for Multi Config are saved as <extName>.<seqNo>.settings.
                    # Use this pattern to determine if Handler supports Multi Config or not and add extensions
                    for settings_path in glob.iglob(os.path.join(handler_instance.get_conf_dir(), "*.*.settings")):
                        match = re.search("(?P<extname>\\w+)\\.\\d+\\.settings", settings_path)
                        if match is not None:
                            extensions_names.add(match.group("extname"))
                            ext_handler.supports_multi_config = True

                    # If nothing found with that pattern then its a Single Config, add an extension with Handler Name
                    if not any(extensions_names):
                        extensions_names.add(ext_handler.name)

                    for ext_name in extensions_names:
                        ext = ExtensionSettings(name=ext_name)
                        # Fetch the last modified sequence number
                        seq_no, _ = handler_instance.get_status_file_path(ext)
                        ext.sequenceNumber = seq_no
                        # Append extension to the list of extensions for the handler
                        ext_handler.settings.append(ext)

                    handlers_to_report.append(ext_handler)
            except Exception as error:
                # Log error once per goal state
                if goal_state_changed:
                    logger.warn("Can't fetch ExtHandler from path: {0}; Error: {1}".format(path, ustr(error)))

        return handlers_to_report

    def report_ext_handlers_status(self, goal_state_changed=False, vm_agent_update_status=None,
                                   vm_agent_supports_fast_track=False):
        """
        Go through handler_state dir, collect and report status.
        Returns the status it reported, or None if an error occurred.
        """
        try:
            vm_status = VMStatus(status="Ready", message="Guest Agent is running",
                                 gs_aggregate_status=self.__gs_aggregate_status,
                                 vm_agent_update_status=vm_agent_update_status)
            vm_status.vmAgent.set_supports_fast_track(vm_agent_supports_fast_track)
            handlers_to_report = []

            # In case of Unsupported error, report the status of the handlers in the VM
            if self.__last_gs_unsupported():
                handlers_to_report = self.__get_handlers_on_file_system(goal_state_changed)

            # If GoalState supported, report the status of extension handlers that were requested by the GoalState
            elif not self.__last_gs_unsupported() and self.ext_handlers is not None:
                handlers_to_report = self.ext_handlers

            for ext_handler in handlers_to_report:
                try:
                    self.report_ext_handler_status(vm_status, ext_handler, goal_state_changed)
                except ExtensionError as error:
                    add_event(op=WALAEventOperation.ExtensionProcessing, is_success=False, message=ustr(error))

            logger.verbose("Report vm agent status")
            try:
                self.protocol.report_vm_status(vm_status)
                logger.verbose("Completed vm agent status report successfully")
                self.report_status_error_state.reset()
            except ProtocolNotFoundError as error:
                self.report_status_error_state.incr()
                message = "Failed to report vm agent status: {0}".format(error)
                logger.verbose(message)
            except ProtocolError as error:
                self.report_status_error_state.incr()
                message = "Failed to report vm agent status: {0}".format(error)
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

            return vm_status

        except Exception as error:
            msg = u"Failed to report status: {0}".format(textutil.format_exception(error))
            logger.warn(msg)
            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.ReportStatus,
                      is_success=False,
                      message=msg)
            return None

    def report_ext_handler_status(self, vm_status, ext_handler, goal_state_changed):
        ext_handler_i = ExtHandlerInstance(ext_handler, self.protocol)

        handler_status = ext_handler_i.get_handler_status()

        # If nothing available, skip reporting
        if handler_status is None:
            # We should always have some handler status if requested state != Uninstall irrespective of single or
            # multi-config. If state is != Uninstall, report error
            if ext_handler.state != ExtensionRequestedState.Uninstall:
                msg = "No handler status found for {0}. Not reporting anything for it.".format(ext_handler.name)
                ext_handler_i.report_error_on_incarnation_change(goal_state_changed, log_msg=msg, event_msg=msg)
            return

        handler_state = ext_handler_i.get_handler_state()
        ext_handler_statuses = []
        ext_disallowed = ext_handler in self._disallowed_ext_handlers
        # For MultiConfig, we need to report status per extension even for Handler level failures.
        # If we have HandlerStatus for a MultiConfig handler and GS is requesting for it, we would report status per
        # extension even if HandlerState == NotInstalled (Sample scenario: ExtensionsGoalStateError, DecideVersionError, etc)
        # We also need to report extension status for an uninstalled handler if the extension is disallowed (due to
        # policy failure, extensions disabled, etc.) because CRP waits for extension runtime status before failing the operation.
        if handler_state != ExtHandlerState.NotInstalled or ext_handler.supports_multi_config or ext_disallowed:

            # Since we require reading the Manifest for reading the heartbeat, this would fail if HandlerManifest not found.
            # Only try to read heartbeat if HandlerState != NotInstalled.
            # If extension is disallowed, concatenate the heartbeat message to the existing handler status message, and
            # do not override handler error code or status with heartbeat.
            if handler_state != ExtHandlerState.NotInstalled:
                # Heartbeat is a handler level thing only, so we don't need to modify this
                try:
                    heartbeat = ext_handler_i.collect_heartbeat()
                    if heartbeat is not None:
                        if ext_disallowed:
                            pass  # The status already specifies that the extension is disallowed ('NotReady')
                        else:
                            handler_status.status = heartbeat.get('status')

                        if 'formattedMessage' in heartbeat:
                            heartbeat_message = parse_formatted_message(heartbeat.get('formattedMessage'))
                            if ext_disallowed:
                                # If extension is disallowed, the agent should set the handler status message on behalf of the
                                # extension, handler_status.message should not be None.
                                if handler_status.message is None:
                                    handler_status.message = "Extension was not executed, but it was previously enabled and reported the following heartbeat:\n{0}".format(heartbeat_message)
                                else:
                                    handler_status.message += " Extension was previously enabled and reported the following heartbeat:\n{0}".format(heartbeat_message)
                            else:
                                handler_status.message = heartbeat_message

                except ExtensionError as e:
                    ext_handler_i.set_handler_status(message=ustr(e), code=e.code)

            ext_handler_statuses = ext_handler_i.get_extension_handler_statuses(handler_status, goal_state_changed)

        # If not any extension status reported, report the Handler status
        if not any(ext_handler_statuses):
            ext_handler_statuses.append(handler_status)

        vm_status.vmAgent.extensionHandlers.extend(ext_handler_statuses)

    def __should_ignore_signature_validation_errors(self, ext_handler_i):
        """
        Determine whether to ignore signature validation errors.
        Signature validation errors are ignored only if:
            1. The configuration flag "Debug.IgnoreSignatureValidationError" is set to True, AND
            2. The policy does NOT require signature validation for this extension.
\
        TODO: After telemetry release, remove condition #2 so that signature validation errors will block the
        extension regardless of policy.
        """
        return conf.get_ignore_signature_validation_errors() and not self._policy_engine.should_enforce_signature_validation(ext_handler_i.ext_handler.name)


class ExtHandlerInstance(object):

    def __init__(self, ext_handler, protocol, execution_log_max_size=(10 * 1024 * 1024), extension=None):
        self.ext_handler = ext_handler
        self.protocol = protocol
        self.operation = None
        self.pkg = None
        self.pkg_file = None
        self.logger = None
        self.set_logger(extension=extension, execution_log_max_size=execution_log_max_size)
        self._signature_validated = self.__get_signature_validated()

    @property
    def signature_validated(self):
        return self._signature_validated

    @property
    def supports_multi_config(self):
        return self.ext_handler.supports_multi_config

    @property
    def extensions(self):
        return self.ext_handler.settings

    @property
    def enabled_extensions(self):
        """
        In case of Single config, just return all the extensions of the handler
        (expectation being that there'll only be a single extension per handler).
        We will not be maintaining extension level state for Single config Handlers
        """
        if self.supports_multi_config:
            return [ext for ext in self.extensions if self.get_extension_state(ext) == ExtensionState.Enabled]
        return self.extensions

    def get_extension_full_name(self, extension=None):
        """
        Get the full name of the extension <HandlerName>.<ExtensionName>.
        :param extension: The requested extension
        :return: <HandlerName> if MultiConfig not supported or extension == None, else <HandlerName>.<ExtensionName>
        """
        if self.should_perform_multi_config_op(extension):
            return "{0}.{1}".format(self.ext_handler.name, extension.name)

        return self.ext_handler.name

    def __set_command_execution_log(self, extension, execution_log_max_size):
        try:
            fileutil.mkdir(self.get_log_dir(), mode=0o755, reset_mode_and_owner=False)
        except IOError as e:
            self.logger.error(u"Failed to create extension log dir: {0}", e)
        else:
            log_file_name = "CommandExecution.log" if not self.should_perform_multi_config_op(
                extension) else "CommandExecution_{0}.log".format(extension.name)

            log_file = os.path.join(self.get_log_dir(), log_file_name)
            self.__truncate_file_head(log_file, execution_log_max_size, self.get_extension_full_name(extension))
            self.logger.add_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, log_file)

    @staticmethod
    def __truncate_file_head(filename, max_size, extension_name):
        try:
            if os.stat(filename).st_size <= max_size:
                return

            with open(filename, "rb") as existing_file:
                existing_file.seek(-1 * max_size, 2)
                _ = existing_file.readline()

                with open(filename + ".tmp", "wb") as tmp_file:
                    shutil.copyfileobj(existing_file, tmp_file)

            os.rename(filename + ".tmp", filename)

        except (IOError, OSError) as e:
            if is_file_not_found_error(e):
                # If CommandExecution.log does not exist, it's not noteworthy;
                # this just means that no extension with self.ext_handler.name is
                # installed.
                return

            logger.error(
                "Exception occurred while attempting to truncate {0} for extension {1}. Exception is: {2}",
                filename, extension_name, ustr(e))

            for f in (filename, filename + ".tmp"):
                try:
                    os.remove(f)
                except (IOError, OSError) as cleanup_exception:
                    if is_file_not_found_error(cleanup_exception):
                        logger.info("File '{0}' does not exist.", f)
                    else:
                        logger.warn("Exception occurred while attempting to remove file '{0}': {1}", f,
                                    cleanup_exception)

    def decide_version(self, target_state, extension, gs_activity_id):
        self.logger.verbose("Decide which version to use")
        try:
            manifest = self.protocol.get_goal_state().fetch_extension_manifest(self.ext_handler.name, self.ext_handler.manifest_uris)
            pkg_list = manifest.pkg_list
        except ProtocolError as e:
            raise ExtensionError("Failed to get ext handler pkgs", e)
        except ExtensionDownloadError:
            self.set_operation(WALAEventOperation.Download)
            raise

        # Determine the desired and installed versions
        requested_version = FlexibleVersion(str(self.ext_handler.version))
        installed_version_string = self.get_installed_version()
        installed_version = requested_version if installed_version_string is None else FlexibleVersion(installed_version_string)

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
            if installed_version is not None:
                self.ext_handler.version = str(installed_version)
                # In the case of uninstall, signature_validated should reflect the state of the extension version that is currently installed
                self._signature_validated = self.__get_signature_validated()
            else:
                self.ext_handler.version = None
        else:
            self.pkg = selected_pkg
            if self.pkg is not None:
                if self.ext_handler.version != str(selected_pkg.version):
                    # The Agent should not change the version requested by the Goal State. Send telemetry if this happens.
                    event.info(
                        WALAEventOperation.RequestedVersionMismatch,
                        'Goal State requesting {0} version {1}, but Agent overriding with version {2} [Activity ID: {3}]',  self.ext_handler.name, self.ext_handler.version, selected_pkg.version, gs_activity_id)
                self.ext_handler.version = str(selected_pkg.version)

        if self.pkg is not None:
            self.logger.verbose("Use version: {0}", self.pkg.version)

        # We reset the logger here incase the handler version changes
        if not requested_version.matches(FlexibleVersion(self.ext_handler.version)):
            self.set_logger(extension=extension)

        return self.pkg

    def set_logger(self, execution_log_max_size=(10 * 1024 * 1024), extension=None):
        prefix = "[{0}]".format(self.get_full_name(extension))
        self.logger = logger.Logger(logger.DEFAULT_LOGGER, prefix)
        self.__set_command_execution_log(extension, execution_log_max_size)

    def version_gt(self, other):
        self_version = self.ext_handler.version
        other_version = other.ext_handler.version
        return FlexibleVersion(self_version) > FlexibleVersion(other_version)

    def version_ne(self, other):
        self_version = self.ext_handler.version
        other_version = other.ext_handler.version
        return FlexibleVersion(self_version) != FlexibleVersion(other_version)

    def get_installed_ext_handler(self):
        latest_version = self.get_installed_version()
        if latest_version is None:
            return None

        installed_handler = copy.deepcopy(self.ext_handler)
        installed_handler.version = latest_version
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
                logger.verbose("Ignoring version of uninstalled or failed extension: {0}".format(path))
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
            logger.info("Migrating {0} to {1}.", old_ext_mrseq_file, new_ext_dir)
            shutil.copy2(old_ext_mrseq_file, new_ext_dir)
        else:
            logger.info("{0} does not exist, no migration is needed.", old_ext_mrseq_file)

        old_ext_status_dir = old_ext_handler_i.get_status_dir()
        new_ext_status_dir = self.get_status_dir()

        if os.path.isdir(old_ext_status_dir):
            for status_file in os.listdir(old_ext_status_dir):
                status_file = os.path.join(old_ext_status_dir, status_file)
                if os.path.isfile(status_file):
                    shutil.copy2(status_file, new_ext_status_dir)

    def set_operation(self, op):
        self.operation = op

    def report_event(self, name=None, message="", is_success=True, duration=0, log_event=True):
        ext_handler_version = self.ext_handler.version
        name = self.ext_handler.name if name is None else name
        add_event(name=name, version=ext_handler_version, message=message,
                  op=self.operation, is_success=is_success, duration=duration, log_event=log_event)

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

    def download(self, ignore_signature_validation_errors):
        """
        If extension is signed, validate extension package signature immediately after download, and validate handler
        manifest 'signingInfo' after package extraction. If both signature and handler manifest are successfully validated,
        save state file indicating this.

        If signature validation fails:
         - if 'ignore_signature_validation_errors' is false, download is blocked.
         - if 'ignore_signature_validation_errors' is true, the error is captured and reported via telemetry, but download and extraction proceed.
        """
        begin_utc = datetime.datetime.now(UTC)
        self.set_operation(WALAEventOperation.Download)

        if self.pkg is None or self.pkg.uris is None or len(self.pkg.uris) == 0:
            raise ExtensionDownloadError("No package uri found")

        package_file = os.path.join(conf.get_lib_dir(), self.get_extension_package_zipfile_name())

        should_validate_ext_signature = signature_validation_enabled() and self.ext_handler.encoded_signature != ""
        signature_validation_succeeded = False

        # Handle case where extension zip package already exists, but has not been extracted. If signature is present,
        # validate the package signature, extract the package, and then validate handler manifest.
        package_exists = False
        if os.path.exists(package_file):
            msg = "Using existing extension package: {0}".format(package_file)
            self.logger.info(msg)
            add_event(op=WALAEventOperation.Download, message=msg, name=self.ext_handler.name, version=self.ext_handler.version, is_success=True, log_event=False)

            # Validate package signature
            if should_validate_ext_signature:
                try:
                    validate_signature(package_file, self.ext_handler.encoded_signature, package_full_name=self.get_full_name())
                    signature_validation_succeeded = True
                except SignatureValidationError as ex:
                    # validate_signature() only raises SignatureValidationError.
                    if not ignore_signature_validation_errors:
                        cleanup_package_with_invalid_signature(package_file)
                        raise
                    report_validation_event(op=ex.operation, level=logger.LogLevel.WARNING, message=ustr(ex),
                                            name=self.ext_handler.name, version=self.ext_handler.version, duration=ex.duration)

            if self._unzip_extension_package(package_file, self.get_base_dir()):
                package_exists = True
            else:
                msg = "The existing extension package is invalid, will ignore it."
                self.logger.info(msg)
                add_event(op=WALAEventOperation.Download, message=msg, name=self.ext_handler.name, version=self.ext_handler.version, is_success=True, log_event=False)
                signature_validation_succeeded = False

        # Handle the case where the extension package does not exist. Download the zip package, validate the signature
        # if present, and extract the package. If package is signed, validate handler manifest.
        if not package_exists:
            is_fast_track_goal_state = self.protocol.get_goal_state().extensions_goal_state.source == GoalStateSource.FastTrack

            try:
                if signature_validation_enabled() and self.ext_handler.encoded_signature == "":
                    # Extension signature status is already reported in telemetry during goal state processing, so here,
                    # we log locally only for debugging purposes if extension is unsigned.
                    # Note: If policy requires signature, an error would have been raised earlier for an unsigned extension.
                    self.logger.info("No signature for extension '{0}' in goal state, skipping signature validation.".format(self.get_full_name()))

                # If signature should not be validated, pass an empty string as 'signature' to download_zip_package(),
                # which will skip validation when the signature parameter is empty.
                signature = self.ext_handler.encoded_signature if should_validate_ext_signature else ""
                self.protocol.client.download_zip_package(package_name=self.get_full_name(), uris=self.pkg.uris,
                                                          target_file=package_file, target_directory=self.get_base_dir(),
                                                          use_verify_header=is_fast_track_goal_state,
                                                          signature=signature, ignore_signature_validation_errors=ignore_signature_validation_errors)

                if should_validate_ext_signature:
                    # download_zip_package() performs signature validation internally. If no exception is raised, the signature was successfully validated.
                    # Mark this here so that we can save validation state later, if handler manifest validation also succeeds.
                    signature_validation_succeeded = True

            except SignatureValidationError as ex:
                # download_zip_package() will propagate a SignatureValidationError if validation fails. Re-raise if
                # validation errors should not be ignored, otherwise report the error and continue.
                if not ignore_signature_validation_errors:
                    raise   # Package has already been cleaned up
                report_validation_event(op=ex.operation, level=logger.LogLevel.WARNING, message=ustr(ex), name=self.ext_handler.name,
                                        version=self.ext_handler.version, duration=ex.duration)

            self.report_event(message="Download succeeded", duration=elapsed_milliseconds(begin_utc))

        # Validate 'signingInfo' - the publisher, type, and version specified in handler manifest 'signingInfo' should match the extension
        if should_validate_ext_signature:
            try:
                validate_handler_manifest_signing_info(self.load_manifest(), self.ext_handler)
                # If both manifest and signature were validated successfully, update self._signature_validated. This
                # attribute will be saved to the HandlerStatus file during status reporting.
                self._signature_validated = signature_validation_succeeded

            except ManifestValidationError as ex:
                # validate_handler_manifest_signing_info() raises only ManifestValidationError.
                if not ignore_signature_validation_errors:
                    raise
                report_validation_event(op=ex.operation, level=logger.LogLevel.WARNING, message=ustr(ex), name=self.ext_handler.name,
                                        version=self.ext_handler.version, duration=ex.duration)

        self.pkg_file = package_file

    def ensure_consistent_data_for_mc(self):
        # If CRP expects Handler to support MC, ensure the HandlerManifest also reflects that.
        # Even though the HandlerManifest.json is not expected to change once the extension is installed,
        # CRP can wrongfully request send a Multi-Config GoalState even if the Handler supports only Single Config.
        # Checking this only if HandlerState == Enable. In case of Uninstall, we dont care.
        if self.supports_multi_config and not self.load_manifest().supports_multiple_extensions():
            raise ExtensionsGoalStateError(
                "Handler {0} does not support MultiConfig but CRP expects it, failing due to inconsistent data".format(
                    self.ext_handler.name))

    def initialize(self):
        self.logger.info("Initializing extension {0}".format(self.get_full_name()))

        # Add user execute permission to all files under the base dir
        for file in fileutil.get_all_files(self.get_base_dir()):  # pylint: disable=redefined-builtin
            fileutil.chmod(file, os.stat(file).st_mode | stat.S_IXUSR)

        # Save HandlerManifest.json
        man_file = fileutil.search_file(self.get_base_dir(), 'HandlerManifest.json')

        if man_file is None:
            raise ExtensionDownloadError("HandlerManifest.json not found")

        try:
            man = fileutil.read_file(man_file, remove_bom=True)
            fileutil.write_file(self.get_manifest_file(), man)
        except IOError as e:
            fileutil.clean_ioerror(e, paths=[self.get_base_dir(), self.pkg_file])
            raise ExtensionDownloadError(u"Failed to save HandlerManifest.json", e)

        man = self.load_manifest()
        man.report_invalid_boolean_properties(ext_name=self.get_full_name())

        self.ensure_consistent_data_for_mc()

        # Create status and config dir
        try:
            status_dir = self.get_status_dir()
            fileutil.mkdir(status_dir, mode=0o700)

            conf_dir = self.get_conf_dir()
            fileutil.mkdir(conf_dir, mode=0o700)

            if get_supported_feature_by_name(SupportedFeatureNames.ExtensionTelemetryPipeline).is_supported:
                fileutil.mkdir(self.get_extension_events_dir(), mode=0o700)

        except IOError as e:
            fileutil.clean_ioerror(e, paths=[self.get_base_dir(), self.pkg_file])
            raise ExtensionDownloadError(u"Failed to initialize extension '{0}'".format(self.get_full_name()), e)

        # Save HandlerEnvironment.json
        self.create_handler_env()

        self.log_telemetry_if_ext_uses_resource_limits()
        self.set_extension_resource_limits()

    def set_extension_resource_limits(self):
        extension_name = self.get_full_name()
        # setup the resource limits for extension operations and it's services.
        man = self.load_manifest()
        resource_limits = man.get_resource_limits()

        CGroupConfigurator.get_instance().setup_extension_slice(
            extension_name=extension_name, cpu_quota=resource_limits.get_extension_slice_cpu_quota())
        CGroupConfigurator.get_instance().set_extension_services_cpu_memory_quota(resource_limits.get_service_list())

    def log_telemetry_if_ext_uses_resource_limits(self):
        extension_name = self.get_full_name()
        man = self.load_manifest()
        resource_limits = man.get_resource_limits()

        def _log(msg):
            event.info(WALAEventOperation.ExtensionResourceGovernance, msg)

        if resource_limits is None:
            return

        if resource_limits.get_extension_slice_cpu_quota() is not None or resource_limits.get_extension_slice_memory_quota() is not None:
            msg = "{0} is using resource governance to set limits".format(extension_name)
            _log(msg)
        if resource_limits.get_service_list() is not None and len(resource_limits.get_service_list()) > 0:
            msg = "{0} is using resource governance for its service list".format(extension_name)
            _log(msg)

    def create_status_file(self, extension, status, code, operation, message, overwrite):
        # Create status file for specified extension. If overwrite is true, overwrite any existing status file. If
        # false, create a status file only if it does not already exist.
        _, status_path = self.get_status_file_path(extension)
        if status_path is not None and (overwrite or not os.path.exists(status_path)):
            now = datetime.datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            status_contents = [
                {
                    "version": 1.0,
                    "timestampUTC": now,
                    "status": {
                        "name": self.get_extension_full_name(extension),
                        "operation": operation,
                        "status": status,
                        "code": code,
                        "formattedMessage": {
                            "lang": "en-US",
                            "message": redact_sas_token(message)
                        }
                    }
                }
            ]
            # Create status directory if not exists. This is needed in the case where the Handler fails before even
            # initializing the directories (ExtensionsGoalStateError, Version deleted from PIR error, etc)
            if not os.path.exists(os.path.dirname(status_path)):
                fileutil.mkdir(os.path.dirname(status_path), mode=0o700)
            self.logger.info("Creating a placeholder status file {0} with status: {1}".format(status_path, status))
            fileutil.write_file(status_path, json.dumps(status_contents))

    def enable(self, extension=None, uninstall_exit_code=None):
        try:
            self._enable_extension(extension, uninstall_exit_code)
        except ExtensionError as error:
            if self.should_perform_multi_config_op(extension):
                raise MultiConfigExtensionEnableError(error)
            raise
        # Even if a single extension is enabled for this handler, set the Handler state as Enabled
        self.set_handler_state(ExtHandlerState.Enabled)
        self.set_handler_status(status=ExtHandlerStatusValue.ready, message="Plugin enabled")

    def should_perform_multi_config_op(self, extension):
        return self.supports_multi_config and extension is not None

    def _enable_extension(self, extension, uninstall_exit_code):
        uninstall_exit_code = str(uninstall_exit_code) if uninstall_exit_code is not None else NOT_RUN

        env = {
            ExtCommandEnvVariable.UninstallReturnCode: uninstall_exit_code
        }
        # This check to call the setup if extension already installed and not called setup before
        self.set_extension_resource_limits()

        self.set_operation(WALAEventOperation.Enable)
        man = self.load_manifest()
        enable_cmd = man.get_enable_command()
        self.logger.info("Enable extension: [{0}]".format(enable_cmd))
        self.launch_command(enable_cmd, cmd_name="enable", timeout=300,
                            extension_error_code=ExtensionErrorCodes.PluginEnableProcessingFailed, env=env,
                            extension=extension)

        if self.should_perform_multi_config_op(extension):
            # Only save extension state if MC supported
            self.__set_extension_state(extension, ExtensionState.Enabled)

        # start tracking the extension services cgroup.
        resource_limits = man.get_resource_limits()
        CGroupConfigurator.get_instance().start_tracking_extension_services_cgroups(
            resource_limits.get_service_list())

    def _disable_extension(self, extension=None):
        self.set_operation(WALAEventOperation.Disable)
        man = self.load_manifest()
        disable_cmd = man.get_disable_command()
        self.logger.info("Disable extension: [{0}]".format(disable_cmd))
        self.launch_command(disable_cmd, cmd_name="disable", timeout=900,
                            extension_error_code=ExtensionErrorCodes.PluginDisableProcessingFailed,
                            extension=extension)

    def disable(self, extension=None, ignore_error=False):
        try:
            self._disable_extension(extension)
        except ExtensionError as error:
            if not ignore_error:
                raise

            msg = "[Ignored Error] Ran into error disabling extension:{0}".format(ustr(error))
            self.logger.info(msg)
            self.report_event(name=self.get_extension_full_name(extension), message=msg, is_success=False,
                              log_event=False)

        #
        # In the case of multi-config handlers, we keep the state of each extension individually.
        # Disable can be called when the extension is deleted (the extension state in the goal state is set to "disabled"),
        # or as part of the Uninstall and Update sequences. When the extension is deleted, we need to remove its state, along
        # with its status and settings files. Otherwise, we need to set the state to "disabled".
        #
        if self.should_perform_multi_config_op(extension):
            if extension.state == ExtensionRequestedState.Disabled:
                self.__remove_extension_state_files(extension)
            else:
                self.__set_extension_state(extension, ExtensionState.Disabled)

        # For Single config, dont check enabled_extensions because no extension state is maintained.
        # For MultiConfig, Set the handler state to Installed only when all extensions have been disabled
        if not self.supports_multi_config or not any(self.enabled_extensions):
            self.set_handler_state(ExtHandlerState.Installed)
            self.set_handler_status(status=ExtHandlerStatusValue.not_ready, message="Plugin disabled")

    def install(self, uninstall_exit_code=None, extension=None):
        # For Handler level operations, extension just specifies the settings that initiated the install.
        # This is needed to provide the sequence number and extension name in case the extension needs to report
        # failure/status using status file.
        uninstall_exit_code = str(uninstall_exit_code) if uninstall_exit_code is not None else NOT_RUN
        env = {ExtCommandEnvVariable.UninstallReturnCode: uninstall_exit_code}

        man = self.load_manifest()
        install_cmd = man.get_install_command()
        self.logger.info("Install extension [{0}]".format(install_cmd))
        self.set_operation(WALAEventOperation.Install)
        self.launch_command(install_cmd, cmd_name="install", timeout=900, extension=extension,
                            extension_error_code=ExtensionErrorCodes.PluginInstallProcessingFailed, env=env)
        self.set_handler_state(ExtHandlerState.Installed)
        self.set_handler_status(status=ExtHandlerStatusValue.not_ready, message="Plugin installed but not enabled")

    def uninstall(self, extension=None):
        # For Handler level operations, extension just specifies the settings that initiated the uninstall.
        # This is needed to provide the sequence number and extension name in case the extension needs to report
        # failure/status using status file.
        self.set_operation(WALAEventOperation.UnInstall)
        man = self.load_manifest()

        # stop tracking extension services cgroup.
        resource_limits = man.get_resource_limits()
        CGroupConfigurator.get_instance().stop_tracking_extension_services_cgroups(
            resource_limits.get_service_list())
        CGroupConfigurator.get_instance().reset_extension_services_quota(
            resource_limits.get_service_list())

        uninstall_cmd = man.get_uninstall_command()
        self.logger.info("Uninstall extension [{0}]".format(uninstall_cmd))
        self.launch_command(uninstall_cmd, cmd_name="uninstall", extension=extension)

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
                def on_rmtree_exception(_, __, exception):
                    if not isinstance(exception, OSError) or exception.errno != 2:  # [Errno 2] No such file or directory
                        raise exception

                # On 3.12, 'onerror' has been deprecated in favor of 'onexc'
                if sys.version_info[0] == 3 and sys.version_info[1] >= 12 or sys.version_info[0] > 3:
                    kwargs = { 'onexc': on_rmtree_exception }
                else:
                    kwargs = { 'onerror': lambda function, path, exc_info: on_rmtree_exception(function, path, exc_info[1]) }

                # E1123: Unexpected keyword argument 'onexc' in function call (unexpected-keyword-arg)
                shutil.rmtree(base_dir, **kwargs)  # pylint: disable=unexpected-keyword-arg

            CGroupConfigurator.get_instance().stop_tracking_extension_cgroups(self.get_full_name())
            self.logger.info("Remove the extension slice: {0}".format(self.get_full_name()))
            CGroupConfigurator.get_instance().reset_extension_quota(
                extension_name=self.get_full_name())

        except IOError as e:
            message = "Failed to remove extension handler directory: {0}".format(e)
            self.report_event(message=message, is_success=False)
            self.logger.warn(message)

    def update(self, updating_from_version, updating_to_version, extension=None, disable_exit_codes=None):
        # For Handler level operations, extension just specifies the settings that initiated the update.
        # This is needed to provide the sequence number and extension name in case the extension needs to report
        # failure/status using status file.
        env = {
            'VERSION': updating_to_version,  # Target version to be updated to
            ExtCommandEnvVariable.UpdatingFromVersion: updating_from_version  # Version upgrading/downgrading from
        }

        if not self.supports_multi_config:
            # For single config, extension.name == ext_handler.name
            env[ExtCommandEnvVariable.DisableReturnCode] = ustr(disable_exit_codes.get(self.ext_handler.name))
        else:
            disable_codes = []
            for ext in self.extensions:
                disable_codes.append({
                    "extensionName": ext.name,
                    "exitCode": ustr(disable_exit_codes.get(ext.name))
                })
            env[ExtCommandEnvVariable.DisableReturnCodeMultipleExtensions] = json.dumps(disable_codes)

        try:
            self.set_operation(WALAEventOperation.Update)
            man = self.load_manifest()
            update_cmd = man.get_update_command()
            self.logger.info("Update extension [{0}]".format(update_cmd))
            self.launch_command(update_cmd, cmd_name="update",
                                timeout=900,
                                extension_error_code=ExtensionErrorCodes.PluginUpdateProcessingFailed,
                                env=env, extension=extension)
        except ExtensionError:
            # Mark the handler as Failed so we don't clean it up and can keep reporting its status
            self.set_handler_state(ExtHandlerState.FailedUpgrade)
            raise

    def update_with_install(self, uninstall_exit_code=None, extension=None):
        man = self.load_manifest()
        if man.is_update_with_install():
            self.install(uninstall_exit_code=uninstall_exit_code, extension=extension)
        else:
            self.logger.info("UpdateWithInstall not set. "
                             "Skip install during upgrade.")
        self.set_handler_state(ExtHandlerState.Installed)

    def _get_last_modified_seq_no_from_config_files(self, extension):
        """
        The sequence number is not guaranteed to always be strictly increasing. To ensure we always get the latest one,
        fetching the sequence number from config file that was last modified (and not necessarily the largest).
        :return: Last modified Sequence number or -1 on errors
        """
        seq_no = -1

        if self.supports_multi_config and (extension is None or extension.name is None):
            # If no extension name is provided for Multi Config, don't try to parse any sequence number from filesystem
            return seq_no

        try:
            largest_modified_time = 0
            conf_dir = self.get_conf_dir()
            for item in os.listdir(conf_dir):
                item_path = os.path.join(conf_dir, item)
                if not os.path.isfile(item_path):
                    continue
                try:
                    # Settings file for Multi Config look like - <extName>.<seqNo>.settings
                    # Settings file for Single Config look like - <seqNo>.settings
                    match = re.search("((?P<ext_name>\\w+)\\.)*(?P<seq_no>\\d+)\\.settings", item_path)
                    if match is not None:
                        ext_name = match.group('ext_name')
                        if self.supports_multi_config and extension.name != ext_name:
                            continue
                        curr_seq_no = int(match.group("seq_no"))
                        curr_modified_time = os.path.getmtime(item_path)
                        if curr_modified_time > largest_modified_time:
                            seq_no = curr_seq_no
                            largest_modified_time = curr_modified_time
                except (ValueError, IndexError, TypeError):
                    self.logger.verbose("Failed to parse file name: {0}", item)
                    continue
        except Exception as error:
            logger.verbose("Error fetching sequence number from config files: {0}".format(ustr(error)))
            seq_no = -1

        return seq_no

    def get_status_file_path(self, extension=None):
        """
        We should technically only fetch the sequence number from GoalState and not rely on the filesystem at all,
        But there are certain scenarios where we need to fetch the latest sequence number from the filesystem
        (For example when we need to report the status for extensions of previous GS if the current GS is Unsupported).
        Always prioritizing sequence number from extensions but falling back to filesystem
        :param extension: Extension for which the sequence number is required
        :return: Sequence number for the extension, Status file path or -1, None
        """
        path = None
        seq_no = None
        if extension is not None and extension.sequenceNumber is not None:
            try:
                seq_no = int(extension.sequenceNumber)
            except ValueError:
                logger.error('Sequence number [{0}] does not appear to be valid'.format(extension.sequenceNumber))

        if seq_no is None:
            # If we're unable to fetch Sequence number from Extension for any reason,
            # try fetching it from the last modified Settings file.
            seq_no = self._get_last_modified_seq_no_from_config_files(extension)

        if seq_no is not None and seq_no > -1:
            if self.should_perform_multi_config_op(extension) and extension is not None and extension.name is not None:
                path = os.path.join(self.get_status_dir(), "{0}.{1}.status".format(extension.name, seq_no))
            elif not self.supports_multi_config:
                path = os.path.join(self.get_status_dir(), "{0}.status").format(seq_no)

        return seq_no if seq_no is not None else -1, path

    def collect_ext_status(self, ext):
        self.logger.verbose("Collect extension status for {0}".format(self.get_extension_full_name(ext)))
        seq_no, ext_status_file = self.get_status_file_path(ext)

        # We should never try to read any status file if the handler has no settings, returning None in that case
        if seq_no == -1 or ext is None:
            return None

        data = None
        data_str = None
        # Extension.name contains the extension name in case of MC and Handler name in case of Single Config.
        ext_status = ExtensionStatus(name=ext.name, seq_no=seq_no)

        try:
            data_str, data = self._read_status_file(ext_status_file)
        except ExtensionStatusError as e:
            msg = ""
            ext_status.status = ExtensionStatusValue.error

            if e.code == ExtensionStatusError.CouldNotReadStatusFile:
                ext_status.code = ExtensionErrorCodes.PluginUnknownFailure
                msg = u"We couldn't read any status for {0} extension, for the sequence number {1}. It failed due" \
                      u" to {2}".format(self.get_full_name(ext), seq_no, ustr(e))
            elif e.code == ExtensionStatusError.InvalidJsonFile:
                ext_status.code = ExtensionErrorCodes.PluginSettingsStatusInvalid
                msg = u"The status reported by the extension {0}(Sequence number {1}), was in an " \
                      u"incorrect format and the agent could not parse it correctly. Failed due to {2}" \
                      .format(self.get_full_name(ext), seq_no, ustr(e))
            elif e.code == ExtensionStatusError.FileNotExists:
                msg = "This status is being reported by the Guest Agent since no status file was " \
                      "reported by extension {0}: {1}".format(self.get_extension_full_name(ext), ustr(e))

                # Reporting a success code and transitioning status to keep in accordance with existing code that
                # creates default status placeholder file
                ext_status.code = ExtensionErrorCodes.PluginSuccess
                ext_status.status = ExtensionStatusValue.transitioning

            # This log is periodic due to the verbose nature of the status check. Please make sure that the message
            # constructed above does not change very frequently and includes important info such as sequence number,
            # extension name to make sure that the log reflects changes in the extension sequence for which the
            # status is being sent.
            logger.periodic_warn(logger.EVERY_HALF_HOUR, u"[PERIODIC] " + msg)
            add_periodic(delta=logger.EVERY_HALF_HOUR, name=self.get_extension_full_name(ext),
                         version=self.ext_handler.version,
                         op=WALAEventOperation.StatusProcessing, is_success=False, message=msg,
                         log_event=False)

            ext_status.message = msg

            return ext_status

        # We did not encounter InvalidJsonFile/CouldNotReadStatusFile and thus the status file was correctly written
        # and has valid json.
        try:
            parse_ext_status(ext_status, data)
            if len(data_str) > _MAX_STATUS_FILE_SIZE_IN_BYTES:
                raise ExtensionStatusError(msg="For Extension Handler {0} for the sequence number {1}, the status "
                                               "file {2} of size {3} bytes is too big. Max Limit allowed is {4} bytes"
                                           .format(self.get_full_name(ext), seq_no,
                                                   ext_status_file, len(data_str), _MAX_STATUS_FILE_SIZE_IN_BYTES),
                                           code=ExtensionStatusError.MaxSizeExceeded)
        except ExtensionStatusError as e:
            msg = u"For Extension Handler {0} for the sequence number {1}, the status file {2}. " \
                  u"Encountered the following error: {3}".format(self.get_full_name(ext), seq_no,
                                                                 ext_status_file, ustr(e))
            logger.periodic_warn(logger.EVERY_DAY, u"[PERIODIC] " + msg)
            add_periodic(delta=logger.EVERY_HALF_HOUR, name=self.get_extension_full_name(ext),
                         version=self.ext_handler.version,
                         op=WALAEventOperation.StatusProcessing, is_success=False, message=msg, log_event=False)

            if e.code == ExtensionStatusError.MaxSizeExceeded:
                ext_status.message, field_size = self._truncate_message(ext_status.message, _MAX_STATUS_MESSAGE_LENGTH)
                ext_status.substatusList = self._process_substatus_list(ext_status.substatusList, field_size)

            elif e.code == ExtensionStatusError.StatusFileMalformed:
                ext_status.message = "Could not get a valid status from the extension {0}. Encountered the " \
                                     "following error: {1}".format(self.get_full_name(ext), ustr(e))
                ext_status.code = ExtensionErrorCodes.PluginSettingsStatusInvalid
                ext_status.status = ExtensionStatusValue.error

        return ext_status

    def get_ext_handling_status(self, ext):
        seq_no, ext_status_file = self.get_status_file_path(ext)

        # This is legacy scenario for cases when no extension settings is available
        if seq_no < 0 or ext_status_file is None:
            return None

        # Missing status file is considered a non-terminal state here
        # so that extension sequencing can wait until it becomes existing
        if not os.path.exists(ext_status_file):
            status = ExtensionStatusValue.warning
        else:
            ext_status = self.collect_ext_status(ext)
            status = ext_status.status if ext_status is not None else None

        return status

    def is_ext_handling_complete(self, ext):
        status = self.get_ext_handling_status(ext)

        # when seq < 0 (i.e. no new user settings), the handling is complete and return None status
        if status is None:
            return True, None

        # If not in terminal state, it is incomplete
        if status not in _EXTENSION_TERMINAL_STATUSES:
            return False, status

        # Extension completed, return its status
        return True, status

    def report_error_on_incarnation_change(self, goal_state_changed, log_msg, event_msg, extension=None,
                                           op=WALAEventOperation.ReportStatus):
        # Since this code is called on a loop, logging as a warning only on goal state change, else logging it
        # as verbose
        if goal_state_changed:
            logger.warn(log_msg)
            add_event(name=self.get_extension_full_name(extension), version=self.ext_handler.version,
                      op=op, message=event_msg, is_success=False, log_event=False)
        else:
            logger.verbose(log_msg)

    def get_extension_handler_statuses(self, handler_status, goal_state_changed):
        """
        Get the list of ExtHandlerStatus objects corresponding to each extension in the Handler. Each object might have
        its own status for the Extension status but the Handler status would be the same for each extension in a Handle
        :return: List of ExtHandlerStatus objects for each extension in the Handler
        """
        ext_handler_statuses = []
        # TODO Refactor or remove this common code pattern (for each extension subordinate to an ext_handler, do X).
        for ext in self.extensions:
            # In MC, for disabled extensions we dont need to report status. Skip reporting if disabled and state == disabled
            # Extension.state corresponds to the state requested by CRP, self.__get_extension_state() corresponds to the
            # state of the extension on the VM. Skip reporting only if both are Disabled
            if self.should_perform_multi_config_op(ext) and \
                    ext.state == ExtensionState.Disabled and self.get_extension_state(ext) == ExtensionState.Disabled:
                continue

            # Breaking off extension reporting in 2 parts, one which is Handler dependent and the other that is Extension dependent
            try:
                ext_handler_status = ExtHandlerStatus()
                set_properties("ExtHandlerStatus", ext_handler_status, get_properties(handler_status))
            except Exception as error:
                msg = "Something went wrong when trying to get a copy of the Handler status for {0}".format(
                    self.get_extension_full_name())
                self.report_error_on_incarnation_change(goal_state_changed, event_msg=msg,
                                                        log_msg="{0}.\nStack Trace: {1}".format(
                                                                                     msg, textutil.format_exception(error)))
                # Since this is a Handler level error and we need to do it per extension, breaking here and logging
                # error since we wont be able to report error anyways and saving it as a handler status (legacy behavior)
                self.set_handler_status(message=msg, code=-1)
                break

            # For the extension dependent stuff, if there's some unhandled error, we will report it back to CRP as an extension error.
            try:
                ext_status = self.collect_ext_status(ext)
                if ext_status is not None:
                    ext_handler_status.extension_status = ext_status
                ext_handler_statuses.append(ext_handler_status)
            except ExtensionError as error:

                msg = "Unknown error when trying to fetch status from extension {0}".format(
                    self.get_extension_full_name(ext))
                self.report_error_on_incarnation_change(goal_state_changed, event_msg=msg,
                                                        log_msg="{0}.\nStack Trace: {1}".format(
                                                                                     msg, textutil.format_exception(error)),
                                                        extension=ext)

                # Unexpected error, for single config, keep the behavior as is
                if not self.should_perform_multi_config_op(ext):
                    self.set_handler_status(message=ustr(error), code=error.code)
                    break

                # For MultiConfig, create a custom ExtensionStatus object with the error details and attach it to the Handler.
                # This way the error would be reported back to CRP and the failure would be propagated instantly as compared to CRP eventually timing it out.
                ext_status = ExtensionStatus(name=ext.name, seq_no=ext.sequenceNumber,
                                             code=ExtensionErrorCodes.PluginUnknownFailure,
                                             status=ExtensionStatusValue.error, message=msg)
                ext_handler_status.extension_status = ext_status
                ext_handler_statuses.append(ext_handler_status)

        return ext_handler_statuses

    def collect_heartbeat(self):  # pylint: disable=R1710
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

    def launch_command(self, cmd, cmd_name=None, timeout=300, extension_error_code=ExtensionErrorCodes.PluginProcessingError,
                       env=None, extension=None):
        begin_utc = datetime.datetime.now(UTC)
        self.logger.verbose("Launch command: [{0}]", cmd)

        base_dir = self.get_base_dir()

        with tempfile.TemporaryFile(dir=base_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=base_dir, mode="w+b") as stderr:
                if env is None:
                    env = {}

                # Always add Extension Path and version to the current launch_command (Ask from publishers)
                env.update({
                    ExtCommandEnvVariable.ExtensionPath: base_dir,
                    ExtCommandEnvVariable.ExtensionVersion: str(self.ext_handler.version),
                    ExtCommandEnvVariable.WireProtocolAddress: self.protocol.get_endpoint(),

                    # Setting sequence number to 0 incase no settings provided to keep in accordance with the empty
                    # 0.settings file that we create for such extensions.
                    ExtCommandEnvVariable.ExtensionSeqNumber: str(
                        extension.sequenceNumber) if extension is not None else _DEFAULT_SEQ_NO
                })

                if self.should_perform_multi_config_op(extension):
                    env[ExtCommandEnvVariable.ExtensionName] = extension.name

                supported_features = []
                for _, feature in get_agent_supported_features_list_for_extensions().items():
                    supported_features.append(
                        {
                            "Key": feature.name,
                            "Value": feature.version
                        }
                    )
                if supported_features:
                    env[ExtCommandEnvVariable.ExtensionSupportedFeatures] = json.dumps(supported_features)

                ext_name = self.get_extension_full_name(extension)
                try:
                    # Some extensions erroneously begin cmd with a slash; don't interpret those
                    # as root-relative. (Issue #1170)
                    command_full_path = os.path.join(base_dir, cmd.lstrip(os.path.sep))
                    log_msg = "Executing command: {0} with environment variables: {1}".format(command_full_path,
                                                                                              json.dumps(env))
                    self.logger.info(log_msg)
                    self.report_event(name=ext_name, message=log_msg, log_event=False)

                    # Add the os environment variables before executing command
                    env.update(os.environ)
                    process_output = CGroupConfigurator.get_instance().start_extension_command(
                        extension_name=self.get_full_name(extension),
                        command=command_full_path,
                        cmd_name=cmd_name,
                        timeout=timeout,
                        shell=True,
                        cwd=base_dir,
                        env=env,
                        stdout=stdout,
                        stderr=stderr,
                        error_code=extension_error_code)

                except OSError as e:
                    raise ExtensionError("Failed to launch '{0}': {1}".format(command_full_path, e.strerror),
                                         code=extension_error_code)

                duration = elapsed_milliseconds(begin_utc)
                log_msg = "Command: {0}\n{1}".format(cmd, "\n".join(
                    [line for line in process_output.split('\n') if line != ""]))
                self.logger.info(log_msg)
                self.report_event(name=ext_name, message=log_msg, duration=duration, log_event=False)

                return process_output

    def load_manifest(self):
        man_file = self.get_manifest_file()
        try:
            data = json.loads(fileutil.read_file(man_file))
        except (IOError, OSError) as e:
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
        except IOError as e:
            fileutil.clean_ioerror(e,
                                   paths=[settings_file])
            raise ExtensionError(u"Failed to update settings file", e)

    def update_settings(self, extension):
        if self.extensions is None or len(self.extensions) == 0 or extension is None:
            # This is the behavior of waagent 2.0.x
            # The new agent has to be consistent with the old one.
            self.logger.info("Extension has no settings, write empty 0.settings")
            self.update_settings_file("{0}.settings".format(_DEFAULT_SEQ_NO), "")
            return

        settings = {
            'publicSettings': extension.publicSettings,
            'protectedSettings': extension.protectedSettings,
            'protectedSettingsCertThumbprint': extension.certificateThumbprint
        }
        ext_settings = {
            "runtimeSettings": [{
                "handlerSettings": settings
            }]
        }
        # MultiConfig: change the name to <extName>.<seqNo>.settings for MC and <seqNo>.settings for SC
        settings_file = "{0}.{1}.settings".format(extension.name, extension.sequenceNumber) if \
            self.should_perform_multi_config_op(extension) else "{0}.settings".format(extension.sequenceNumber)

        self.logger.info("Update settings file: {0}", settings_file)
        self.update_settings_file(settings_file, json.dumps(ext_settings))

    def create_handler_env(self):
        handler_env = {
                HandlerEnvironment.logFolder: self.get_log_dir(),
                HandlerEnvironment.configFolder: self.get_conf_dir(),
                HandlerEnvironment.statusFolder: self.get_status_dir(),
                HandlerEnvironment.heartbeatFile: self.get_heartbeat_file()
            }

        if get_supported_feature_by_name(SupportedFeatureNames.ExtensionTelemetryPipeline).is_supported:
            handler_env[HandlerEnvironment.eventsFolder] = self.get_extension_events_dir()
            # For now, keep the preview key to not break extensions that were using the preview.
            handler_env[HandlerEnvironment.eventsFolder_preview] = self.get_extension_events_dir()

        env = [{
            HandlerEnvironment.name: self.ext_handler.name,
            HandlerEnvironment.version: HandlerEnvironment.schemaVersion,
            HandlerEnvironment.handlerEnvironment: handler_env
        }]
        try:
            fileutil.write_file(self.get_env_file(), json.dumps(env))
        except IOError as e:
            fileutil.clean_ioerror(e,
                                   paths=[self.get_base_dir(), self.pkg_file])
            raise ExtensionDownloadError(u"Failed to save handler environment", e)

    def __get_handler_state_file_name(self, extension=None):
        if self.should_perform_multi_config_op(extension):
            return "{0}.HandlerState".format(extension.name)
        return "HandlerState"

    def set_handler_state(self, handler_state):
        self.__set_state(name=self.__get_handler_state_file_name(), value=handler_state)

    def get_handler_state(self):
        return self.__get_state(name=self.__get_handler_state_file_name(), default=ExtHandlerState.NotInstalled)

    def __set_extension_state(self, extension, extension_state):
        self.__set_state(name=self.__get_handler_state_file_name(extension), value=extension_state)

    def get_extension_state(self, extension=None):
        return self.__get_state(name=self.__get_handler_state_file_name(extension), default=ExtensionState.Disabled)

    def __set_state(self, name, value):
        state_dir = self.get_conf_dir()
        state_file = os.path.join(state_dir, name)
        try:
            if not os.path.exists(state_dir):
                fileutil.mkdir(state_dir, mode=0o700)
            fileutil.write_file(state_file, value)
        except IOError as e:
            fileutil.clean_ioerror(e, paths=[state_file])
            self.logger.error("Failed to set state: {0}", e)

    def __get_state(self, name, default=None):
        state_dir = self.get_conf_dir()
        state_file = os.path.join(state_dir, name)
        if not os.path.isfile(state_file):
            return default

        try:
            return fileutil.read_file(state_file)
        except IOError as e:
            self.logger.error("Failed to get state: {0}", e)
            return default

    def __remove_extension_state_files(self, extension):
        self.logger.info("Removing states files for disabled extension: {0}".format(extension.name))
        try:
            # MultiConfig: Remove all config/<extName>.*.settings, status/<extName>.*.status and config/<extName>.HandlerState files
            files_to_delete = [
                os.path.join(self.get_conf_dir(), "{0}.*.settings".format(extension.name)),
                os.path.join(self.get_status_dir(), "{0}.*.status".format(extension.name)),
                os.path.join(self.get_conf_dir(), self.__get_handler_state_file_name(extension))
            ]

            fileutil.rm_files(*files_to_delete)

        except Exception as error:
            extension_name = self.get_extension_full_name(extension)
            message = "Failed to remove extension state files for {0}: {1}".format(extension_name, ustr(error))
            self.report_event(name=extension_name, message=message, is_success=False, log_event=False)
            self.logger.warn(message)

    def set_handler_status(self, status=ExtHandlerStatusValue.not_ready, message="", code=0):
        state_dir = self.get_conf_dir()

        handler_status = ExtHandlerStatus()
        handler_status.name = self.ext_handler.name
        handler_status.version = str(self.ext_handler.version)
        handler_status.message = redact_sas_token(message)
        handler_status.code = code
        handler_status.status = status
        handler_status.supports_multi_config = self.ext_handler.supports_multi_config
        handler_status.signature_validated = self.signature_validated
        status_file = os.path.join(state_dir, "HandlerStatus")

        try:
            handler_status_json = json.dumps(get_properties(handler_status))
            if handler_status_json is not None:
                if not os.path.exists(state_dir):
                    fileutil.mkdir(state_dir, mode=0o700)
                fileutil.write_file(status_file, handler_status_json)
            else:
                self.logger.error("Failed to create JSON document of handler status for {0} version {1}".format(
                    self.ext_handler.name, self.ext_handler.version))
        except (IOError, ValueError, ProtocolError) as error:
            fileutil.clean_ioerror(error, paths=[status_file])
            self.logger.error("Failed to save handler status: {0}", textutil.format_exception(error))

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
        except (IOError, ValueError) as error:
            self.logger.error("Failed to get handler status: {0}", error)
        except Exception as error:
            error_msg = "Failed to get handler status message: {0}.\n Contents of file: {1}".format(
                ustr(error), handler_status_contents).replace('"', '\'')
            add_periodic(
                delta=logger.EVERY_HOUR,
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.ExtensionProcessing,
                is_success=False,
                message=error_msg)
            raise

        return None

    def __get_signature_validated(self):
        """
        Returns the signature validation state recorded in the HandlerStatus file. If HandlerStatus has not been created,
        returns False.
        """
        # Retrieve the ExtHandlerStatus object.
        handler_status = self.get_handler_status()
        if handler_status is None:
            return False

        # The "signature_validated" attribute defaults to False if it is missing from the HandlerStatus file,
        # so there's no need to explicitly check for its existence here.
        return handler_status.signature_validated

    def get_extension_package_zipfile_name(self):
        return "{0}__{1}{2}".format(self.ext_handler.name,
                                    self.ext_handler.version,
                                    HANDLER_PKG_EXT)

    def get_full_name(self, extension=None):
        """
        :return: <HandlerName>-<HandlerVersion> if extension is None or Handler does not support Multi Config,
        else then return -  <HandlerName>.<ExtensionName>-<HandlerVersion>
        """
        return "{0}-{1}".format(self.get_extension_full_name(extension), self.ext_handler.version)

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

    @staticmethod
    def _read_status_file(ext_status_file):
        err_count = 0
        while True:
            try:
                return ExtHandlerInstance._read_and_parse_json_status_file(ext_status_file)
            except Exception:
                err_count += 1
                if err_count >= _NUM_OF_STATUS_FILE_RETRIES:
                    raise
            time.sleep(_STATUS_FILE_RETRY_DELAY)

    @staticmethod
    def _read_and_parse_json_status_file(ext_status_file):

        if not os.path.exists(ext_status_file):
            raise ExtensionStatusError(msg="Status file {0} does not exist".format(ext_status_file),
                                       code=ExtensionStatusError.FileNotExists)
        try:
            data_str = fileutil.read_file(ext_status_file)
        except IOError as e:
            raise ExtensionStatusError(msg=ustr(e), inner=e,
                                       code=ExtensionStatusError.CouldNotReadStatusFile)
        try:
            data = json.loads(data_str)
        except (ValueError, TypeError) as e:
            raise ExtensionStatusError(msg="{0} \n First 2000 Bytes of status file:\n {1}".format(ustr(e), ustr(data_str)[:2000]),
                                       inner=e,
                                       code=ExtensionStatusError.InvalidJsonFile)
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
    def _truncate_message(field, truncate_size=_MAX_SUBSTATUS_FIELD_LENGTH):  # pylint: disable=R1710
        if field is None:  # pylint: disable=R1705
            return
        else:
            truncated_field = field if len(field) < truncate_size else field[:truncate_size] + _TRUNCATED_SUFFIX
            return truncated_field, len(truncated_field)


class HandlerEnvironment(object):
    # HandlerEnvironment.json schema version
    schemaVersion = 1.0
    fileName = "HandlerEnvironment.json"
    handlerEnvironment = "handlerEnvironment"
    logFolder = "logFolder"
    configFolder = "configFolder"
    statusFolder = "statusFolder"
    heartbeatFile = "heartbeatFile"
    eventsFolder_preview = "eventsFolder_preview"
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
        value = self.data['handlerManifest'].get('reportHeartbeat', False)
        return self._parse_boolean_value(value, default_val=False)

    def is_update_with_install(self):
        update_mode = self.data['handlerManifest'].get('updateMode')
        if update_mode is None:
            return True
        return update_mode.lower() == "updatewithinstall"

    def is_continue_on_update_failure(self):
        value = self.data['handlerManifest'].get('continueOnUpdateFailure', False)
        return self._parse_boolean_value(value, default_val=False)

    def supports_multiple_extensions(self):
        value = self.data['handlerManifest'].get('supportsMultipleExtensions', False)
        return self._parse_boolean_value(value, default_val=False)

    def get_resource_limits(self):
        return ResourceLimits(self.data.get('resourceLimits', None))

    def report_invalid_boolean_properties(self, ext_name):
        """
        Check that the specified keys in the handler manifest has boolean values.
        """
        for key in ['reportHeartbeat', 'continueOnUpdateFailure', 'supportsMultipleExtensions']:
            value = self.data['handlerManifest'].get(key)
            if value is not None and not isinstance(value, bool):
                msg = "In the handler manifest: '{0}' has a non-boolean value [{1}] for boolean type. Please change it to a boolean value.".format(key, value)
                logger.info(msg)
                add_event(name=ext_name, message=msg, op=WALAEventOperation.ExtensionHandlerManifest, log_event=False)

    @staticmethod
    def _parse_boolean_value(value, default_val):
        """
        Expects boolean value but
        for backward compatibility, 'true' (case-insensitive) is accepted, and other values default to False
        Note: Json module returns unicode on py2. In py3, unicode removed
        ustr is a unicode object for Py2 and a str object for Py3.
        """
        if not isinstance(value, bool):
            return True if isinstance(value, ustr) and value.lower() == "true" else default_val
        return value


class ResourceLimits(object):
    def __init__(self, data):
        self.data = data

    def get_extension_slice_cpu_quota(self):
        if self.data is not None:
            return self.data.get('cpuQuotaPercentage', None)
        return None

    def get_extension_slice_memory_quota(self):
        if self.data is not None:
            return self.data.get('memoryQuotaInMB', None)
        return None

    def get_service_list(self):
        if self.data is not None:
            return self.data.get('services', None)
        return None


class ExtensionStatusError(ExtensionError):
    """
    When extension failed to provide a valid status file
    """
    CouldNotReadStatusFile = 1
    InvalidJsonFile = 2
    StatusFileMalformed = 3
    MaxSizeExceeded = 4
    FileNotExists = 5

    def __init__(self, msg=None, inner=None, code=-1):  # pylint: disable=W0235
        super(ExtensionStatusError, self).__init__(msg, inner, code)
