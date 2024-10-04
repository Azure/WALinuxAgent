# Copyright 2018 Microsoft Corporation
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

import atexit
import json
import os
import platform
import re
import sys
import threading
import time
import traceback
from datetime import datetime

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.exception import EventError, OSUtilError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.datacontract import get_properties, set_properties
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.telemetryevent import TelemetryEventParam, TelemetryEvent, CommonTelemetryEventSchema, \
    GuestAgentGenericLogsSchema, GuestAgentExtensionEventsSchema, GuestAgentPerfCounterEventsSchema
from azurelinuxagent.common.utils import fileutil, textutil
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, getattrib, str_to_encoded_ustr
from azurelinuxagent.common.version import CURRENT_VERSION, CURRENT_AGENT, AGENT_NAME, DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME, AGENT_EXECUTION_MODE
from azurelinuxagent.common.protocol.imds import get_imds_client

EVENTS_DIRECTORY = "events"

_EVENT_MSG = "Event: name={0}, op={1}, message={2}, duration={3}"
TELEMETRY_EVENT_PROVIDER_ID = "69B669B9-4AF8-4C50-BDC4-6006FA76E975"
TELEMETRY_EVENT_EVENT_ID = 1
TELEMETRY_METRICS_EVENT_ID = 4

TELEMETRY_LOG_PROVIDER_ID = "FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F"
TELEMETRY_LOG_EVENT_ID = 7

#
# When this flag is enabled the TODO comment in Logger.log() needs to be addressed; also the tests
# marked with "Enable this test when SEND_LOGS_TO_TELEMETRY is enabled" should be enabled.
#
SEND_LOGS_TO_TELEMETRY = False

MAX_NUMBER_OF_EVENTS = 1000

AGENT_EVENT_FILE_EXTENSION = '.waagent.tld'
EVENT_FILE_REGEX = re.compile(r'(?P<agent_event>\.waagent)?\.tld$')

def send_logs_to_telemetry():
    return SEND_LOGS_TO_TELEMETRY


class WALAEventOperation:
    ActivateResourceDisk = "ActivateResourceDisk"
    AgentBlacklisted = "AgentBlacklisted"
    AgentEnabled = "AgentEnabled"
    AgentMemory = "AgentMemory"
    AgentUpgrade = "AgentUpgrade"
    ArtifactsProfileBlob = "ArtifactsProfileBlob"
    CGroupsCleanUp = "CGroupsCleanUp"
    CGroupsDisabled = "CGroupsDisabled"
    CGroupsInfo = "CGroupsInfo"
    CloudInit = "CloudInit"
    CollectEventErrors = "CollectEventErrors"
    CollectEventUnicodeErrors = "CollectEventUnicodeErrors"
    ConfigurationChange = "ConfigurationChange"
    CustomData = "CustomData"
    DefaultChannelChange = "DefaultChannelChange"
    Deploy = "Deploy"
    Disable = "Disable"
    Downgrade = "Downgrade"
    Download = "Download"
    Enable = "Enable"
    ExtensionHandlerManifest = "ExtensionHandlerManifest"
    ExtensionPolicy = "ExtensionPolicy"
    ExtensionProcessing = "ExtensionProcessing"
    ExtensionTelemetryEventProcessing = "ExtensionTelemetryEventProcessing"
    FetchGoalState = "FetchGoalState"
    Firewall = "Firewall"
    GoalState = "GoalState"
    GoalStateUnsupportedFeatures = "GoalStateUnsupportedFeatures"
    HealthCheck = "HealthCheck"
    HealthObservation = "HealthObservation"
    HeartBeat = "HeartBeat"
    HostnamePublishing = "HostnamePublishing"
    HostPlugin = "HostPlugin"
    HostPluginHeartbeat = "HostPluginHeartbeat"
    HostPluginHeartbeatExtended = "HostPluginHeartbeatExtended"
    HttpErrors = "HttpErrors"
    HttpGet = "HttpGet"
    ImdsHeartbeat = "ImdsHeartbeat"
    Install = "Install"
    InitializeHostPlugin = "InitializeHostPlugin"
    Log = "Log"
    LogCollection = "LogCollection"
    NoExec = "NoExec"
    OSInfo = "OSInfo"
    OpenSsl = "OpenSsl"
    Partition = "Partition"
    PersistFirewallRules = "PersistFirewallRules"
    Policy = "Policy"
    ProvisionAfterExtensions = "ProvisionAfterExtensions"
    PluginSettingsVersionMismatch = "PluginSettingsVersionMismatch"
    InvalidExtensionConfig = "InvalidExtensionConfig"
    Provision = "Provision"
    ProvisionGuestAgent = "ProvisionGuestAgent"
    RemoteAccessHandling = "RemoteAccessHandling"
    ReportEventErrors = "ReportEventErrors"
    ReportEventUnicodeErrors = "ReportEventUnicodeErrors"
    ReportStatus = "ReportStatus"
    ReportStatusExtended = "ReportStatusExtended"
    ResetFirewall = "ResetFirewall"
    Restart = "Restart"
    SequenceNumberMismatch = "SequenceNumberMismatch"
    SetCGroupsLimits = "SetCGroupsLimits"
    SkipUpdate = "SkipUpdate"
    StatusProcessing = "StatusProcessing"
    UnhandledError = "UnhandledError"
    UnInstall = "UnInstall"
    Unknown = "Unknown"
    Update = "Update"
    VmSettings = "VmSettings"
    VmSettingsSummary = "VmSettingsSummary"


SHOULD_ENCODE_MESSAGE_LEN = 80
SHOULD_ENCODE_MESSAGE_OP = [
    WALAEventOperation.Disable,
    WALAEventOperation.Enable,
    WALAEventOperation.Install,
    WALAEventOperation.UnInstall,
]


class EventStatus(object):
    EVENT_STATUS_FILE = "event_status.json"

    def __init__(self):
        self._path = None
        self._status = {}

    def clear(self):
        self._status = {}
        self._save()

    def event_marked(self, name, version, op):
        return self._event_name(name, version, op) in self._status

    def event_succeeded(self, name, version, op):
        event = self._event_name(name, version, op)
        if event not in self._status:
            return True
        return self._status[event] is True

    def initialize(self, status_dir=conf.get_lib_dir()):
        self._path = os.path.join(status_dir, EventStatus.EVENT_STATUS_FILE)
        self._load()

    def mark_event_status(self, name, version, op, status):
        event = self._event_name(name, version, op)
        self._status[event] = (status is True)
        self._save()

    def _event_name(self, name, version, op):
        return "{0}-{1}-{2}".format(name, version, op)

    def _load(self):
        try:
            self._status = {}
            if os.path.isfile(self._path):
                with open(self._path, 'r') as f:
                    self._status = json.load(f)
        except Exception as e:
            logger.warn("Exception occurred loading event status: {0}".format(e))
            self._status = {}

    def _save(self):
        try:
            with open(self._path, 'w') as f:
                json.dump(self._status, f)
        except Exception as e:
            logger.warn("Exception occurred saving event status: {0}".format(e))


__event_status__ = EventStatus()
__event_status_operations__ = [
        WALAEventOperation.ReportStatus
    ]


def parse_json_event(data_str):
    data = json.loads(data_str)
    event = TelemetryEvent()
    set_properties("TelemetryEvent", event, data)
    event.file_type = "json"
    return event


def parse_event(data_str):
    try:
        return parse_json_event(data_str)
    except ValueError:
        return parse_xml_event(data_str)

def parse_xml_param(param_node):
    name = getattrib(param_node, "Name")
    value_str = getattrib(param_node, "Value")
    attr_type = getattrib(param_node, "T")
    value = value_str
    if attr_type == 'mt:uint64':
        value = int(value_str)
    elif attr_type == 'mt:bool':
        value = bool(value_str)
    elif attr_type == 'mt:float64':
        value = float(value_str)
    return TelemetryEventParam(name, value)


def parse_xml_event(data_str):
    try:
        xml_doc = parse_doc(data_str)
        event_id = getattrib(find(xml_doc, "Event"), 'id')
        provider_id = getattrib(find(xml_doc, "Provider"), 'id')
        event = TelemetryEvent(event_id, provider_id)
        param_nodes = findall(xml_doc, 'Param')
        for param_node in param_nodes:
            event.parameters.append(parse_xml_param(param_node))
        event.file_type = "xml"
        return event
    except Exception as e:
        raise ValueError(ustr(e))


def _encode_message(op, message):
    """
    Gzip and base64 encode a message based on the operation.

    The intent of this message is to make the logs human readable and include the
    stdout/stderr from extension operations.  Extension operations tend to generate
    a lot of noise, which makes it difficult to parse the line-oriented waagent.log.
    The compromise is to encode the stdout/stderr so we preserve the data and do
    not destroy the line oriented nature.

    The data can be recovered using the following command:

      $ echo '<encoded data>' | base64 -d | pigz -zd

    You may need to install the pigz command.

    :param op: Operation, e.g. Enable or Install
    :param message: Message to encode
    :return: gzip'ed and base64 encoded message, or the original message
    """

    if len(message) == 0:
        return message

    if op not in SHOULD_ENCODE_MESSAGE_OP:
        return message

    try:
        return textutil.compress(message)
    except Exception:
        # If the message could not be encoded a dummy message ('<>') is returned.
        # The original message was still sent via telemetry, so all is not lost.
        return "<>"


def _log_event(name, op, message, duration, is_success=True):
    global _EVENT_MSG  # pylint: disable=W0602, W0603

    if not is_success:
        logger.error(_EVENT_MSG, name, op, message, duration)
    else:
        logger.info(_EVENT_MSG, name, op, message, duration)


class CollectOrReportEventDebugInfo(object):
    """
    This class is used for capturing and reporting debug info that is captured during event collection and
    reporting to wireserver.
    It captures the count of unicode errors and any unexpected errors and also a subset of errors with stacks to help
    with debugging any potential issues.
    """
    __MAX_ERRORS_TO_REPORT = 5
    OP_REPORT = "Report"
    OP_COLLECT = "Collect"

    def __init__(self, operation=OP_REPORT):
        self.__unicode_error_count = 0
        self.__unicode_errors = set()
        self.__op_error_count = 0
        self.__op_errors = set()

        if operation == self.OP_REPORT:
            self.__unicode_error_event = WALAEventOperation.ReportEventUnicodeErrors
            self.__op_errors_event = WALAEventOperation.ReportEventErrors
        elif operation == self.OP_COLLECT:
            self.__unicode_error_event = WALAEventOperation.CollectEventUnicodeErrors
            self.__op_errors_event = WALAEventOperation.CollectEventErrors

    def report_debug_info(self):

        def report_dropped_events_error(count, errors, operation_name):
            err_msg_format = "DroppedEventsCount: {0}\nReasons (first {1} errors): {2}"
            if count > 0:
                add_event(op=operation_name,
                          message=err_msg_format.format(count, CollectOrReportEventDebugInfo.__MAX_ERRORS_TO_REPORT, ', '.join(errors)),
                          is_success=False)

        report_dropped_events_error(self.__op_error_count, self.__op_errors, self.__op_errors_event)
        report_dropped_events_error(self.__unicode_error_count, self.__unicode_errors, self.__unicode_error_event)

    @staticmethod
    def _update_errors_and_get_count(error_count, errors, error):
        error_count += 1
        if len(errors) < CollectOrReportEventDebugInfo.__MAX_ERRORS_TO_REPORT:
            errors.add("{0}: {1}".format(ustr(error), traceback.format_exc()))
        return error_count

    def update_unicode_error(self, unicode_err):
        self.__unicode_error_count = self._update_errors_and_get_count(self.__unicode_error_count, self.__unicode_errors,
                                                                       unicode_err)

    def update_op_error(self, op_err):
        self.__op_error_count = self._update_errors_and_get_count(self.__op_error_count, self.__op_errors, op_err)

    def get_error_count(self):
        return self.__op_error_count + self.__unicode_error_count


class EventLogger(object):
    def __init__(self):
        self.event_dir = None
        self.periodic_events = {}
        self.protocol = None

        #
        # All events should have these parameters.
        #
        # The first set comes from the current OS and is initialized here. These values don't change during
        # the agent's lifetime.
        #
        # The next two sets come from the goal state and IMDS and must be explicitly initialized using
        # initialize_vminfo_common_parameters() once a protocol for communication with the host has been
        # created. Their values  don't change during the agent's lifetime. Note that we initialize these
        # parameters here using dummy values (*_UNINITIALIZED) since events sent to the host should always
        # match the schema defined for them in the telemetry pipeline.
        #
        # There is another set of common parameters that must be computed at the time the event is created
        # (e.g. the timestamp and the container ID); those are added to events (along with the parameters
        # below) in _add_common_event_parameters()
        #
        # Note that different kinds of events may also include other parameters; those are added by the
        # corresponding add_* method (e.g. add_metric for performance metrics).
        #
        self._common_parameters = []

        # Parameters from OS
        osutil = get_osutil()
        keyword_name = {
            "CpuArchitecture": osutil.get_vm_arch()
        }
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.OSVersion, EventLogger._get_os_version()))
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.ExecutionMode, AGENT_EXECUTION_MODE))
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.RAM, int(EventLogger._get_ram(osutil))))
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.Processors, int(EventLogger._get_processors(osutil))))
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.KeywordName, json.dumps(keyword_name)))

        # Parameters from goal state
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.TenantName, "TenantName_UNINITIALIZED"))
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.RoleName, "RoleName_UNINITIALIZED"))
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.RoleInstanceName, "RoleInstanceName_UNINITIALIZED"))
        #
        # # Parameters from IMDS
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.Location, "Location_UNINITIALIZED"))
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.SubscriptionId, "SubscriptionId_UNINITIALIZED"))
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.ResourceGroupName, "ResourceGroupName_UNINITIALIZED"))
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.VMId, "VMId_UNINITIALIZED"))
        self._common_parameters.append(TelemetryEventParam(CommonTelemetryEventSchema.ImageOrigin, 0))

    @staticmethod
    def _get_os_version():
        return "{0}:{1}-{2}-{3}:{4}".format(platform.system(), DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME, platform.release())

    @staticmethod
    def _get_ram(osutil):
        try:
            return osutil.get_total_mem()
        except OSUtilError as e:
            logger.warn("Failed to get RAM info; will be missing from telemetry: {0}", ustr(e))
        return 0

    @staticmethod
    def _get_processors(osutil):
        try:
            return osutil.get_processor_cores()
        except OSUtilError as e:
            logger.warn("Failed to get Processors info; will be missing from telemetry: {0}", ustr(e))
        return 0

    def initialize_vminfo_common_parameters(self, protocol):
        """
        Initializes the common parameters that come from the goal state and IMDS
        """
        # create an index of the event parameters for faster updates
        parameters = {}
        for p in self._common_parameters:
            parameters[p.name] = p

        try:
            vminfo = protocol.get_vminfo()
            parameters[CommonTelemetryEventSchema.TenantName].value = vminfo.tenantName
            parameters[CommonTelemetryEventSchema.RoleName].value = vminfo.roleName
            parameters[CommonTelemetryEventSchema.RoleInstanceName].value = vminfo.roleInstanceName
        except Exception as e:
            logger.warn("Failed to get VM info from goal state; will be missing from telemetry: {0}", ustr(e))

        try:
            imds_client = get_imds_client()
            imds_info = imds_client.get_compute()
            parameters[CommonTelemetryEventSchema.Location].value = imds_info.location
            parameters[CommonTelemetryEventSchema.SubscriptionId].value = imds_info.subscriptionId
            parameters[CommonTelemetryEventSchema.ResourceGroupName].value = imds_info.resourceGroupName
            parameters[CommonTelemetryEventSchema.VMId].value = imds_info.vmId
            parameters[CommonTelemetryEventSchema.ImageOrigin].value = int(imds_info.image_origin)
        except Exception as e:
            logger.warn("Failed to get IMDS info; will be missing from telemetry: {0}", ustr(e))

    def save_event(self, data):
        if self.event_dir is None:
            logger.warn("Cannot save event -- Event reporter is not initialized.")
            return

        try:
            fileutil.mkdir(self.event_dir, mode=0o700)
        except (IOError, OSError) as e:
            msg = "Failed to create events folder {0}. Error: {1}".format(self.event_dir, ustr(e))
            raise EventError(msg)

        try:
            existing_events = os.listdir(self.event_dir)
            if len(existing_events) >= MAX_NUMBER_OF_EVENTS:
                logger.periodic_warn(logger.EVERY_MINUTE, "[PERIODIC] Too many files under: {0}, current count:  {1}, "
                                                          "removing oldest event files".format(self.event_dir,
                                                                                               len(existing_events)))
                existing_events.sort()
                oldest_files = existing_events[:-999]
                for event_file in oldest_files:
                    os.remove(os.path.join(self.event_dir, event_file))
        except (IOError, OSError) as e:
            msg = "Failed to remove old events from events folder {0}. Error: {1}".format(self.event_dir, ustr(e))
            raise EventError(msg)

        filename = os.path.join(self.event_dir,
                                ustr(int(time.time() * 1000000)))
        try:
            with open(filename + ".tmp", 'wb+') as hfile:
                hfile.write(data.encode("utf-8"))
            os.rename(filename + ".tmp", filename + AGENT_EVENT_FILE_EXTENSION)
        except (IOError, OSError) as e:
            msg = "Failed to write events to file: {0}".format(e)
            raise EventError(msg)

    def reset_periodic(self):
        self.periodic_events = {}

    def is_period_elapsed(self, delta, h):
        return h not in self.periodic_events or \
            (self.periodic_events[h] + delta) <= datetime.now()

    def add_periodic(self, delta, name, op=WALAEventOperation.Unknown, is_success=True, duration=0,
                     version=str(CURRENT_VERSION), message="", log_event=True, force=False):
        h = hash(name + op + ustr(is_success) + message)

        if force or self.is_period_elapsed(delta, h):
            self.add_event(name, op=op, is_success=is_success, duration=duration,
                           version=version, message=message, log_event=log_event)
            self.periodic_events[h] = datetime.now()

    def add_event(self, name, op=WALAEventOperation.Unknown, is_success=True, duration=0, version=str(CURRENT_VERSION),
                  message="", log_event=True, flush=False):
        """
        :param flush: Flush the event immediately to the wire server
        """

        if (not is_success) and log_event:
            _log_event(name, op, message, duration, is_success=is_success)

        event = TelemetryEvent(TELEMETRY_EVENT_EVENT_ID, TELEMETRY_EVENT_PROVIDER_ID)
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Name, str_to_encoded_ustr(name)))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Version, str_to_encoded_ustr(version)))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Operation, str_to_encoded_ustr(op)))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.OperationSuccess, bool(is_success)))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Message, str_to_encoded_ustr(message)))
        event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Duration, int(duration)))
        self.add_common_event_parameters(event, datetime.utcnow())

        self.report_or_save_event(event, flush)

    def add_log_event(self, level, message):
        event = TelemetryEvent(TELEMETRY_LOG_EVENT_ID, TELEMETRY_LOG_PROVIDER_ID)
        event.parameters.append(TelemetryEventParam(GuestAgentGenericLogsSchema.EventName, WALAEventOperation.Log))
        event.parameters.append(TelemetryEventParam(GuestAgentGenericLogsSchema.CapabilityUsed, logger.LogLevel.STRINGS[level]))
        event.parameters.append(TelemetryEventParam(GuestAgentGenericLogsSchema.Context1, str_to_encoded_ustr(self._clean_up_message(message))))
        event.parameters.append(TelemetryEventParam(GuestAgentGenericLogsSchema.Context2, datetime.utcnow().strftime(logger.Logger.LogTimeFormatInUTC)))
        event.parameters.append(TelemetryEventParam(GuestAgentGenericLogsSchema.Context3, ''))
        self.add_common_event_parameters(event, datetime.utcnow())

        self.report_or_save_event(event)

    def add_metric(self, category, counter, instance, value, log_event=False):
        """
        Create and save an event which contains a telemetry event.

        :param str category: The category of metric (e.g. "cpu", "memory")
        :param str counter: The specific metric within the category (e.g. "%idle")
        :param str instance: For instanced metrics, the instance identifier (filesystem name, cpu core#, etc.)
        :param value: Value of the metric
        :param bool log_event: If true, log the collected metric in the agent log
        :param immediate_flush: If true, flush the event to wireserver immediately
        """
        if log_event:
            message = "Metric {0}/{1} [{2}] = {3}".format(category, counter, instance, value)
            _log_event(AGENT_NAME, "METRIC", message, 0)

        event = TelemetryEvent(TELEMETRY_METRICS_EVENT_ID, TELEMETRY_EVENT_PROVIDER_ID)
        event.parameters.append(TelemetryEventParam(GuestAgentPerfCounterEventsSchema.Category, str_to_encoded_ustr(category)))
        event.parameters.append(TelemetryEventParam(GuestAgentPerfCounterEventsSchema.Counter, str_to_encoded_ustr(counter)))
        event.parameters.append(TelemetryEventParam(GuestAgentPerfCounterEventsSchema.Instance, str_to_encoded_ustr(instance)))
        event.parameters.append(TelemetryEventParam(GuestAgentPerfCounterEventsSchema.Value, float(value)))
        self.add_common_event_parameters(event, datetime.utcnow())

        self.report_or_save_event(event)

    def report_or_save_event(self, event, flush=False):
        """
        Flush the event to wireserver if flush to set to true, else
        save it disk if we fail to send or not required to flush immediately.
        TODO: pickup as many events as possible and send them in one go.
        """
        report_success = False
        if flush and self.protocol is not None:
            report_success = self.protocol.report_event([event], flush)

        if not report_success:
            try:
                data = get_properties(event)
                self.save_event(json.dumps(data))
            except EventError as e:
                logger.periodic_error(logger.EVERY_FIFTEEN_MINUTES, "[PERIODIC] {0}".format(ustr(e)))


    @staticmethod
    def _clean_up_message(message):
        # By the time the message has gotten to this point it is formatted as
        #
        #   Old Time format
        #   YYYY/MM/DD HH:mm:ss.fffffff LEVEL <text>.
        #   YYYY/MM/DD HH:mm:ss.fffffff <text>.
        #   YYYY/MM/DD HH:mm:ss LEVEL <text>.
        #   YYYY/MM/DD HH:mm:ss <text>.
        #
        #   UTC ISO Time format added in #1716
        #   YYYY-MM-DDTHH:mm:ss.fffffffZ LEVEL <text>.
        #   YYYY-MM-DDTHH:mm:ss.fffffffZ <text>.
        #   YYYY-MM-DDTHH:mm:ssZ LEVEL <text>.
        #   YYYY-MM-DDTHH:mm:ssZ <text>.
        #
        # The timestamp and the level are redundant, and should be stripped. The logging library does not schematize
        # this data, so I am forced to parse the message using a regex.  The format is regular, so the burden is low,
        # and usability on the telemetry side is high.

        if not message:
            return message

        # Adding two regexs to simplify the handling of logs and to keep it maintainable. Most of the logs would have
        # level includent in the log itself, but if it doesn't have, the second regex is a catch all case and will work
        # for all the cases.
        log_level_format_parser = re.compile(r"^.*(INFO|WARNING|ERROR|VERBOSE)\s*(.*)$")
        log_format_parser = re.compile(r"^[0-9:/\-TZ\s.]*\s(.*)$")

        # Parsing the log messages containing levels in it
        extract_level_message = log_level_format_parser.search(message)
        if extract_level_message:
            return extract_level_message.group(2)  # The message bit
        else:
            # Parsing the log messages without levels in it.
            extract_message = log_format_parser.search(message)
            if extract_message:
                return extract_message.group(1)  # The message bit
            else:
                return message

    def add_common_event_parameters(self, event, event_timestamp):
        """
        This method is called for all events and ensures all telemetry fields are added before the event is sent out.
        Note that the event timestamp is saved in the OpcodeName field.
        """
        common_params = [TelemetryEventParam(CommonTelemetryEventSchema.GAVersion, CURRENT_AGENT),
                         TelemetryEventParam(CommonTelemetryEventSchema.ContainerId, AgentGlobals.get_container_id()),
                         TelemetryEventParam(CommonTelemetryEventSchema.OpcodeName, event_timestamp.strftime(logger.Logger.LogTimeFormatInUTC)),
                         TelemetryEventParam(CommonTelemetryEventSchema.EventTid, threading.current_thread().ident),
                         TelemetryEventParam(CommonTelemetryEventSchema.EventPid, os.getpid()),
                         TelemetryEventParam(CommonTelemetryEventSchema.TaskName, threading.current_thread().name)]

        if event.eventId == TELEMETRY_EVENT_EVENT_ID and event.providerId == TELEMETRY_EVENT_PROVIDER_ID:
            # Currently only the GuestAgentExtensionEvents has these columns, the other tables dont have them so skipping
            # this data in those tables.
            common_params.extend([TelemetryEventParam(GuestAgentExtensionEventsSchema.ExtensionType, event.file_type),
                         TelemetryEventParam(GuestAgentExtensionEventsSchema.IsInternal, False)]) 

        event.parameters.extend(common_params)
        event.parameters.extend(self._common_parameters)


__event_logger__ = EventLogger()

def get_event_logger():
    return __event_logger__


def elapsed_milliseconds(utc_start):
    now = datetime.utcnow()
    if now < utc_start:
        return 0

    d = now - utc_start
    return int(((d.days * 24 * 60 * 60 + d.seconds) * 1000) + \
                    (d.microseconds / 1000.0))


def report_event(op, is_success=True, message='', log_event=True, flush=False):
    """
    :param flush: if true, flush the event immediately to the wire server
    """
    add_event(AGENT_NAME,
              version=str(CURRENT_VERSION),
              is_success=is_success,
              message=message,
              op=op,
              log_event=log_event, flush=flush)


def report_periodic(delta, op, is_success=True, message=''):
    add_periodic(delta, AGENT_NAME,
                 version=str(CURRENT_VERSION),
                 is_success=is_success,
                 message=message,
                 op=op)


def report_metric(category, counter, instance, value, log_event=False, reporter=__event_logger__):
    """
    Send a telemetry event reporting a single instance of a performance counter.
    :param str category: The category of the metric (cpu, memory, etc)
    :param str counter: The name of the metric ("%idle", etc)
    :param str instance: For instanced metrics, the identifier of the instance. E.g. a disk drive name, a cpu core#
    :param     value: The value of the metric
    :param bool log_event: If True, log the metric in the agent log as well
    :param EventLogger reporter: The EventLogger instance to which metric events should be sent
    """
    if reporter.event_dir is None:
        logger.warn("Cannot report metric event -- Event reporter is not initialized.")
        message = "Metric {0}/{1} [{2}] = {3}".format(category, counter, instance, value)
        _log_event(AGENT_NAME, "METRIC", message, 0)
        return
    try:
        reporter.add_metric(category, counter, instance, float(value), log_event)
    except ValueError:
        logger.periodic_warn(logger.EVERY_HALF_HOUR, "[PERIODIC] Cannot cast the metric value. Details of the Metric - "
                                                     "{0}/{1} [{2}] = {3}".format(category, counter, instance, value))


def initialize_event_logger_vminfo_common_parameters_and_protocol(protocol, reporter=__event_logger__):
    # Initialize protocal for event logger to directly send events to wireserver
    reporter.protocol = protocol
    reporter.initialize_vminfo_common_parameters(protocol)


def add_event(name=AGENT_NAME, op=WALAEventOperation.Unknown, is_success=True, duration=0, version=str(CURRENT_VERSION),
              message="", log_event=True, flush=False, reporter=__event_logger__):
    """
    :param flush: if true, flush the event immediately to the wire server
    """
    if reporter.event_dir is None:
        logger.warn("Cannot add event -- Event reporter is not initialized.")
        _log_event(name, op, message, duration, is_success=is_success)
        return

    if should_emit_event(name, version, op, is_success):
        mark_event_status(name, version, op, is_success)
        reporter.add_event(name, op=op, is_success=is_success, duration=duration, version=str(version),
                           message=message,
                           log_event=log_event, flush=flush)


def add_log_event(level, message, forced=False, reporter=__event_logger__):
    """
    :param level: LoggerLevel of the log event
    :param message: Message
    :param forced: Force write the event even if send_logs_to_telemetry() is disabled
        (NOTE: Remove this flag once send_logs_to_telemetry() is enabled for all events)
    :param reporter: The EventLogger instance to which metric events should be sent
    :return:
    """
    if reporter.event_dir is None:
        return

    if not (forced or send_logs_to_telemetry()):
        return

    if level >= logger.LogLevel.WARNING:
        reporter.add_log_event(level, message)


def add_periodic(delta, name, op=WALAEventOperation.Unknown, is_success=True, duration=0, version=str(CURRENT_VERSION),
                 message="", log_event=True, force=False, reporter=__event_logger__):
    if reporter.event_dir is None:
        logger.warn("Cannot add periodic event -- Event reporter is not initialized.")
        _log_event(name, op, message, duration, is_success=is_success)
        return

    reporter.add_periodic(delta, name, op=op, is_success=is_success, duration=duration, version=str(version),
                          message=message, log_event=log_event, force=force)


def mark_event_status(name, version, op, status):
    if op in __event_status_operations__:
        __event_status__.mark_event_status(name, version, op, status)


def should_emit_event(name, version, op, status):
    return \
        op not in __event_status_operations__ or \
        __event_status__ is None or \
        not __event_status__.event_marked(name, version, op) or \
        __event_status__.event_succeeded(name, version, op) != status


def init_event_logger(event_dir):
    __event_logger__.event_dir = event_dir


def init_event_status(status_dir):
    __event_status__.initialize(status_dir)


def dump_unhandled_err(name):
    if hasattr(sys, 'last_type') and hasattr(sys, 'last_value') and \
            hasattr(sys, 'last_traceback'):
        last_type = getattr(sys, 'last_type')
        last_value = getattr(sys, 'last_value')
        last_traceback = getattr(sys, 'last_traceback')
        error = traceback.format_exception(last_type, last_value,
                                           last_traceback)
        message = "".join(error)
        add_event(name, is_success=False, message=message,
                  op=WALAEventOperation.UnhandledError)


def enable_unhandled_err_dump(name):
    atexit.register(dump_unhandled_err, name)
