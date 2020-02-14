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
import re
import sys
import threading
import time
import traceback
from datetime import datetime

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.exception import EventError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.datacontract import get_properties, set_properties
from azurelinuxagent.common.sysinfo import SysInfo
from azurelinuxagent.common.telemetryevent import TelemetryEventParam, TelemetryEvent
from azurelinuxagent.common.utils import fileutil, textutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, getattrib
from azurelinuxagent.common.version import CURRENT_VERSION, CURRENT_AGENT

EVENTS_DIRECTORY = "waagent.events"
LEGACY_EVENTS_DIRECTORY = "events"

_EVENT_MSG = "Event: name={0}, op={1}, message={2}, duration={3}"
TELEMETRY_EVENT_PROVIDER_ID = "69B669B9-4AF8-4C50-BDC4-6006FA76E975"
TELEMETRY_METRICS_EVENT_ID = 4

# Store the last retrieved container id as an environment variable to be shared between threads for telemetry purposes
CONTAINER_ID_ENV_VARIABLE = "AZURE_GUEST_AGENT_CONTAINER_ID"

TELEMETRY_LOG_PROVIDER_ID = "FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F"
TELEMETRY_LOG_EVENT_ID = 7

#
# When this flag is enabled the TODO comment in Logger.log() needs to be addressed; also the tests
# marked with "Enable this test when SEND_LOGS_TO_TELEMETRY is enabled" should be enabled.
#
SEND_LOGS_TO_TELEMETRY = False

MAX_NUMBER_OF_EVENTS = 1000

EVENT_FILE_EXTENSION = ".tld"


def send_logs_to_telemetry():
    return SEND_LOGS_TO_TELEMETRY


def get_container_id_from_env():
    return os.environ.get(CONTAINER_ID_ENV_VARIABLE, "UNINITIALIZED")


class WALAEventOperation:
    ActivateResourceDisk = "ActivateResourceDisk"
    AgentBlacklisted = "AgentBlacklisted"
    AgentEnabled = "AgentEnabled"
    ArtifactsProfileBlob = "ArtifactsProfileBlob"
    AutoUpdate = "AutoUpdate"
    CustomData = "CustomData"
    CGroupsCleanUp = "CGroupsCleanUp"
    CGroupsLimitsCrossed = "CGroupsLimitsCrossed"
    ExtensionMetricsData = "ExtensionMetricsData"
    Deploy = "Deploy"
    Disable = "Disable"
    Downgrade = "Downgrade"
    Download = "Download"
    Enable = "Enable"
    ExtensionProcessing = "ExtensionProcessing"
    FetchGoalState = "FetchGoalState"
    Firewall = "Firewall"
    GetArtifactExtended = "GetArtifactExtended"
    HealthCheck = "HealthCheck"
    HealthObservation = "HealthObservation"
    HeartBeat = "HeartBeat"
    HostPlugin = "HostPlugin"
    HostPluginHeartbeat = "HostPluginHeartbeat"
    HostPluginHeartbeatExtended = "HostPluginHeartbeatExtended"
    HttpErrors = "HttpErrors"
    ImdsHeartbeat = "ImdsHeartbeat"
    Install = "Install"
    InitializeCGroups = "InitializeCGroups"
    InitializeHostPlugin = "InitializeHostPlugin"
    InvokeCommandUsingSystemd = "InvokeCommandUsingSystemd"
    Log = "Log"
    OSInfo = "OSInfo"
    Partition = "Partition"
    ProcessGoalState = "ProcessGoalState"
    Provision = "Provision"
    ProvisionGuestAgent = "ProvisionGuestAgent"
    RemoteAccessHandling = "RemoteAccessHandling"
    ReportStatus = "ReportStatus"
    ReportStatusExtended = "ReportStatusExtended"
    Restart = "Restart"
    SequenceNumberMismatch = "SequenceNumberMismatch"
    SetCGroupsLimits = "SetCGroupsLimits"
    SkipUpdate = "SkipUpdate"
    UnhandledError = "UnhandledError"
    UnInstall = "UnInstall"
    Unknown = "Unknown"
    Upgrade = "Upgrade"
    Update = "Update"


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
        WALAEventOperation.AutoUpdate,
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
    global _EVENT_MSG

    message = _encode_message(op, message)
    if not is_success:
        logger.error(_EVENT_MSG, name, op, message, duration)
    else:
        logger.info(_EVENT_MSG, name, op, message, duration)


class EventLogger(object):
    def __init__(self):
        self.event_dir = None
        self.periodic_events = {}

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
            os.rename(filename + ".tmp", filename + EVENT_FILE_EXTENSION)
        except (IOError, OSError) as e:
            msg = "Failed to write events to file: {0}".format(e)
            raise EventError(msg)

    @staticmethod
    def collect_event_str(evt_file_name):
        try:
            logger.verbose("Found event file: {0}", evt_file_name)
            with open(evt_file_name, "rb") as evt_file:
                data_str = evt_file.read().decode("utf-8")
            logger.verbose("Processed event file: {0}", evt_file_name)
            return data_str
        except (IOError, OSError, UnicodeDecodeError) as e:
            msg = "Failed to process {0}, {1}".format(evt_file_name, e)
            raise EventError(msg)
        finally:
            os.remove(evt_file_name)

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
                  message="", log_event=True):

        if (not is_success) and log_event:
            _log_event(name, op, message, duration, is_success=is_success)

        self._add_event(duration, is_success, message, name, op, version, event_id=1)

    def _add_event(self, duration, is_success, message, name, op, version, event_id):
        event = TelemetryEvent(event_id, TELEMETRY_EVENT_PROVIDER_ID)

        event.parameters.append(TelemetryEventParam('Name', str(name)))
        event.parameters.append(TelemetryEventParam('Version', str(version)))
        event.parameters.append(TelemetryEventParam('Operation', str(op)))
        event.parameters.append(TelemetryEventParam('OperationSuccess', bool(is_success)))
        event.parameters.append(TelemetryEventParam('Message', str(message)))
        event.parameters.append(TelemetryEventParam('Duration', int(duration)))
        event_creation_time = datetime.utcnow().strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')

        self.finalize_event_fields(event, event_creation_time)
        data = get_properties(event)
        try:
            self.save_event(json.dumps(data))
        except EventError as e:
            logger.periodic_error(logger.EVERY_FIFTEEN_MINUTES, "[PERIODIC] {0}".format(ustr(e)))

    def add_log_event(self, level, message):
        event = TelemetryEvent(TELEMETRY_LOG_EVENT_ID, TELEMETRY_LOG_PROVIDER_ID)
        event.parameters.append(TelemetryEventParam('EventName', WALAEventOperation.Log))
        event.parameters.append(TelemetryEventParam('CapabilityUsed', logger.LogLevel.STRINGS[level]))
        event.parameters.append(TelemetryEventParam('Context1', self._clean_up_message(message)))
        event.parameters.append(TelemetryEventParam('Context2', ''))
        event.parameters.append(TelemetryEventParam('Context3', ''))
        event_creation_time = datetime.utcnow().strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')

        self.finalize_event_fields(event, event_creation_time)
        data = get_properties(event)
        try:
            self.save_event(json.dumps(data))
        except EventError:
            pass

    def add_metric(self, category, counter, instance, value, log_event=False):
        """
        Create and save an event which contains a telemetry event.

        :param str category: The category of metric (e.g. "cpu", "memory")
        :param str counter: The specific metric within the category (e.g. "%idle")
        :param str instance: For instanced metrics, the instance identifier (filesystem name, cpu core#, etc.)
        :param value: Value of the metric
        :param bool log_event: If true, log the collected metric in the agent log
        """
        if log_event:
            from azurelinuxagent.common.version import AGENT_NAME
            message = "Metric {0}/{1} [{2}] = {3}".format(category, counter, instance, value)
            _log_event(AGENT_NAME, "METRIC", message, 0)

        event = TelemetryEvent(TELEMETRY_METRICS_EVENT_ID, TELEMETRY_EVENT_PROVIDER_ID)
        event.parameters.append(TelemetryEventParam('Category', str(category)))
        event.parameters.append(TelemetryEventParam('Counter', str(counter)))
        event.parameters.append(TelemetryEventParam('Instance', str(instance)))
        event.parameters.append(TelemetryEventParam('Value', float(value)))
        event_creation_time = datetime.utcnow().strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')

        self.finalize_event_fields(event, event_creation_time)
        data = get_properties(event)
        try:
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

    @staticmethod
    def finalize_event_fields(event, event_creation_time):
        """
        This method is called for all events and ensures all telemetry fields are added before the event is sent out.
        For agent events, the fields are finalized during event creation, and before saving to disk. For extension
        events, this is called when the events are read from disk, and before they are sent out.
        :param event: Event to be finalized.
        :param event_creation_time: Creation time of the event, a datetime object.
        :param sysinfo: Sysinfo object containing sysinfo-related telemetry parameters.
        :return: Finalized event with all telemetry fields.
        """
        EventLogger._add_common_parameters_to_event(event, event_creation_time)
        EventLogger._add_sysinfo_parameters_to_event(event)

    @staticmethod
    def trim_extension_event_parameters(event):
        """
        This method is called for extension events before they are sent out. Per the agreement with extension
        publishers, the parameters that belong to extensions and will be reported intact are Name, Version, Operation,
        OperationSuccess, Message, and Duration. Since there is nothing preventing extensions to instantiate other
        fields (which belong to the agent), we call this method to ensure the rest of the parameters are trimmed since
        they will be replaced with values coming from the agent.
        :param event: Extension event to trim.
        :return: Trimmed extension event; containing only extension-specific parameters.
        """
        params_to_keep = dict().fromkeys(['Name', 'Version', 'Operation', 'OperationSuccess', 'Message', 'Duration'])
        trimmed_params = []

        for param in event.parameters:
            if param.name in params_to_keep:
                trimmed_params.append(param)

        event.parameters = trimmed_params

    @staticmethod
    def _add_common_parameters_to_event(event, event_creation_time):
        """
        This method adds a group of telemetry parameters to an existing event. These parameters are common to all
        events being sent out. The common parameters are GAVersion, ContainerId, OpcodeName, EventTid, EventPid,
        TaskName, KeywordName, ExtensionType, and IsInternal and are populated from the agent.

        For agent events, this method is called during event creation and before the event is saved to disk. By doing
        this at event-creation time, we ensure the GAVersion and ContainerId values are real-time.
        For extension events, this method is called during reading of the events from the events folder on disk and
        before reporting it.

        :param event: Event which parameters will be expanded with parameters common to all events being sent out.
        :param event_creation_time: The time the event was created.
        :return: Event containing the expanded list of telemetry parameters.
        """
        common_params = [TelemetryEventParam('GAVersion', CURRENT_AGENT),
                         TelemetryEventParam('ContainerId', get_container_id_from_env()),
                         TelemetryEventParam('OpcodeName', str(event_creation_time)),
                         TelemetryEventParam('EventTid', threading.current_thread().ident),
                         TelemetryEventParam('EventPid', os.getpid()),
                         TelemetryEventParam('TaskName', threading.current_thread().getName()),
                         TelemetryEventParam('KeywordName', ''),
                         TelemetryEventParam('ExtensionType', event.file_type),
                         TelemetryEventParam('IsInternal', False)]

        event.parameters.extend(common_params)

    @staticmethod
    def _add_sysinfo_parameters_to_event(event):
        sysinfo = SysInfo.get_instance()
        sysinfo_params = sysinfo.get_sysinfo_telemetry_params()
        event.parameters.extend(sysinfo_params)

    @staticmethod
    def update_old_daemon_events_on_disk(event_dir):
        """
        Since WALinuxAgent-2.2.47, the agent events' schema is finalized before the event is saved to disk. This means
        that once the events are collected and sent, there is no post-processing needed. Before 2.2.47, sysinfo
        params and some common fields would be added only after the event is read from disk and before it's reported.
        This means that old agent events (<2.2.47) would be saved to disk with an incomplete schema.

        This method completes the agent event schema and is called only once, during extension handler start up, to
        ensure any remaining fields in the events folder that are still not sent are up to date with the schema.
        :param event_dir: Directory with events on disk.
        :return: Does not return, updates the event file on disk instead.
        """
        try:
            event_files = os.listdir(event_dir)

            for event_file in event_files:
                try:
                    if not event_file.endswith(EVENT_FILE_EXTENSION):
                        continue

                    event_file_path = os.path.join(event_dir, event_file)
                    data_str = fileutil.read_file(event_file_path)

                    event = parse_event(data_str)
                    if event.is_extension_event() or FlexibleVersion(event.get_version()) >= FlexibleVersion("2.2.47"):
                        continue

                    # The event filename is <epoch_time>.tld. The factor 1000000 is defined in save_event.
                    epoch_time = float(event_file[:-4]) / 1000000.0
                    event_creation_time = datetime.fromtimestamp(epoch_time).strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')
                    EventLogger._update_old_event_schema(event, event_creation_time)

                    data = get_properties(event)
                    fileutil.write_file(event_file_path, json.dumps(data))
                except Exception as e:
                    logger.error("Failed to process old event {0}, {1}".format(event_file, ustr(e)))
                    continue
        except Exception as e:
            logger.error("Failed to update the telemetry schema of old daemon events on disk: {0}".format(ustr(e)))

    @staticmethod
    def _update_old_event_schema(event, event_creation_time):
        # Ensure that if an agent event is missing a field from the schema defined since 2.2.47, the missing fields
        # will be appended, ensuring the event schema is complete before the event is reported.
        new_event = TelemetryEvent()
        new_event.parameters = []
        EventLogger.finalize_event_fields(new_event, event_creation_time)

        event_params = dict([(param.name, param.value) for param in event.parameters])
        new_event_params = dict([(param.name, param.value) for param in new_event.parameters])

        missing_params = set(new_event_params.keys()).difference(set(event_params.keys()))
        params_to_add = []
        for param_name in missing_params:
            params_to_add.append(TelemetryEventParam(param_name, new_event_params[param_name]))

        event.parameters.extend(params_to_add)


__event_logger__ = EventLogger()


def elapsed_milliseconds(utc_start):
    now = datetime.utcnow()
    if now < utc_start:
        return 0

    d = now - utc_start
    return int(((d.days * 24 * 60 * 60 + d.seconds) * 1000) + \
                    (d.microseconds / 1000.0))


def report_event(op, is_success=True, message='', log_event=True):
    from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
    add_event(AGENT_NAME,
              version=str(CURRENT_VERSION),
              is_success=is_success,
              message=message,
              op=op,
              log_event=log_event)


def report_periodic(delta, op, is_success=True, message=''):
    from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
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
        from azurelinuxagent.common.version import AGENT_NAME
        logger.warn("Cannot report metric event -- Event reporter is not initialized.")
        message = "Metric {0}/{1} [{2}] = {3}".format(category, counter, instance, value)
        _log_event(AGENT_NAME, "METRIC", message, 0)
        return
    try:
        reporter.add_metric(category, counter, instance, float(value), log_event)
    except ValueError:
        logger.periodic_warn(logger.EVERY_HALF_HOUR, "[PERIODIC] Cannot cast the metric value. Details of the Metric - "
                                                     "{0}/{1} [{2}] = {3}".format(category, counter, instance, value))


def add_event(name, op=WALAEventOperation.Unknown, is_success=True, duration=0, version=str(CURRENT_VERSION),
              message="", log_event=True, reporter=__event_logger__):
    if reporter.event_dir is None:
        logger.warn("Cannot add event -- Event reporter is not initialized.")
        _log_event(name, op, message, duration, is_success=is_success)
        return

    if should_emit_event(name, version, op, is_success):
        mark_event_status(name, version, op, is_success)
        reporter.add_event(name, op=op, is_success=is_success, duration=duration, version=str(version), message=message,
                           log_event=log_event)


def add_log_event(level, message, reporter=__event_logger__):
    """
    :param level: LoggerLevel of the log event
    :param message: Message
    :param reporter:
    :return:
    """
    if reporter.event_dir is None:
        return

    if not send_logs_to_telemetry():
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
