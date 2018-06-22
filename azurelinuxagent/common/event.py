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
import datetime
import json
import os
import sys
import time
import traceback

from datetime import datetime

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.exception import EventError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import TelemetryEventParam, \
    TelemetryEvent, \
    get_properties
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.version import CURRENT_VERSION

_EVENT_MSG = "Event: name={0}, op={1}, message={2}, duration={3}"


class WALAEventOperation:
    ActivateResourceDisk = "ActivateResourceDisk"
    AgentBlacklisted = "AgentBlacklisted"
    AgentEnabled = "AgentEnabled"
    ArtifactsProfileBlob = "ArtifactsProfileBlob"
    AutoUpdate = "AutoUpdate"
    CustomData = "CustomData"
    Deploy = "Deploy"
    Disable = "Disable"
    Downgrade = "Downgrade"
    Download = "Download"
    Enable = "Enable"
    ExtensionProcessing = "ExtensionProcessing"
    Firewall = "Firewall"
    GetArtifactExtended = "GetArtifactExtended"
    HealthCheck = "HealthCheck"
    HeartBeat = "HeartBeat"
    HostPlugin = "HostPlugin"
    HostPluginHeartbeat = "HostPluginHeartbeat"
    HttpErrors = "HttpErrors"
    ImdsHeartbeat = "ImdsHeartbeat"
    Install = "Install"
    InitializeCGroups = "InitializeCGroups"
    InitializeHostPlugin = "InitializeHostPlugin"
    Log = "Log"
    Partition = "Partition"
    ProcessGoalState = "ProcessGoalState"
    Provision = "Provision"
    ProvisionGuestAgent = "ProvisionGuestAgent"
    RemoteAccessHandling = "RemoteAccessHandling"
    ReportStatus = "ReportStatus"
    ReportStatusExtended = "ReportStatusExtended"
    Restart = "Restart"
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

        if not os.path.exists(self.event_dir):
            os.mkdir(self.event_dir)
            os.chmod(self.event_dir, 0o700)

        existing_events = os.listdir(self.event_dir)
        if len(existing_events) >= 1000:
            existing_events.sort()
            oldest_files = existing_events[:-999]
            logger.warn("Too many files under: {0}, removing oldest".format(self.event_dir))
            try:
                for f in oldest_files:
                    os.remove(os.path.join(self.event_dir, f))
            except IOError as e:
                raise EventError(e)

        filename = os.path.join(self.event_dir,
                                ustr(int(time.time() * 1000000)))
        try:
            with open(filename + ".tmp", 'wb+') as hfile:
                hfile.write(data.encode("utf-8"))
            os.rename(filename + ".tmp", filename + ".tld")
        except IOError as e:
            raise EventError("Failed to write events to file:{0}", e)

    def reset_periodic(self):
        self.periodic_events = {}

    def is_period_elapsed(self, delta, h):
        return h not in self.periodic_events or \
            (self.periodic_events[h] + delta) <= datetime.now()

    def add_periodic(self,
        delta, name, op=WALAEventOperation.Unknown, is_success=True, duration=0,
        version=CURRENT_VERSION, message="", evt_type="",
        is_internal=False, log_event=True, force=False):

        h = hash(name+op+ustr(is_success)+message)
        
        if force or self.is_period_elapsed(delta, h):
            self.add_event(name,
                op=op, is_success=is_success, duration=duration,
                version=version, message=message, evt_type=evt_type,
                is_internal=is_internal, log_event=log_event)
            self.periodic_events[h] = datetime.now()

    def add_event(self,
                  name,
                  op=WALAEventOperation.Unknown,
                  is_success=True,
                  duration=0,
                  version=CURRENT_VERSION,
                  message="",
                  evt_type="",
                  is_internal=False,
                  log_event=True):

        if (not is_success) and log_event:
            _log_event(name, op, message, duration, is_success=is_success)

        self._add_event(duration, evt_type, is_internal, is_success, message, name, op, version, eventId=1)
        self._add_event(duration, evt_type, is_internal, is_success, message, name, op, version, eventId=6)

    def _add_event(self, duration, evt_type, is_internal, is_success, message, name, op, version, eventId):
        event = TelemetryEvent(eventId, "69B669B9-4AF8-4C50-BDC4-6006FA76E975")
        event.parameters.append(TelemetryEventParam('Name', name))
        event.parameters.append(TelemetryEventParam('Version', str(version)))
        event.parameters.append(TelemetryEventParam('IsInternal', is_internal))
        event.parameters.append(TelemetryEventParam('Operation', op))
        event.parameters.append(TelemetryEventParam('OperationSuccess',
                                                    is_success))
        event.parameters.append(TelemetryEventParam('Message', message))
        event.parameters.append(TelemetryEventParam('Duration', duration))
        event.parameters.append(TelemetryEventParam('ExtensionType', evt_type))

        data = get_properties(event)
        try:
            self.save_event(json.dumps(data))
        except EventError as e:
            logger.error("{0}", e)

    def add_log_event(self, level, message):
        # By the time the message has gotten to this point it is formatted as
        #
        #   YYYY/MM/DD HH:mm:ss.fffffff LEVEL <text>.
        #
        # The timestamp and the level are redundant, and should be stripped.
        # The logging library does not schematize this data, so I am forced
        # to parse the message.  The format is regular, so the burden is low.

        parts = message.split(' ', 3)
        msg = parts[3] if len(parts) == 4 \
            else message

        event = TelemetryEvent(7, "FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F")
        event.parameters.append(TelemetryEventParam('EventName', WALAEventOperation.Log))
        event.parameters.append(TelemetryEventParam('CapabilityUsed', logger.LogLevel.STRINGS[level]))
        event.parameters.append(TelemetryEventParam('Context1', msg))
        event.parameters.append(TelemetryEventParam('Context2', ''))
        event.parameters.append(TelemetryEventParam('Context3', ''))

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

        event = TelemetryEvent(4, "69B669B9-4AF8-4C50-BDC4-6006FA76E975")
        event.parameters.append(TelemetryEventParam('Category', category))
        event.parameters.append(TelemetryEventParam('Counter', counter))
        event.parameters.append(TelemetryEventParam('Instance', instance))
        event.parameters.append(TelemetryEventParam('Value', value))

        data = get_properties(event)
        try:
            self.save_event(json.dumps(data))
        except EventError as e:
            logger.error("{0}", e)


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
              version=CURRENT_VERSION,
              is_success=is_success,
              message=message,
              op=op,
              log_event=log_event)


def report_periodic(delta, op, is_success=True, message=''):
    from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
    add_periodic(delta, AGENT_NAME,
              version=CURRENT_VERSION,
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
    reporter.add_metric(category, counter, instance, value, log_event)


def add_event(name, op=WALAEventOperation.Unknown, is_success=True, duration=0,
              version=CURRENT_VERSION,
              message="", evt_type="", is_internal=False, log_event=True,
              reporter=__event_logger__):
    if reporter.event_dir is None:
        logger.warn("Cannot add event -- Event reporter is not initialized.")
        _log_event(name, op, message, duration, is_success=is_success)
        return

    if should_emit_event(name, version, op, is_success):
        mark_event_status(name, version, op, is_success)
        reporter.add_event(
            name, op=op, is_success=is_success, duration=duration,
            version=str(version), message=message, evt_type=evt_type,
            is_internal=is_internal, log_event=log_event)


def add_log_event(level, message, reporter=__event_logger__):
    if reporter.event_dir is None:
        return

    reporter.add_log_event(level, message)


def add_periodic(
    delta, name, op=WALAEventOperation.Unknown, is_success=True, duration=0,
    version=CURRENT_VERSION,
    message="", evt_type="", is_internal=False, log_event=True, force=False,
    reporter=__event_logger__):
    if reporter.event_dir is None:
        logger.warn("Cannot add periodic event -- Event reporter is not initialized.")
        _log_event(name, op, message, duration, is_success=is_success)
        return

    reporter.add_periodic(
        delta, name, op=op, is_success=is_success, duration=duration,
        version=str(version), message=message, evt_type=evt_type,
        is_internal=is_internal, log_event=log_event, force=force)


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
