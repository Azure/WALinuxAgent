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

import os
import sys
import traceback
import atexit
import json
import time
import datetime
import threading
import platform

from datetime import datetime, timedelta

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.exception import EventError, ProtocolError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import TelemetryEventParam, \
    TelemetryEventList, \
    TelemetryEvent, \
    set_properties, get_properties
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, \
    DISTRO_CODE_NAME, AGENT_VERSION, \
    CURRENT_AGENT, CURRENT_VERSION

_EVENT_MSG = "Event: name={0}, op={1}, message={2}"

class WALAEventOperation:
    ActivateResourceDisk = "ActivateResourceDisk"
    AutoUpdate = "AutoUpdate"
    Disable = "Disable"
    Download = "Download"
    Enable = "Enable"
    HealthCheck = "HealthCheck"
    HeartBeat = "HeartBeat"
    HostPlugin = "HostPlugin"
    Install = "Install"
    InitializeHostPlugin = "InitializeHostPlugin"
    ProcessGoalState = "ProcessGoalState"
    Provision = "Provision"
    ReportStatus = "ReportStatus"
    Restart = "Restart"
    UnhandledError = "UnhandledError"
    UnInstall = "UnInstall"
    Upgrade = "Upgrade"
    Update = "Update"


class EventStatus(object):
    EVENT_STATUS_FILE = "event_status.json"

    def __init__(self, status_dir=conf.get_lib_dir()):
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
        return self._status[event] == True

    def initialize(self, status_dir=conf.get_lib_dir()):
        self._path = os.path.join(status_dir, EventStatus.EVENT_STATUS_FILE)
        self._load()

    def mark_event_status(self, name, version, op, status):
        event = self._event_name(name, version, op)
        self._status[event] = (status == True)
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

def _log_event(name, op, message, is_success=True):
    global _EVENT_MSG

    if not is_success:
        logger.error(_EVENT_MSG, name, op, message)
    else:
        logger.info(_EVENT_MSG, name, op, message)


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
        self.periodic_messages = {}

    def is_period_elapsed(self, delta, h):
        return h not in self.periodic_messages or \
            (self.periodic_messages[h] + delta) <= datetime.now()

    def add_periodic(self,
        delta, name, op="", is_success=True, duration=0,
        version=CURRENT_VERSION, message="", evt_type="",
        is_internal=False, log_event=True, force=False):

        h = hash(name+op+ustr(is_success)+message)
        
        if force or self.is_period_elapsed(delta, h):
            self.add_event(name,
                op=op, is_success=is_success, duration=duration,
                version=version, message=message, evt_type=evt_type,
                is_internal=is_internal, log_event=log_event)
            self.periodic_messages[h] = datetime.now()

    def add_event(self, name, op="", is_success=True, duration=0,
                  version=CURRENT_VERSION,
                  message="", evt_type="", is_internal=False, log_event=True):
        if not is_success or log_event:
            _log_event(name, op, message, is_success=is_success)

        event = TelemetryEvent(1, "69B669B9-4AF8-4C50-BDC4-6006FA76E975")
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


__event_logger__ = EventLogger()


def elapsed_milliseconds(utc_start):
    d = datetime.utcnow() - utc_start
    return int(((d.days * 24 * 60 * 60 + d.seconds) * 1000) + \
                    (d.microseconds / 1000.0))

def report_event(op, is_success=True, message=''):
    from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
    add_event(AGENT_NAME,
              version=CURRENT_VERSION,
              is_success=is_success,
              message=message,
              op=op)

def report_periodic(delta, op, is_success=True, message=''):
    from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
    add_periodic(delta, AGENT_NAME,
              version=CURRENT_VERSION,
              is_success=is_success,
              message=message,
              op=op)

def add_event(name, op="", is_success=True, duration=0, version=CURRENT_VERSION,
              message="", evt_type="", is_internal=False, log_event=True,
              reporter=__event_logger__):
    if reporter.event_dir is None:
        logger.warn("Cannot add event -- Event reporter is not initialized.")
        _log_event(name, op, message, is_success=is_success)
        return

    if should_emit_event(name, version, op, is_success):
        mark_event_status(name, version, op, is_success)
        reporter.add_event(
            name, op=op, is_success=is_success, duration=duration,
            version=str(version), message=message, evt_type=evt_type,
            is_internal=is_internal, log_event=log_event)

def add_periodic(
    delta, name, op="", is_success=True, duration=0, version=CURRENT_VERSION,
    message="", evt_type="", is_internal=False, log_event=True, force=False,
    reporter=__event_logger__):
    if reporter.event_dir is None:
        logger.warn("Cannot add periodic event -- Event reporter is not initialized.")
        _log_event(name, op, message, is_success=is_success)
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
