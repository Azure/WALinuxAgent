# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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
import threading
import datetime

import re

import os

import json

from azurelinuxagent.common.event import EVENTS_DIRECTORY, parse_event, TELEMETRY_LOG_EVENT_ID, \
    TELEMETRY_LOG_PROVIDER_ID, add_common_params_to_extension_event, add_event, WALAEventOperation, add_log_event
from azurelinuxagent.ga.exthandlers import HANDLER_NAME_PATTERN

from azurelinuxagent.common import conf
from azurelinuxagent.common.future import ustr

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.telemetryevent import TelemetryEventList, TelemetryEvent, TelemetryEventParam, \
    TelemetryEventSchemaKeyNames
from azurelinuxagent.ga.periodic_operation import PeriodicOperation


def get_extension_telemetry_handler(protocol_util):
    return ExtensionTelemetryHandler(protocol_util)

class ExtensionEventSchema(object):
    """
    Class for defining the schema for Extension Events.
    Note: All values are in lowercase here to avoid any case mismatch later.
    """
    Version = "version"
    Timestamp = "timestamp"
    TaskName = "taskname"
    EventLevel = "eventlevel"
    Message = "message"
    EventPid = "eventpid"
    EventTid = "eventtid"
    OperationId = "operationid"

class ExtensionTelemetryHandler(object):
    """
    This Handler takes care of fetching the Extension Telemetry events from the {extension_events_dir} and sends it to
    Kusto for advanced debuggability.
    """

    EXTENSION_EVENT_COLLECTION_PERIOD = datetime.timedelta(minutes=5)
    EXTENSION_EVENT_FILE_NAME_REGEX = re.compile(r"^(\d+)\.json$", re.IGNORECASE)

    # Limits
    MAX_NUMBER_OF_EXTENSIONS_EVENTS_PER_PERIOD = 300
    EXTENSION_EVENT_FILE_MAX_SIZE = 4000000  # 4 MB = 4000000 Bytes (in decimal)
    EXTENSION_EVENT_MAX_SIZE = 1024 * 6   # 6Kb or 6144 characters. Limit for the whole event. Prevent oversized events.
    EXTENSION_EVENT_MAX_MSG_LEN = 1024 * 3  # 3Kb or 3072 chars.

    EXTENSION_EVENT_SCHEMA_FIELDS = [attr for attr in dir(ExtensionEventSchema) if
                                     not callable(getattr(ExtensionEventSchema, attr)) and not attr.startswith("__")]

    _THREAD_NAME = "ExtensionTelemetryHandler"

    def __init__(self, protocol_util):
        self.protocol_util = protocol_util
        self._protocol = self.protocol_util.get_protocol()
        self.should_run = True
        self.thread = None

    @staticmethod
    def get_thread_name():
        return ExtensionTelemetryHandler._THREAD_NAME

    def run(self):
        logger.info("Start Extension Telemetry service.")
        self.start()

    def is_alive(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self):
        self.thread = threading.Thread(target=self.daemon)
        self.thread.setDaemon(True)
        self.thread.setName(ExtensionTelemetryHandler.get_thread_name())
        self.thread.start()

    def stop(self):
        """
        Stop server communication and join the thread to main thread.
        """
        self.should_run = False
        if self.is_alive():
            self.thread.join()

    def stopped(self):
        return not self.should_run

    def daemon(self):
        op = PeriodicOperation("collect_and_send_events", self.collect_and_send_events,
                               self.EXTENSION_EVENT_COLLECTION_PERIOD)
        while not self.stopped():
            try:
                op.run()

            except Exception as e:
                logger.warn(
                    "An error occurred in the Telemetry Extension thread main loop; will skip the current iteration.\n{0}",
                    ustr(e))
            finally:
                PeriodicOperation.sleep_until_next_operation([op])



    def collect_and_send_events(self):
        event_list = self._collect_extension_events()

        if len(event_list.events) > 0:
            self._protocol.report_event(event_list)

    def _collect_extension_events(self):
        """
        1- Figure out all extension events directory exist in FS
        2- Pick all events which match the REGEX and ensure no_of_events <= 300,
            if not, sort by filename and delete the older ones
        3-
        :return:
        """
        events_list = TelemetryEventList()
        extension_handler_with_event_dirs = []

        try:
            extension_handler_with_event_dirs = self._get_extension_events_dir_with_handler_name()

            if not extension_handler_with_event_dirs:
                logger.info("No Extension events directory exist")
                return events_list

            for extension_handler_with_event_dir in extension_handler_with_event_dirs:
                handler_name = extension_handler_with_event_dir[0]
                handler_event_dir_path = extension_handler_with_event_dir[1]
                self._capture_extension_events(handler_name, handler_event_dir_path, events_list)
        except Exception as e:
            msg = "Unknown error occurred when trying to collect extension events. Error: {0}".format(ustr(e))
            add_event(op=WALAEventOperation.ExtensionTelemetryEventProcessing, message=msg, is_success=False)
        finally:
            # Always ensure that the events directory are being deleted each run,
            # even if we run into an error and dont process them this run.
            self._ensure_all_events_directories_empty(extension_handler_with_event_dirs)
            return events_list

    @staticmethod
    def _get_extension_events_dir_with_handler_name(extension_log_dir=conf.get_ext_log_dir()):
        extension_handler_with_event_dirs = []

        for ext_handler_name in os.listdir(extension_log_dir):
            # Check if its an Extension directory
            if not os.path.isdir(os.path.join(extension_log_dir, ext_handler_name)) \
                    or re.match(HANDLER_NAME_PATTERN, ext_handler_name) is None:
                continue

            # Check if EVENTS_DIRECTORY (events) directory exists
            extension_event_dir = os.path.join(extension_log_dir, ext_handler_name, EVENTS_DIRECTORY)
            if os.path.exists(extension_event_dir):
                extension_handler_with_event_dirs.append((ext_handler_name, extension_event_dir))

        return extension_handler_with_event_dirs

    def _capture_extension_events(self, handler_name, handler_event_dir_path, events_list):
        # Eg: handler_name = Microsoft.CPlat.Core.RunCommandLinux
        # handler_event_path = '/var/log/azure/Microsoft.CPlat.Core.RunCommandLinux/events'

        convert_to_mb = lambda x: x/(1000 * 1000)

        event_files = [event_file for event_file in os.listdir(handler_event_dir_path) if
                       re.match(self.EXTENSION_EVENT_FILE_NAME_REGEX, event_file) is not None]
        # Pick the latest files first, we'll discard older events if len(events) > MAX_EVENT_COUNT
        event_files.sort(reverse=True)

        for event_file in event_files:

            event_file_path = os.path.join(handler_event_dir_path, event_file)
            try:
                logger.verbose("Processing event file: {0}", event_file_path)

                if len(events_list.events) >= self.MAX_NUMBER_OF_EXTENSIONS_EVENTS_PER_PERIOD:
                    msg = "Reached max count for the extension: {0}. Skipping the rest.".format(handler_name)
                    logger.warn(msg)
                    add_log_event(level=logger.LogLevel.WARNING, message=msg)
                    break

                # We only support 4Mb max file size
                event_file_size = os.stat(event_file_path).st_size
                if event_file_size > self.EXTENSION_EVENT_FILE_MAX_SIZE:
                    msg = "Skipping file {0} as its size is {1:.2f} Mb. Max size allowed is: {2:.1f} Mb".format(
                            event_file_path, convert_to_mb(event_file_size),
                            convert_to_mb(self.EXTENSION_EVENT_FILE_MAX_SIZE))
                    logger.warn(msg)
                    add_log_event(level=logger.LogLevel.WARNING, message=msg)
                    continue

                # We support multiple events in a file, read the file and parse events.
                parsed_events = self._parse_event_file_and_capture_events(handler_name, event_file_path, len(events_list.events))
                events_list.events.extend(parsed_events)

            except Exception as e:
                msg = "Failed to process event file {0}: {1}", event_file, ustr(e)
                logger.warn(msg)
                add_log_event(level=logger.LogLevel.WARNING, message=msg)
            finally:
                os.remove(event_file_path)

        logger.info("Collected {0} events for extension: {1}".format(len(events_list.events), handler_name))

    @staticmethod
    def _ensure_all_events_directories_empty(extension_events_directories):
        if not extension_events_directories:
            return

        for extension_handler_with_event_dir in extension_events_directories:
            event_dir_path = extension_handler_with_event_dir[1]
            try:
                # Delete any residue files in the events directory
                for residue_file in os.listdir(event_dir_path):
                    os.remove(residue_file)
            except Exception as e:
                logger.error("Failed to completely clear the {0} directory. Exception: {1}", event_dir_path, ustr(e))

    def _parse_event_file_and_capture_events(self, handler_name, event_file_path, captured_events_count):
        events_list = []

        # Read event file and decode it properly
        with open(event_file_path, "rb") as fd:
            event_data = fd.read().decode("utf-8")

        # Parse the string and get the list of events
        events = json.loads(event_data)

        # Note: we can avoid reading string into memory and converting to JSON, instead we can directly convert to
        # JSON using json.load() but unfortunately the open() and json.load() function have different signatures in py2 vs py3
        # to encode to utf8 and to do it properly for both, this is the best way.
        # If we depracate Py2, we can use the single way.

        for event in events:
            try:
                events_list.append(self._parse_telemetry_event(handler_name, event))
                captured_events_count += 1
            except Exception as e:
                logger.warn("Unable to parse and add event, error: {0}".format(e))

            if captured_events_count >= self.MAX_NUMBER_OF_EXTENSIONS_EVENTS_PER_PERIOD:
                break

        return events_list

    def _parse_telemetry_event(self, handler_name, extension_event):

        # Convert the dict to all lower keys to avoid schema confusion. Only pick the params that we care about and skip the rest
        # (Not sure if this is needed or not)
        extension_event = {k.lower(): v.strip() for k, v in extension_event.items() if
                           k.lower() in self.EXTENSION_EVENT_SCHEMA_FIELDS}

        self._ensure_event_is_valid(extension_event)

        # Create an event,
        # add all common parameters to the event
        # and then overwrite all the common params with extension events params if same

        event = TelemetryEvent(TELEMETRY_LOG_EVENT_ID, TELEMETRY_LOG_PROVIDER_ID)
        event.file_type = "json"
        add_common_params_to_extension_event(event)

        replace_or_add_params = {
            TelemetryEventSchemaKeyNames.EventName: "{0}-{1}".format(handler_name, extension_event[ExtensionEventSchema.Version]),
            TelemetryEventSchemaKeyNames.CapabilityUsed: extension_event[ExtensionEventSchema.EventLevel],
            TelemetryEventSchemaKeyNames.TaskName: extension_event[ExtensionEventSchema.TaskName],
            TelemetryEventSchemaKeyNames.Context1: extension_event[ExtensionEventSchema.Message],
            TelemetryEventSchemaKeyNames.Context2: extension_event[ExtensionEventSchema.Timestamp],
            TelemetryEventSchemaKeyNames.Context3: extension_event[ExtensionEventSchema.OperationId],
            TelemetryEventSchemaKeyNames.EventPid: extension_event[ExtensionEventSchema.EventPid],
            TelemetryEventSchemaKeyNames.EventTid: extension_event[ExtensionEventSchema.EventTid]
        }
        self._replace_or_add_param_in_event(event, replace_or_add_params)
        return event

    @staticmethod
    def _ensure_event_is_valid(event):

        event_size = 0

        # Trim message and only pick the first 3k chars
        event[ExtensionEventSchema.Message] = event[ExtensionEventSchema.Message][:ExtensionTelemetryHandler.EXTENSION_EVENT_MAX_MSG_LEN]

        for required_key in ExtensionTelemetryHandler.EXTENSION_EVENT_SCHEMA_FIELDS:
            # If all required keys not in event then raise
            if not required_key in event:
                raise KeyError("Expected keys not present in extension event")

            # If the event_size > 6k, then raise
            if event_size > ExtensionTelemetryHandler.EXTENSION_EVENT_MAX_SIZE:
                raise MemoryError("Extension Event size: {0} is > Max size: {1}".format(event_size, ExtensionTelemetryHandler.EXTENSION_EVENT_MAX_SIZE))

            event_size += len(event[required_key])

    @staticmethod
    def _replace_or_add_param_in_event(event, replace_or_add_params):
        for param in event.parameters:
            if param.name in replace_or_add_params:
                param.value = replace_or_add_params.pop(param.name)

        if not replace_or_add_params:
            # All values replaced, return
            return

        # Add the remaining params to the event
        for param_name in replace_or_add_params:
            event.parameters.append(TelemetryEventParam(param_name, replace_or_add_params[param_name]))