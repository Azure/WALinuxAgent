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
import datetime
import json
import os
import re
import threading
from collections import defaultdict

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common import conf
from azurelinuxagent.common.event import EVENTS_DIRECTORY, TELEMETRY_LOG_EVENT_ID, \
    TELEMETRY_LOG_PROVIDER_ID, add_event, WALAEventOperation, add_log_event, get_event_logger
from azurelinuxagent.common.exception import InvalidExtensionEventError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.telemetryevent import TelemetryEventList, TelemetryEvent, TelemetryEventParam, \
    GuestAgentGenericLogsSchema
from azurelinuxagent.ga.exthandlers import HANDLER_NAME_PATTERN
from azurelinuxagent.ga.periodic_operation import PeriodicOperation


def get_extension_telemetry_handler(protocol_util):
    return ExtensionTelemetryHandler(protocol_util)

class ExtensionEventSchema(object): # pylint: disable=R0903
    """
    Class for defining the schema for Extension Events.
    """
    Version = "Version"
    Timestamp = "Timestamp"
    TaskName = "TaskName"
    EventLevel = "EventLevel"
    Message = "Message"
    EventPid = "EventPid"
    EventTid = "EventTid"
    OperationId = "OperationId"

class ProcessExtensionTelemetry(PeriodicOperation):
    """
    Periodic operation for collecting and sending extension telemetry events to Wireserver.
    """

    _EXTENSION_EVENT_COLLECTION_PERIOD = datetime.timedelta(minutes=5)
    _EXTENSION_EVENT_FILE_NAME_REGEX = re.compile(r"^(\d+)\.json$", re.IGNORECASE)

    # Limits
    _MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD = 300
    _EXTENSION_EVENT_FILE_MAX_SIZE = 4 * 1024 * 1024  # 4 MB = 4 * 1,048,576 Bytes
    _EXTENSION_EVENT_MAX_SIZE = 1024 * 6  # 6Kb or 6144 characters. Limit for the whole event. Prevent oversized events.
    _EXTENSION_EVENT_MAX_MSG_LEN = 1024 * 3  # 3Kb or 3072 chars.

    _EXTENSION_EVENT_REQUIRED_FIELDS = [attr.lower() for attr in dir(ExtensionEventSchema) if
                                        not callable(getattr(ExtensionEventSchema, attr)) and not attr.startswith("__")]

    def __init__(self, protocol_util):
        super(ProcessExtensionTelemetry, self).__init__(
            name="collect and send extension events",
            operation=self._collect_and_send_events,
            period=ProcessExtensionTelemetry._EXTENSION_EVENT_COLLECTION_PERIOD)

        self._protocol = protocol_util.get_protocol()

    def _collect_and_send_events(self):
        event_list = self._collect_extension_events()

        if len(event_list.events) > 0: # pylint: disable=C1801
            self._protocol.report_event(event_list)

    def _collect_extension_events(self):
        events_list = TelemetryEventList()
        extension_handler_with_event_dirs = []

        try:
            extension_handler_with_event_dirs = self._get_extension_events_dir_with_handler_name(conf.get_ext_log_dir())

            if len(extension_handler_with_event_dirs) == 0: # pylint: disable=C1801
                logger.verbose("No Extension events directory exist")
                return events_list

            for extension_handler_with_event_dir in extension_handler_with_event_dirs:
                handler_name = extension_handler_with_event_dir[0]
                handler_event_dir_path = extension_handler_with_event_dir[1]
                self._capture_extension_events(handler_name, handler_event_dir_path, events_list)
        except Exception as e: # pylint: disable=C0103
            msg = "Unknown error occurred when trying to collect extension events. Error: {0}".format(ustr(e))
            add_event(op=WALAEventOperation.ExtensionTelemetryEventProcessing, message=msg, is_success=False)
        finally:
            # Always ensure that the events directory are being deleted each run,
            # even if we run into an error and dont process them this run.
            self._ensure_all_events_directories_empty(extension_handler_with_event_dirs)

        return events_list

    @staticmethod
    def _get_extension_events_dir_with_handler_name(extension_log_dir):
        """
        Get the full path to events directory for all extension handlers that have one
        :param extension_log_dir: Base log directory for all extensions
        :return: A list of full paths of existing events directory for all handlers
        """
        extension_handler_with_event_dirs = []

        for ext_handler_name in os.listdir(extension_log_dir):
            # Check if its an Extension directory
            if not os.path.isdir(os.path.join(extension_log_dir, ext_handler_name)) \
                    or re.match(HANDLER_NAME_PATTERN, ext_handler_name) is None:
                continue

            # Check if EVENTS_DIRECTORY directory exists
            extension_event_dir = os.path.join(extension_log_dir, ext_handler_name, EVENTS_DIRECTORY)
            if os.path.exists(extension_event_dir):
                extension_handler_with_event_dirs.append((ext_handler_name, extension_event_dir))

        return extension_handler_with_event_dirs

    def _capture_extension_events(self, handler_name, handler_event_dir_path, events_list): # pylint: disable=R0914
        """
        Capture Extension events and add them to the events_list
        :param handler_name: Complete Handler Name. Eg: Microsoft.CPlat.Core.RunCommandLinux
        :param handler_event_dir_path: Full path. Eg: '/var/log/azure/Microsoft.CPlat.Core.RunCommandLinux/events'
        :param events_list: List of captured extension events
        """

        convert_to_mb = lambda x: (1.0 * x)/(1000 * 1000)

        # Filter out the files that do not follow the pre-defined EXTENSION_EVENT_FILE_NAME_REGEX
        event_files = [event_file for event_file in os.listdir(handler_event_dir_path) if
                       re.match(self._EXTENSION_EVENT_FILE_NAME_REGEX, event_file) is not None]
        # Pick the latest files first, we'll discard older events if len(events) > MAX_EVENT_COUNT
        event_files.sort(reverse=True)

        captured_extension_events_count = 0
        dropped_events_with_error_count = defaultdict(int)

        for event_file in event_files:

            event_file_path = os.path.join(handler_event_dir_path, event_file)
            try:
                logger.verbose("Processing event file: {0}", event_file_path)

                # We only support _EXTENSION_EVENT_FILE_MAX_SIZE=4Mb max file size
                event_file_size = os.stat(event_file_path).st_size
                if event_file_size > self._EXTENSION_EVENT_FILE_MAX_SIZE:
                    msg = "Skipping file: {0} as its size is {1:.2f} Mb > Max size allowed {2:.1f} Mb".format(
                            event_file_path, convert_to_mb(event_file_size),
                            convert_to_mb(self._EXTENSION_EVENT_FILE_MAX_SIZE))
                    logger.warn(msg)
                    add_log_event(level=logger.LogLevel.WARNING, message=msg, forced=True)
                    continue

                # We support multiple events in a file, read the file and parse events.
                parsed_events = self._parse_event_file_and_capture_events(handler_name, event_file_path,
                                                                          captured_extension_events_count,
                                                                          dropped_events_with_error_count)
                events_list.events.extend(parsed_events)
                captured_extension_events_count += len(parsed_events)

                # We only allow MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD=300 maximum events per period per handler
                if captured_extension_events_count >= self._MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD:
                    msg = "Reached max count for the extension: {0}; Max Limit: {1}. Skipping the rest.".format(
                        handler_name, self._MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD)
                    logger.warn(msg)
                    add_log_event(level=logger.LogLevel.WARNING, message=msg, forced=True)
                    break

            except Exception as e: # pylint: disable=C0103
                msg = "Failed to process event file {0}: {1}", event_file, ustr(e)
                logger.warn(msg)
                add_log_event(level=logger.LogLevel.WARNING, message=msg, forced=True)
            finally:
                os.remove(event_file_path)

        if dropped_events_with_error_count is not None and len(dropped_events_with_error_count) > 0: # pylint: disable=C1801
            msg = "Dropped events for Extension: {0}; Details:\n\t{1}".format(handler_name, '\n\t'.join(
                ["Reason: {0}; Dropped Count: {1}".format(k, v) for k, v in dropped_events_with_error_count.items()]))
            logger.warn(msg)
            add_log_event(level=logger.LogLevel.WARNING, message=msg, forced=True)

        if captured_extension_events_count > 0:
            logger.info("Collected {0} events for extension: {1}".format(captured_extension_events_count, handler_name))

    @staticmethod
    def _ensure_all_events_directories_empty(extension_events_directories):
        if len(extension_events_directories) == 0: # pylint: disable=C1801
            return

        for extension_handler_with_event_dir in extension_events_directories:
            event_dir_path = extension_handler_with_event_dir[1]
            if not os.path.exists(event_dir_path):
                return

            err = None
            # Delete any residue files in the events directory
            for residue_file in os.listdir(event_dir_path):
                try:
                    os.remove(os.path.join(event_dir_path, residue_file))
                except Exception as e: # pylint: disable=C0103
                    # Only log the first error once per handler per run if unable to clean off residue files
                    err = ustr(e) if err is None else err

                if err is not None:
                    logger.error("Failed to completely clear the {0} directory. Exception: {1}", event_dir_path, err)

    def _parse_event_file_and_capture_events(self, handler_name, event_file_path, captured_events_count,
                                             dropped_events_with_error_count):
        events_list = []
        event_file_time = datetime.datetime.fromtimestamp(os.path.getmtime(event_file_path))

        # Read event file and decode it properly
        with open(event_file_path, "rb") as fd: # pylint: disable=C0103
            event_data = fd.read().decode("utf-8")

        # Parse the string and get the list of events
        events = json.loads(event_data)

        # We allow multiple events in a file but there can be an instance where the file only has a single
        # JSON event and not a list. Handling that condition too
        if not isinstance(events, list):
            events = [events]

        for event in events:
            try:
                events_list.append(self._parse_telemetry_event(handler_name, event, event_file_time))
                captured_events_count += 1
            except InvalidExtensionEventError as e: # pylint: disable=C0103
                # These are the errors thrown if there's an error parsing the event. We want to report these back to the
                # extension publishers so that they are aware of the issues.
                # The error messages are all static messages, we will use this to create a dict and emit an event at the
                # end of each run to notify if there were any errors parsing events for the extension
                dropped_events_with_error_count[ustr(e)] += 1
            except Exception as e: # pylint: disable=C0103
                logger.warn("Unable to parse and transmit event, error: {0}".format(e))

            if captured_events_count >= self._MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD:
                break

        return events_list

    def _parse_telemetry_event(self, handler_name, extension_unparsed_event, event_file_time):
        """
        Parse the Json event file and convert it to TelemetryEvent object with the required data.
        :return: Complete TelemetryEvent with all required fields filled up properly. Raises if event breaches contract.
        """

        extension_event = self._parse_event_and_ensure_it_is_valid(extension_unparsed_event)

        # Create a telemetry event, add all common parameters to the event
        # and then overwrite all the common params with extension events params if same

        event = TelemetryEvent(TELEMETRY_LOG_EVENT_ID, TELEMETRY_LOG_PROVIDER_ID)
        event.file_type = "json"
        self.add_common_params_to_extension_event(event, event_file_time)

        replace_or_add_params = {
            GuestAgentGenericLogsSchema.EventName: "{0}-{1}".format(handler_name, extension_event[
                ExtensionEventSchema.Version.lower()]),
            GuestAgentGenericLogsSchema.CapabilityUsed: extension_event[ExtensionEventSchema.EventLevel.lower()],
            GuestAgentGenericLogsSchema.TaskName: extension_event[ExtensionEventSchema.TaskName.lower()],
            GuestAgentGenericLogsSchema.Context1: extension_event[ExtensionEventSchema.Message.lower()],
            GuestAgentGenericLogsSchema.Context2: extension_event[ExtensionEventSchema.Timestamp.lower()],
            GuestAgentGenericLogsSchema.Context3: extension_event[ExtensionEventSchema.OperationId.lower()],
            GuestAgentGenericLogsSchema.EventPid: extension_event[ExtensionEventSchema.EventPid.lower()],
            GuestAgentGenericLogsSchema.EventTid: extension_event[ExtensionEventSchema.EventTid.lower()]
        }
        self._replace_or_add_param_in_event(event, replace_or_add_params)
        return event

    def _parse_event_and_ensure_it_is_valid(self, extension_event):
        """
        Parse the Json event from file. Raise InvalidExtensionEventError if the event breaches pre-set contract.
        :param extension_event: The json event from file
        :return: Verified Json event that qualifies the contract.
        """

        clean_string = lambda x: x.strip() if x is not None else x

        event_size = 0
        key_err_msg = "{0}: {1} not found"

        # Convert the dict to all lower keys to avoid schema confusion.
        # Only pick the params that we care about and skip the rest.
        event = dict((k.lower(), clean_string(v)) for k, v in extension_event.items() if
                     k.lower() in self._EXTENSION_EVENT_REQUIRED_FIELDS)

        # Trim message and only pick the first 3k chars
        message_key = ExtensionEventSchema.Message.lower()
        if message_key in event:
            event[message_key] = event[message_key][:self._EXTENSION_EVENT_MAX_MSG_LEN]
        else:
            raise InvalidExtensionEventError(
                key_err_msg.format(InvalidExtensionEventError.MissingKeyError, ExtensionEventSchema.Message))

        if event[message_key] is None or len(event[message_key]) == 0: # pylint: disable=C1801
            raise InvalidExtensionEventError(
                "{0}: {1} should not be empty".format(InvalidExtensionEventError.EmptyMessageError,
                                                     ExtensionEventSchema.Message))

        for required_key in self._EXTENSION_EVENT_REQUIRED_FIELDS:
            # If all required keys not in event then raise
            if not required_key in event:
                raise InvalidExtensionEventError(
                    key_err_msg.format(InvalidExtensionEventError.MissingKeyError, required_key))

            # If the event_size > _EXTENSION_EVENT_MAX_SIZE=6k, then raise
            if event_size > self._EXTENSION_EVENT_MAX_SIZE:
                raise InvalidExtensionEventError(
                    "{0}: max event size allowed: {1}".format(InvalidExtensionEventError.OversizeEventError,
                                                              self._EXTENSION_EVENT_MAX_SIZE))

            event_size += len(event[required_key])

        return event

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

    @staticmethod
    def add_common_params_to_extension_event(event, event_time):
        reporter = get_event_logger()
        reporter.add_common_event_parameters(event, event_time)


class ExtensionTelemetryHandler(ThreadHandlerInterface):
    """
    This Handler takes care of fetching the Extension Telemetry events from the {extension_events_dir} and sends it to
    Kusto for advanced debuggability.
    """

    _THREAD_NAME = "ExtensionTelemetryHandler"

    def __init__(self, protocol_util):
        self.protocol_util = protocol_util
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
        op = ProcessExtensionTelemetry(self.protocol_util) # pylint: disable=C0103
        logger.info("Successfully started the {0} thread".format(self.get_thread_name()))
        while not self.stopped():
            try:
                op.run()

            except Exception as e: # pylint: disable=C0103
                logger.warn(
                    "An error occurred in the Telemetry Extension thread main loop; will skip the current iteration.\n{0}",
                    ustr(e))
            finally:
                PeriodicOperation.sleep_until_next_operation([op])