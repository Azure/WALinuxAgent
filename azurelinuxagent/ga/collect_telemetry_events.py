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
import traceback
from collections import defaultdict

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common import conf
from azurelinuxagent.common.event import EVENTS_DIRECTORY, TELEMETRY_LOG_EVENT_ID, \
    TELEMETRY_LOG_PROVIDER_ID, add_event, WALAEventOperation, add_log_event, get_event_logger, \
    CollectOrReportEventDebugInfo, EVENT_FILE_REGEX, parse_event
from azurelinuxagent.common.exception import InvalidExtensionEventError, ServiceStoppedError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventParam, \
    GuestAgentGenericLogsSchema, GuestAgentExtensionEventsSchema
from azurelinuxagent.ga.exthandlers import HANDLER_NAME_PATTERN, is_extension_telemetry_pipeline_enabled
from azurelinuxagent.ga.periodic_operation import PeriodicOperation


def get_collect_telemetry_events_handler(send_telemetry_events_handler):
    return CollectTelemetryEventsHandler(send_telemetry_events_handler)


class ExtensionEventSchema(object):
    """
    Class for defining the schema for Extension Events.

    Sample Extension Event Example:
        {
           "Version":"1.0.0.23",
           "Timestamp":"2018-01-02T22:08:12.510696Z"    //(time in UTC (ISO-8601 standard),
           "TaskName":"TestRun"                         //Open for publishers,
           "EventLevel":"Critical/Error/Warning/Verbose/Informational/LogAlways",
           "Message": "Successful test"                //(max 3K, 3072 characters),
           "EventPid":"1",
           "EventTid":"2",
           "OperationId":"Guid (str)"
        }
    """
    Version = "Version"
    Timestamp = "Timestamp"
    TaskName = "TaskName"
    EventLevel = "EventLevel"
    Message = "Message"
    EventPid = "EventPid"
    EventTid = "EventTid"
    OperationId = "OperationId"


class _ProcessExtensionEventsPeriodicOperation(PeriodicOperation):
    """
    Periodic operation for collecting extension telemetry events and enqueueing them for the SendTelemetryHandler thread.
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

    def __init__(self, send_telemetry_events_handler):
        super(_ProcessExtensionEventsPeriodicOperation, self).__init__(
            name="collect_and_enqueue_extension_events",
            operation=self._collect_and_enqueue_extension_events,
            period=_ProcessExtensionEventsPeriodicOperation._EXTENSION_EVENT_COLLECTION_PERIOD)

        self._send_telemetry_events_handler = send_telemetry_events_handler

    def _collect_and_enqueue_extension_events(self):

        if self._send_telemetry_events_handler.stopped():
            logger.warn("{0} service is not running, skipping current iteration".format(
                self._send_telemetry_events_handler.get_thread_name()))
            return

        delete_all_event_files = True
        extension_handler_with_event_dirs = []

        try:
            extension_handler_with_event_dirs = self._get_extension_events_dir_with_handler_name(conf.get_ext_log_dir())

            if not extension_handler_with_event_dirs:
                logger.verbose("No Extension events directory exist")
                return

            for extension_handler_with_event_dir in extension_handler_with_event_dirs:
                handler_name = extension_handler_with_event_dir[0]
                handler_event_dir_path = extension_handler_with_event_dir[1]
                self._capture_extension_events(handler_name, handler_event_dir_path)
        except ServiceStoppedError:
            # Since the service stopped, we should not delete the extension files and retry sending them whenever
            # the telemetry service comes back up
            delete_all_event_files = False
        except Exception as error:
            msg = "Unknown error occurred when trying to collect extension events. Error: {0}, Stack: {1}".format(
                ustr(error), traceback.format_exc())
            add_event(op=WALAEventOperation.ExtensionTelemetryEventProcessing, message=msg, is_success=False)
        finally:
            # Always ensure that the events directory are being deleted each run except when Telemetry Service is stopped,
            # even if we run into an error and dont process them this run.
            if delete_all_event_files:
                self._ensure_all_events_directories_empty(extension_handler_with_event_dirs)

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

    def _event_file_size_allowed(self, event_file_path):

        event_file_size = os.stat(event_file_path).st_size
        if event_file_size > self._EXTENSION_EVENT_FILE_MAX_SIZE:
            convert_to_mb = lambda x: (1.0 * x) / (1000 * 1000)
            msg = "Skipping file: {0} as its size is {1:.2f} Mb > Max size allowed {2:.1f} Mb".format(
                event_file_path, convert_to_mb(event_file_size),
                convert_to_mb(self._EXTENSION_EVENT_FILE_MAX_SIZE))
            logger.warn(msg)
            add_log_event(level=logger.LogLevel.WARNING, message=msg, forced=True)
            return False
        return True

    def _capture_extension_events(self, handler_name, handler_event_dir_path):
        """
        Capture Extension events and add them to the events_list
        :param handler_name: Complete Handler Name. Eg: Microsoft.CPlat.Core.RunCommandLinux
        :param handler_event_dir_path: Full path. Eg: '/var/log/azure/Microsoft.CPlat.Core.RunCommandLinux/events'
        """

        # Filter out the files that do not follow the pre-defined EXTENSION_EVENT_FILE_NAME_REGEX
        event_files = [event_file for event_file in os.listdir(handler_event_dir_path) if
                       re.match(self._EXTENSION_EVENT_FILE_NAME_REGEX, event_file) is not None]
        # Pick the latest files first, we'll discard older events if len(events) > MAX_EVENT_COUNT
        event_files.sort(reverse=True)

        captured_extension_events_count = 0
        dropped_events_with_error_count = defaultdict(int)

        try:
            for event_file in event_files:

                event_file_path = os.path.join(handler_event_dir_path, event_file)
                try:
                    logger.verbose("Processing event file: {0}", event_file_path)

                    if not self._event_file_size_allowed(event_file_path):
                        continue

                    # We support multiple events in a file, read the file and parse events.
                    captured_extension_events_count = self._enqueue_events_and_get_count(handler_name, event_file_path,
                                                                                         captured_extension_events_count,
                                                                                         dropped_events_with_error_count)

                    # We only allow MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD=300 maximum events per period per handler
                    if captured_extension_events_count >= self._MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD:
                        msg = "Reached max count for the extension: {0}; Max Limit: {1}. Skipping the rest.".format(
                            handler_name, self._MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD)
                        logger.warn(msg)
                        add_log_event(level=logger.LogLevel.WARNING, message=msg, forced=True)
                        break
                except ServiceStoppedError:
                    # Not logging here as already logged once, re-raising
                    # Since we already started processing this file, deleting it as we could've already sent some events out
                    # This is a trade-off between data replication vs data loss.
                    raise
                except Exception as error:
                    msg = "Failed to process event file {0}: {1}, {2}".format(event_file, ustr(error),
                                                                              traceback.format_exc())
                    logger.warn(msg)
                    add_log_event(level=logger.LogLevel.WARNING, message=msg, forced=True)
                finally:
                    # Todo: We should delete files after ensuring that we sent the data to Wireserver successfully
                    # from our end rather than deleting first and sending later. This is to ensure the data reliability
                    # of the agent telemetry pipeline.
                    os.remove(event_file_path)

        finally:
            if dropped_events_with_error_count:
                msg = "Dropped events for Extension: {0}; Details:\n\t{1}".format(handler_name, '\n\t'.join(
                    ["Reason: {0}; Dropped Count: {1}".format(k, v) for k, v in dropped_events_with_error_count.items()]))
                logger.warn(msg)
                add_log_event(level=logger.LogLevel.WARNING, message=msg, forced=True)

            if captured_extension_events_count > 0:
                logger.info("Collected {0} events for extension: {1}".format(captured_extension_events_count, handler_name))

    @staticmethod
    def _ensure_all_events_directories_empty(extension_events_directories):
        if not extension_events_directories:
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
                except Exception as error:
                    # Only log the first error once per handler per run if unable to clean off residue files
                    err = ustr(error) if err is None else err

                if err is not None:
                    logger.error("Failed to completely clear the {0} directory. Exception: {1}", event_dir_path, err)

    def _enqueue_events_and_get_count(self, handler_name, event_file_path, captured_events_count,
                                      dropped_events_with_error_count):

        event_file_time = datetime.datetime.fromtimestamp(os.path.getmtime(event_file_path))

        # Read event file and decode it properly
        with open(event_file_path, "rb") as event_file_descriptor:
            event_data = event_file_descriptor.read().decode("utf-8")

        # Parse the string and get the list of events
        events = json.loads(event_data)

        # We allow multiple events in a file but there can be an instance where the file only has a single
        # JSON event and not a list. Handling that condition too
        if not isinstance(events, list):
            events = [events]

        for event in events:
            try:
                self._send_telemetry_events_handler.enqueue_event(
                    self._parse_telemetry_event(handler_name, event, event_file_time)
                )
                captured_events_count += 1
            except InvalidExtensionEventError as invalid_error:
                # These are the errors thrown if there's an error parsing the event. We want to report these back to the
                # extension publishers so that they are aware of the issues.
                # The error messages are all static messages, we will use this to create a dict and emit an event at the
                # end of each run to notify if there were any errors parsing events for the extension
                dropped_events_with_error_count[ustr(invalid_error)] += 1
            except ServiceStoppedError as stopped_error:
                logger.error(
                    "Unable to enqueue events as service stopped: {0}. Stopping collecting extension events".format(
                        ustr(stopped_error)))
                raise
            except Exception as error:
                logger.warn("Unable to parse and transmit event, error: {0}".format(error))

            if captured_events_count >= self._MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD:
                break

        return captured_events_count

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
        CollectTelemetryEventsHandler.add_common_params_to_telemetry_event(event, event_file_time)

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

        if not event[message_key]:
            raise InvalidExtensionEventError(
                "{0}: {1} should not be empty".format(InvalidExtensionEventError.EmptyMessageError,
                                                     ExtensionEventSchema.Message))

        for required_key in self._EXTENSION_EVENT_REQUIRED_FIELDS:
            # If all required keys not in event then raise
            if required_key not in event:
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


class _CollectAndEnqueueEventsPeriodicOperation(PeriodicOperation):
    """
    Periodic operation to collect telemetry events located in the events folder and enqueue them for the
    SendTelemetryHandler thread.
    """

    _EVENT_COLLECTION_PERIOD = datetime.timedelta(minutes=1)

    def __init__(self, send_telemetry_events_handler):
        super(_CollectAndEnqueueEventsPeriodicOperation, self).__init__(
            name="collect_and_enqueue_events",
            operation=self._collect_and_enqueue_events,
            period=_CollectAndEnqueueEventsPeriodicOperation._EVENT_COLLECTION_PERIOD)
        self._send_telemetry_events_handler = send_telemetry_events_handler

    def _collect_and_enqueue_events(self):
        """
        Periodically send any events located in the events folder
        """
        try:
            if self._send_telemetry_events_handler.stopped():
                logger.warn("{0} service is not running, skipping iteration.".format(
                    self._send_telemetry_events_handler.get_thread_name()))
                return
            self.process_events()
        except Exception as error:
            err_msg = "Failure in collecting telemetry events: {0}".format(ustr(error))
            add_event(op=WALAEventOperation.UnhandledError, message=err_msg, is_success=False)

    def process_events(self):
        """
        Returns a list of events that need to be sent to the telemetry pipeline and deletes the corresponding files
        from the events directory.
        """
        event_directory_full_path = os.path.join(conf.get_lib_dir(), EVENTS_DIRECTORY)
        event_files = os.listdir(event_directory_full_path)
        debug_info = CollectOrReportEventDebugInfo(operation=CollectOrReportEventDebugInfo.OP_COLLECT)

        for event_file in event_files:
            try:
                match = EVENT_FILE_REGEX.search(event_file)
                if match is None:
                    continue

                event_file_path = os.path.join(event_directory_full_path, event_file)

                try:
                    logger.verbose("Processing event file: {0}", event_file_path)

                    with open(event_file_path, "rb") as event_fd:
                        event_data = event_fd.read().decode("utf-8")

                    event = parse_event(event_data)

                    # "legacy" events are events produced by previous versions of the agent (<= 2.2.46) and extensions;
                    # they do not include all the telemetry fields, so we add them here
                    is_legacy_event = match.group('agent_event') is None

                    if is_legacy_event:
                        # We'll use the file creation time for the event's timestamp
                        event_file_creation_time_epoch = os.path.getmtime(event_file_path)
                        event_file_creation_time = datetime.datetime.fromtimestamp(event_file_creation_time_epoch)

                        if event.is_extension_event():
                            _CollectAndEnqueueEventsPeriodicOperation._trim_legacy_extension_event_parameters(event)
                            CollectTelemetryEventsHandler.add_common_params_to_telemetry_event(event,
                                                                                               event_file_creation_time)
                        else:
                            _CollectAndEnqueueEventsPeriodicOperation._update_legacy_agent_event(event,
                                                                                                 event_file_creation_time)

                    self._send_telemetry_events_handler.enqueue_event(event)
                finally:
                    # Todo: We should delete files after ensuring that we sent the data to Wireserver successfully
                    # from our end rather than deleting first and sending later. This is to ensure the data reliability
                    # of the agent telemetry pipeline.
                    os.remove(event_file_path)
            except ServiceStoppedError as stopped_error:
                logger.error(
                    "Unable to enqueue events as service stopped: {0}, skipping events collection".format(
                        ustr(stopped_error)))
            except UnicodeError as uni_err:
                debug_info.update_unicode_error(uni_err)
            except Exception as error:
                debug_info.update_op_error(error)

        debug_info.report_debug_info()

    @staticmethod
    def _update_legacy_agent_event(event, event_creation_time):
        # Ensure that if an agent event is missing a field from the schema defined since 2.2.47, the missing fields
        # will be appended, ensuring the event schema is complete before the event is reported.
        new_event = TelemetryEvent()
        new_event.parameters = []
        CollectTelemetryEventsHandler.add_common_params_to_telemetry_event(new_event, event_creation_time)

        event_params = dict([(param.name, param.value) for param in event.parameters])
        new_event_params = dict([(param.name, param.value) for param in new_event.parameters])

        missing_params = set(new_event_params.keys()).difference(set(event_params.keys()))
        params_to_add = []
        for param_name in missing_params:
            params_to_add.append(TelemetryEventParam(param_name, new_event_params[param_name]))

        event.parameters.extend(params_to_add)

    @staticmethod
    def _trim_legacy_extension_event_parameters(event):
        """
        This method is called for extension events before they are sent out. Per the agreement with extension
        publishers, the parameters that belong to extensions and will be reported intact are Name, Version, Operation,
        OperationSuccess, Message, and Duration. Since there is nothing preventing extensions to instantiate other
        fields (which belong to the agent), we call this method to ensure the rest of the parameters are trimmed since
        they will be replaced with values coming from the agent.
        :param event: Extension event to trim.
        :return: Trimmed extension event; containing only extension-specific parameters.
        """
        params_to_keep = dict().fromkeys([
            GuestAgentExtensionEventsSchema.Name,
            GuestAgentExtensionEventsSchema.Version,
            GuestAgentExtensionEventsSchema.Operation,
            GuestAgentExtensionEventsSchema.OperationSuccess,
            GuestAgentExtensionEventsSchema.Message,
            GuestAgentExtensionEventsSchema.Duration
        ])
        trimmed_params = []

        for param in event.parameters:
            if param.name in params_to_keep:
                trimmed_params.append(param)

        event.parameters = trimmed_params


class CollectTelemetryEventsHandler(ThreadHandlerInterface):
    """
    This Handler takes care of fetching the Extension Telemetry events from the {extension_events_dir} and sends it to
    Kusto for advanced debuggability.
    """

    _THREAD_NAME = "TelemetryEventsCollector"

    def __init__(self, send_telemetry_events_handler):
        self.should_run = True
        self.thread = None
        self._send_telemetry_events_handler = send_telemetry_events_handler

    @staticmethod
    def get_thread_name():
        return CollectTelemetryEventsHandler._THREAD_NAME

    def run(self):
        logger.info("Start Extension Telemetry service.")
        self.start()

    def is_alive(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self):
        self.thread = threading.Thread(target=self.daemon)
        self.thread.setDaemon(True)
        self.thread.setName(CollectTelemetryEventsHandler.get_thread_name())
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
        periodic_operations = [
            _CollectAndEnqueueEventsPeriodicOperation(self._send_telemetry_events_handler)
        ]

        logger.info("Extension Telemetry pipeline enabled: {0}".format(
            is_extension_telemetry_pipeline_enabled()))
        if is_extension_telemetry_pipeline_enabled():
            periodic_operations.append(_ProcessExtensionEventsPeriodicOperation(self._send_telemetry_events_handler))

        logger.info("Successfully started the {0} thread".format(self.get_thread_name()))
        while not self.stopped():
            try:
                for periodic_op in periodic_operations:
                    periodic_op.run()

            except Exception as error:
                logger.warn(
                    "An error occurred in the Telemetry Extension thread main loop; will skip the current iteration.\n{0}",
                    ustr(error))
            finally:
                PeriodicOperation.sleep_until_next_operation(periodic_operations)

    @staticmethod
    def add_common_params_to_telemetry_event(event, event_time):
        reporter = get_event_logger()
        reporter.add_common_event_parameters(event, event_time)