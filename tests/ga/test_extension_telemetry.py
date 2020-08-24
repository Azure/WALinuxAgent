import contextlib
import glob
import json
import os
import random
import re
import shutil
import string
import uuid
from collections import defaultdict

from mock import MagicMock, Mock, patch

from azurelinuxagent.common import conf
from azurelinuxagent.common.event import EVENTS_DIRECTORY
from azurelinuxagent.common.exception import InvalidExtensionEventError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.protocol.wire import event_param_to_v1
from azurelinuxagent.common.telemetryevent import TelemetryEventParam, GuestAgentGenericLogsSchema, \
    CommonTelemetryEventSchema
from azurelinuxagent.common.utils import fileutil, textutil
from azurelinuxagent.ga.extension_telemetry import ExtensionEventSchema, ProcessExtensionTelemetry
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates, MockHttpResponse
from tests.protocol.mockwiredata import DATA_FILE
from tests.tools import AgentTestCase, clear_singleton_instances, data_dir, skip_if_predicate_true # pylint: disable=unused-import


class TestExtensionTelemetryHandler(AgentTestCase, HttpRequestPredicates):

    _TEST_DATA_DIR = os.path.join(data_dir, "events", "extension_events")
    _WELL_FORMED_FILES = os.path.join(_TEST_DATA_DIR, "well_formed_files")
    _MALFORMED_FILES = os.path.join(_TEST_DATA_DIR, "malformed_files")
    _MIX_FILES = os.path.join(_TEST_DATA_DIR, "mix_files")

    # To make tests more versatile, include this key in a test event to mark that event as a bad event.
    # This event will then be skipped and will not be counted as a good event. This is purely for testing purposes,
    # we use the good_event_count to validate the no of events the agent actually sends to Wireserver.
    # Eg: {
    #         "EventLevel": "INFO",
    #         "Message": "Starting IaaS ScriptHandler Extension v1",
    #         "Version": "1.2.3",
    #         "TaskName": "Extension Info",
    #         "EventPid": "5676",
    #         "EventTid": "1",
    #         "OperationId": "e1065def-7571-42c2-88a2-4f8b4c8f226d",
    #         "TimeStamp": "2019-12-12T01:11:38.2298194Z",
    #         "BadEvent": true
    #     }
    BAD_EVENT_KEY = 'BadEvent'

    def setUp(self):
        AgentTestCase.setUp(self)
        clear_singleton_instances(ProtocolUtil)

        # Create the log directory if not exists
        fileutil.mkdir(conf.get_ext_log_dir())

    def tearDown(self):
        AgentTestCase.tearDown(self)


    @staticmethod
    def _parse_file_and_count_good_events(test_events_file_path):
        if not os.path.exists(test_events_file_path):
            raise OSError("Test Events file {0} not found".format(test_events_file_path))

        try:
            with open(test_events_file_path, "rb") as fd: # pylint: disable=invalid-name
                event_data = fd.read().decode("utf-8")

            # Parse the string and get the list of events
            events = json.loads(event_data)

            if not isinstance(events, list):
                events = [events]

        except Exception as e: # pylint: disable=invalid-name
            print("Error parsing json file: {0}".format(e))
            return 0

        bad_key = TestExtensionTelemetryHandler.BAD_EVENT_KEY
        return len([e for e in events if bad_key not in e or not e[bad_key]])

    @staticmethod
    def _create_random_extension_events_dir_with_events(no_of_extensions, events_path, no_of_chars=10):
        if os.path.isdir(events_path):
            # If its a directory, get all files from that directory
            test_events_paths = glob.glob(os.path.join(events_path, "*"))
        else:
            test_events_paths = [events_path]

        extension_names = {}
        for i in range(no_of_extensions): # pylint: disable=unused-variable
            ext_name = "Microsoft.OSTCExtensions.{0}".format(''.join(random.sample(string.ascii_letters, no_of_chars)))
            no_of_good_events = 0

            for test_events_file_path in test_events_paths:
                if not os.path.exists(test_events_file_path) or not os.path.isfile(test_events_file_path):
                    continue
                no_of_good_events += TestExtensionTelemetryHandler._parse_file_and_count_good_events(test_events_file_path)
                events_dir = os.path.join(conf.get_ext_log_dir(), ext_name, EVENTS_DIRECTORY)
                fileutil.mkdir(events_dir)
                shutil.copy(test_events_file_path, events_dir)

            extension_names[ext_name] = no_of_good_events

        return extension_names

    @staticmethod
    def _get_no_of_events_from_body(body):
        return body.count("</Event>")

    @staticmethod
    def _replace_in_file(file_path, replace_from, replace_to):

        with open(file_path, 'r') as f: # pylint: disable=invalid-name
            content = f.read()

        content = content.replace(replace_from, replace_to)

        with open(file_path, 'w') as f: # pylint: disable=invalid-name
            f.write(content)

    @staticmethod
    def _get_handlers_with_version_from_event_body(event_body):
        event_with_name_and_versions = defaultdict(list)
        regex_pattern = r'<Param Name="EventName" Value="(.+?)-(.+?)" .* \/>'
        for body in event_body:
            body = TestExtensionTelemetryHandler._get_ustr_from_event_body(body)
            xml_doc = textutil.parse_doc(body)
            events = textutil.findall(xml_doc, "Event")

            for event in events:
                # Since this is a telemetry event, we should always have an EventName param in the event
                handler_name, version = re.search(regex_pattern, event.childNodes[0].nodeValue).groups()
                event_with_name_and_versions[handler_name].append(version)

        return event_with_name_and_versions

    @staticmethod
    def _get_param_value_from_event_body_if_exists(event_body, param_name):
        regex_pattern = r'<Param Name="{0}" Value=(\"|\')(?P<value>.+?)(\"|\') .* \/>'.format(param_name)
        param_values = []

        for body in event_body:
            body = TestExtensionTelemetryHandler._get_ustr_from_event_body(body)
            xml_doc = textutil.parse_doc(body)
            events = textutil.findall(xml_doc, "Event")

            for event in events:

                regex = re.search(regex_pattern, event.childNodes[0].nodeValue)
                if regex is None:
                    continue
                param_values.append(regex.group('value'))

        return param_values


    @contextlib.contextmanager
    def _create_extension_telemetry_processor(self):

        def http_post_handler(url, body, **__):
            if self.is_telemetry_request(url):
                extension_telemetry_processor.event_body.append(body)
                return MockHttpResponse(status=200)
            return None

        with mock_wire_protocol(DATA_FILE, http_post_handler=http_post_handler) as protocol:
            protocol_util = MagicMock()
            protocol_util.get_protocol = Mock(return_value=protocol)
            extension_telemetry_processor = ProcessExtensionTelemetry(protocol_util)
            extension_telemetry_processor.event_body = []
            yield extension_telemetry_processor

    def _assert_handler_data_in_event_body(self, telemetry_events, ext_names_with_count, expected_count=None):

        for ext_name, test_file_event_count in ext_names_with_count.items():
            # If expected_count is not given, then the take the no of good events in the test file as the source of truth
            count = expected_count if expected_count is not None else test_file_event_count
            if count == 0:
                self.assertNotIn(ext_name, telemetry_events,
                                 "Found telemetry events for unwanted extension {0}".format(ext_name))
                continue

            self.assertIn(ext_name, telemetry_events,
                          "Extension name: {0} not found in the Telemetry Events".format(ext_name))
            self.assertEqual(len(telemetry_events[ext_name]), count,
                             "No of good events for ext {0} do not match".format(ext_name))

    def _assert_param_in_events(self, event_body, param_key, param_value, min_count=1):

        param = TelemetryEventParam(param_key, param_value)
        param_str = event_param_to_v1(param)
        count = 0
        for body in event_body:
            body = TestExtensionTelemetryHandler._get_ustr_from_event_body(body)
            if count >= min_count:
                break
            count += body.count(param_str)

        self.assertGreaterEqual(count, min_count,
                                "'{0}' param only found {1} times in events. Min_count required: {2}".format(param_str,
                                                                                                             count,
                                                                                                             min_count))
    @staticmethod
    def _get_ustr_from_event_body(body):
        return body if (body is None or type(body) is ustr) else textutil.str_to_encoded_ustr(body) # pylint: disable=unidiomatic-typecheck

    @staticmethod
    def _is_string_in_event_body(event_body, expected_string):
        found = False
        for body in event_body:
            body = TestExtensionTelemetryHandler._get_ustr_from_event_body(body)
            if expected_string in body:
                found = True
                break

        return found

    def test_it_should_not_capture_malformed_events(self):
        with self._create_extension_telemetry_processor() as extension_telemetry_processor:
            bad_name_ext_with_count = self._create_random_extension_events_dir_with_events(2, self._MALFORMED_FILES)
            bad_json_ext_with_count = self._create_random_extension_events_dir_with_events(2, os.path.join(
                self._MALFORMED_FILES, "bad_json_files", "1591816395.json"))

            extension_telemetry_processor.run()
            telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)

            self._assert_handler_data_in_event_body(telemetry_events, bad_name_ext_with_count, expected_count=0)
            self._assert_handler_data_in_event_body(telemetry_events, bad_json_ext_with_count, expected_count=0)

    def test_it_should_capture_and_send_correct_events(self):

        with self._create_extension_telemetry_processor() as extension_telemetry_processor:

            ext_names_with_count = self._create_random_extension_events_dir_with_events(2, self._WELL_FORMED_FILES)
            ext_names_with_count.update(self._create_random_extension_events_dir_with_events(3, os.path.join(
                self._MIX_FILES, "1591835859.json")))
            extension_telemetry_processor.run()

            telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)

            self._assert_handler_data_in_event_body(telemetry_events, ext_names_with_count)

    def test_it_should_disregard_bad_events_and_keep_good_ones_in_a_mixed_file(self):
        with self._create_extension_telemetry_processor() as extension_telemetry_processor:
            extensions_with_count = self._create_random_extension_events_dir_with_events(2, self._MIX_FILES)
            extensions_with_count.update(self._create_random_extension_events_dir_with_events(3, os.path.join(
                self._MALFORMED_FILES, "bad_name_file.json")))

            extension_telemetry_processor.run()
            telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)

            self._assert_handler_data_in_event_body(telemetry_events, extensions_with_count)

    def test_it_should_limit_max_no_of_events_to_send_per_run_per_extension_and_report_event(self):
        max_events = 5
        with patch("azurelinuxagent.ga.extension_telemetry.add_log_event") as mock_event:
            with self._create_extension_telemetry_processor() as extension_telemetry_processor:
                with patch.object(extension_telemetry_processor, "_MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD", max_events):
                    ext_names_with_count = self._create_random_extension_events_dir_with_events(5, self._WELL_FORMED_FILES)
                    extension_telemetry_processor.run()

                    telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)
                    self._assert_handler_data_in_event_body(telemetry_events, ext_names_with_count, expected_count=max_events)

                pattern = r'Reached max count for the extension:\s*(?P<name>.+?);\s*.+'
                self._assert_event_reported(mock_event, ext_names_with_count, pattern)

    def test_it_should_send_the_latest_events(self):
        max_events = 5
        no_of_extension = 2
        test_guid = str(uuid.uuid4())

        with self._create_extension_telemetry_processor() as extension_telemetry_processor:
            with patch.object(extension_telemetry_processor, "_MAX_NUMBER_OF_EVENTS_PER_EXTENSION_PER_PERIOD", max_events):
                ext_names_with_count = self._create_random_extension_events_dir_with_events(no_of_extension, self._WELL_FORMED_FILES)

                for ext_name in ext_names_with_count.keys():
                    self._replace_in_file(
                        os.path.join(conf.get_ext_log_dir(), ext_name, EVENTS_DIRECTORY, "9999999999.json"),
                        replace_from='"{0}": ""'.format(ExtensionEventSchema.OperationId),
                        replace_to='"{0}": "{1}"'.format(ExtensionEventSchema.OperationId, test_guid))
                extension_telemetry_processor.run()

                telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)
                self._assert_handler_data_in_event_body(telemetry_events, ext_names_with_count,
                                                        expected_count=max_events)
                self._assert_param_in_events(extension_telemetry_processor.event_body,
                                             param_key=GuestAgentGenericLogsSchema.Context1,
                                             param_value="This is the latest event", min_count=no_of_extension*max_events)
                self._assert_param_in_events(extension_telemetry_processor.event_body,
                                             param_key=GuestAgentGenericLogsSchema.Context3, param_value=test_guid,
                                             min_count=no_of_extension*max_events)


    def test_it_should_parse_extension_event_irrespective_of_case(self):
        with self._create_extension_telemetry_processor() as extension_telemetry_processor:
            extensions_with_count = self._create_random_extension_events_dir_with_events(2, os.path.join(
                self._TEST_DATA_DIR, "different_cases"))

            extension_telemetry_processor.run()
            telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)

            self._assert_handler_data_in_event_body(telemetry_events, extensions_with_count)

    def test_it_should_parse_special_chars_properly(self):
        with self._create_extension_telemetry_processor() as extension_telemetry_processor:
            extensions_with_count = self._create_random_extension_events_dir_with_events(2, os.path.join(
                self._TEST_DATA_DIR, "special_chars"))

            extension_telemetry_processor.run()
            telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)

            self._assert_handler_data_in_event_body(telemetry_events, extensions_with_count)

    def _setup_and_assert_tests_for_max_sizes(self, no_of_extensions=2, expected_count=None):
        with self._create_extension_telemetry_processor() as extension_telemetry_processor:
            extensions_with_count = self._create_random_extension_events_dir_with_events(no_of_extensions,
                                                                                         os.path.join(
                                                                                             self._TEST_DATA_DIR,
                                                                                             "large_messages"))

            extension_telemetry_processor.run()
            telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)
            self._assert_handler_data_in_event_body(telemetry_events, extensions_with_count, expected_count)

            return extensions_with_count, extension_telemetry_processor.event_body

    def _assert_invalid_extension_error_event_reported(self, mock_event, handler_name_with_count, error, expected_drop_count=None):

        self.assertTrue(mock_event.called, "Even a single event not logged")
        patt = r'Extension:\s+(?P<name>Microsoft.OSTCExtensions.+?);.+\s*Reason:\s+\[InvalidExtensionEventError\](?P<reason>.+?):.+Dropped Count:\s*(?P<count>\d+)'
        for _, kwargs in mock_event.call_args_list:
            msg = kwargs['message']
            match = re.search(patt, msg, re.MULTILINE)
            if match is not None:
                self.assertEqual(match.group("reason").strip(), error, "Incorrect error")
                self.assertIn(match.group("name"), handler_name_with_count, "Extension event not found")
                count = handler_name_with_count.pop(match.group("name"))
                count = expected_drop_count if expected_drop_count is not None else count
                self.assertEqual(int(count), int(match.group("count")), "Dropped count doesnt match")

        self.assertEqual(len(handler_name_with_count), 0, "All extension events not matched")

    def _assert_event_reported(self, mock_event, handler_name_with_count, pattern):

        self.assertTrue(mock_event.called, "Even a single event not logged")
        for _, kwargs in mock_event.call_args_list:
            msg = kwargs['message']
            match = re.search(pattern, msg, re.MULTILINE)
            if match is not None:
                expected_handler_name = match.group("name")
                self.assertIn(expected_handler_name, handler_name_with_count, "Extension event not found")
                handler_name_with_count.pop(expected_handler_name)

        self.assertEqual(len(handler_name_with_count), 0, "All extension events not matched")

    def test_it_should_trim_message_if_more_than_limit(self):
        max_len = 100
        no_of_extensions = 2
        with patch("azurelinuxagent.ga.extension_telemetry.ProcessExtensionTelemetry._EXTENSION_EVENT_MAX_MSG_LEN", max_len):
            handler_name_with_count, event_body = self._setup_and_assert_tests_for_max_sizes() # pylint: disable=unused-variable
            context1_vals = self._get_param_value_from_event_body_if_exists(event_body,
                                                                            GuestAgentGenericLogsSchema.Context1)
            self.assertEqual(no_of_extensions, len(context1_vals),
                             "There should be {0} Context1 values".format(no_of_extensions))

            for val in context1_vals:
                self.assertLessEqual(len(val), max_len, "Message Length does not match")

    def test_it_should_skip_events_larger_than_max_size_and_report_event(self):
        max_size = 1000
        no_of_extensions = 3
        with patch("azurelinuxagent.ga.extension_telemetry.add_log_event") as mock_event:
            with patch("azurelinuxagent.ga.extension_telemetry.ProcessExtensionTelemetry._EXTENSION_EVENT_MAX_SIZE",
                       max_size):
                handler_name_with_count, _ = self._setup_and_assert_tests_for_max_sizes(no_of_extensions, expected_count=0)
                self._assert_invalid_extension_error_event_reported(mock_event, handler_name_with_count,
                                                                    error=InvalidExtensionEventError.OversizeEventError)

    def test_it_should_skip_large_files_greater_than_max_file_size_and_report_event(self):
        max_file_size = 10000
        no_of_extensions = 5
        with patch("azurelinuxagent.ga.extension_telemetry.add_log_event") as mock_event:
            with patch("azurelinuxagent.ga.extension_telemetry.ProcessExtensionTelemetry._EXTENSION_EVENT_FILE_MAX_SIZE",
                       max_file_size):
                handler_name_with_count, _ = self._setup_and_assert_tests_for_max_sizes(no_of_extensions, expected_count=0)

                pattern = r'Skipping file:\s*{0}/(?P<name>.+?)/{1}.+'.format(conf.get_ext_log_dir(), EVENTS_DIRECTORY)
                self._assert_event_reported(mock_event, handler_name_with_count, pattern)

    def test_it_should_map_extension_event_json_correctly_to_telemetry_event(self): # pylint: disable=too-many-locals

        # EventName maps to HandlerName + '-' + Version from event file
        expected_mapping = {
            GuestAgentGenericLogsSchema.EventName: ExtensionEventSchema.Version,
            GuestAgentGenericLogsSchema.CapabilityUsed: ExtensionEventSchema.EventLevel,
            GuestAgentGenericLogsSchema.TaskName: ExtensionEventSchema.TaskName,
            GuestAgentGenericLogsSchema.Context1: ExtensionEventSchema.Message,
            GuestAgentGenericLogsSchema.Context2: ExtensionEventSchema.Timestamp,
            GuestAgentGenericLogsSchema.Context3: ExtensionEventSchema.OperationId,
            CommonTelemetryEventSchema.EventPid: ExtensionEventSchema.EventPid,
            CommonTelemetryEventSchema.EventTid: ExtensionEventSchema.EventTid
        }

        with self._create_extension_telemetry_processor() as extension_telemetry_processor:
            test_file = os.path.join(self._WELL_FORMED_FILES, "1592355539.json")
            handler_name = list(self._create_random_extension_events_dir_with_events(1, test_file))[0]
            extension_telemetry_processor.run()

            telemetry_event_map = defaultdict(list)
            for telemetry_event_key in expected_mapping:
                telemetry_event_map[telemetry_event_key] = self._get_param_value_from_event_body_if_exists(
                    extension_telemetry_processor.event_body, telemetry_event_key)

            with open(test_file, 'r') as event_file:
                data = json.load(event_file)

            extension_event_map = defaultdict(list)
            for extension_event in data:
                for event_key in extension_event:
                    extension_event_map[event_key].append(extension_event[event_key])

            for telemetry_key in expected_mapping:
                extension_event_key = expected_mapping[telemetry_key]
                telemetry_data = telemetry_event_map[telemetry_key]

                # EventName = "HandlerName-Version" from Extensions
                extension_data = ["{0}-{1}".format(handler_name, v) for v in extension_event_map[
                    extension_event_key]] if telemetry_key == GuestAgentGenericLogsSchema.EventName else \
                extension_event_map[extension_event_key]

                self.assertEqual(telemetry_data, extension_data,
                                 "The data for {0} and {1} doesn't map properly".format(telemetry_key,
                                                                                        extension_event_key))

    def test_it_should_always_cleanup_files_on_good_and_bad_cases(self):
        with self._create_extension_telemetry_processor() as extension_telemetry_processor:
            extensions_with_count = self._create_random_extension_events_dir_with_events(2, os.path.join(
                self._TEST_DATA_DIR, "large_messages"))
            extensions_with_count.update(self._create_random_extension_events_dir_with_events(3, self._MALFORMED_FILES))
            extensions_with_count.update(self._create_random_extension_events_dir_with_events(4, self._WELL_FORMED_FILES))
            extensions_with_count.update(self._create_random_extension_events_dir_with_events(1, self._MIX_FILES))

            # Create random files in the events directory for each extension just to ensure that we delete them later
            for handler_name in extensions_with_count.keys():
                file_name = os.path.join(conf.get_ext_log_dir(), handler_name, EVENTS_DIRECTORY,
                                         ''.join(random.sample(string.ascii_letters, 10)))
                with open(file_name, 'a') as random_file:
                    random_file.write('1*2*3' * 100)

            extension_telemetry_processor.run()
            telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)

            self._assert_handler_data_in_event_body(telemetry_events, extensions_with_count)

            for handler_name in extensions_with_count.keys():
                events_path = os.path.join(conf.get_ext_log_dir(), handler_name, EVENTS_DIRECTORY)
                self.assertTrue(os.path.exists(events_path), "{0} dir doesn't exist".format(events_path))
                self.assertEqual(0, len(os.listdir(events_path)), "There should be no files inside the events dir")

    def test_it_should_skip_unwanted_parameters_in_event_file(self):
        extra_params = ["SomethingNewButNotCool", "SomethingVeryWeird"]
        param_format = '<Param Name="{0}"'
        with self._create_extension_telemetry_processor() as extension_telemetry_processor:
            extensions_with_count= self._create_random_extension_events_dir_with_events(3, os.path.join(
                self._TEST_DATA_DIR, "extra_parameters"))

            extension_telemetry_processor.run()
            telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)

            self._assert_handler_data_in_event_body(telemetry_events, extensions_with_count)
            self.assertFalse(self._is_string_in_event_body(extension_telemetry_processor.event_body,
                                                           param_format.format(extra_params[0])),
                             "Unwanted param {0} found".format(extra_params[0]))
            self.assertFalse(self._is_string_in_event_body(extension_telemetry_processor.event_body,
                                                           param_format.format(extra_params[1])),
                             "Unwanted param {0} found".format(extra_params[1]))

    def test_it_should_not_send_events_which_dont_have_all_required_keys_and_report_event(self):
        with patch("azurelinuxagent.ga.extension_telemetry.add_log_event") as mock_event:
            with self._create_extension_telemetry_processor() as extension_telemetry_processor:
                extensions_with_count = self._create_random_extension_events_dir_with_events(3, os.path.join(
                    self._TEST_DATA_DIR, "missing_parameters"))

                extension_telemetry_processor.run()
                telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)

                self._assert_handler_data_in_event_body(telemetry_events, extensions_with_count, expected_count=0)
                self.assertTrue(mock_event.called, "Even a single event not logged")

                for _, kwargs in mock_event.call_args_list:
                    # Example:
                    #['Dropped events for Extension: Microsoft.OSTCExtensions.ZJQRNqbKtP; Details:',
                    # 'Reason: [InvalidExtensionEventError] MissingKeyError: eventpid not found; Dropped Count: 2',
                    # 'Reason: [InvalidExtensionEventError] MissingKeyError: Message not found; Dropped Count: 2',
                    # 'Reason: [InvalidExtensionEventError] MissingKeyError: version not found; Dropped Count: 3']
                    msg = kwargs['message'].split("\n")
                    ext_name = re.search(r'Dropped events for Extension:\s+(?P<name>Microsoft.OSTCExtensions.+?);.+', msg.pop(0))
                    if ext_name is not None:
                        ext_name = ext_name.group('name')
                        self.assertIn(ext_name, extensions_with_count, "Extension {0} not found".format(ext_name))
                        patt = r'\s*Reason:\s+\[InvalidExtensionEventError\](?P<reason>.+?):\s*(?P<key>.+?)\s+not found;\s+Dropped Count:\s*(?P<count>\d+)'
                        expected_error_drop_count = {
                            ExtensionEventSchema.EventPid.lower(): 2,
                            ExtensionEventSchema.Message.lower(): 2,
                            ExtensionEventSchema.Version.lower(): 3
                        }
                        for m in msg: # pylint: disable=invalid-name
                            match = re.search(patt, m)
                            self.assertIsNotNone(match, "No InvalidExtensionEventError errors reported")
                            self.assertEqual(match.group("reason").strip(), InvalidExtensionEventError.MissingKeyError,
                                             "Error is not a {0}".format(InvalidExtensionEventError.MissingKeyError))
                            observerd_error = match.group("key").lower()
                            self.assertIn(observerd_error, expected_error_drop_count, "Unexpected error reported")
                            self.assertEqual(expected_error_drop_count.pop(observerd_error), int(match.group("count")),
                                             "Unequal no of dropped events")
                        self.assertEqual(len(expected_error_drop_count), 0, "All errros not found yet")
                        del extensions_with_count[ext_name]

                self.assertEqual(len(extensions_with_count), 0, "All extension events not matched")

    def test_it_should_not_send_event_where_message_is_empty_and_report_event(self):
        with patch("azurelinuxagent.ga.extension_telemetry.add_log_event") as mock_event:
            with self._create_extension_telemetry_processor() as extension_telemetry_processor:
                extensions_with_count = self._create_random_extension_events_dir_with_events(3, os.path.join(
                    self._TEST_DATA_DIR, "empty_message"))

                extension_telemetry_processor.run()
                telemetry_events = self._get_handlers_with_version_from_event_body(extension_telemetry_processor.event_body)

                self._assert_handler_data_in_event_body(telemetry_events, extensions_with_count, expected_count=0)
                self._assert_invalid_extension_error_event_reported(mock_event, extensions_with_count,
                                                                    InvalidExtensionEventError.EmptyMessageError,
                                                                    expected_drop_count=1)