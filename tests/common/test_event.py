# Copyright 2017 Microsoft Corporation
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

from __future__ import print_function

import json
import os
import threading
from datetime import datetime, timedelta

from azurelinuxagent.common import event, logger
from azurelinuxagent.common.event import add_event, elapsed_milliseconds, EventLogger, report_metric, WALAEventOperation
from azurelinuxagent.common.exception import EventError
from azurelinuxagent.common.future import OrderedDict, ustr
from azurelinuxagent.common.protocol.wire import GoalState
from azurelinuxagent.common.telemetryevent import TelemetryEventParam
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.extensionprocessutil import read_output
from azurelinuxagent.common.version import CURRENT_AGENT, CURRENT_VERSION
from azurelinuxagent.ga.monitor import MonitorHandler
from tests.tools import AgentTestCase, data_dir, load_data, Mock, patch


class TestEvent(AgentTestCase):
    def test_add_event_should_read_container_id_from_process_environment(self):
        tmp_file = os.path.join(self.tmp_dir, "tmp_file")

        def patch_save_event(json_data):
            fileutil.write_file(tmp_file, json_data)

        with patch("azurelinuxagent.common.event.EventLogger.save_event", side_effect=patch_save_event):
            # No container id is set
            os.environ.pop(event.CONTAINER_ID_ENV_VARIABLE, None)
            event.add_event(name='dummy_name')
            data = fileutil.read_file(tmp_file)
            self.assertTrue('{"name": "ContainerId", "value": "UNINITIALIZED"}' in data or
                            '{"value": "UNINITIALIZED", "name": "ContainerId"}' in data)

            # Container id is set as an environment variable explicitly
            os.environ[event.CONTAINER_ID_ENV_VARIABLE] = '424242'
            event.add_event(name='dummy_name')
            data = fileutil.read_file(tmp_file)
            self.assertTrue('{{"name": "ContainerId", "value": "{0}"}}'.format(
                                os.environ[event.CONTAINER_ID_ENV_VARIABLE]) in data or
                            '{{"value": "{0}", "name": "ContainerId"}}'.format(
                                os.environ[event.CONTAINER_ID_ENV_VARIABLE]) in data)

            # Container id is set as an environment variable when parsing the goal state
            xml_text = load_data("wire/goal_state.xml")
            goal_state = GoalState(xml_text)

            container_id = goal_state.container_id
            event.add_event(name='dummy_name')
            data = fileutil.read_file(tmp_file)
            self.assertTrue('{{"name": "ContainerId", "value": "{0}"}}'.format(container_id) in data or
                            '{{"value": "{0}", "name": "ContainerId"}}'.format(container_id), data)

            # Container id is updated as the goal state changes, both in telemetry event and in environment variables
            new_container_id = "z6d5526c-5ac2-4200-b6e2-56f2b70c5ab2"
            xml_text = load_data("wire/goal_state.xml")
            xml_text_updated = xml_text.replace("c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2", new_container_id)
            goal_state = GoalState(xml_text_updated)

            event.add_event(name='dummy_name')
            data = fileutil.read_file(tmp_file)

            # Assert both the environment variable and telemetry event got updated
            self.assertEquals(os.environ[event.CONTAINER_ID_ENV_VARIABLE], new_container_id)
            self.assertTrue('{{"name": "ContainerId", "value": "{0}"}}'.format(new_container_id) in data or
                            '{{"value": "{0}", "name": "ContainerId"}}'.format(new_container_id), data)

        os.environ.pop(event.CONTAINER_ID_ENV_VARIABLE)

    def test_add_event_should_handle_event_errors(self):
        with patch("azurelinuxagent.common.utils.fileutil.mkdir", side_effect=OSError):
            with patch('azurelinuxagent.common.logger.periodic_error') as mock_logger_periodic_error:
                add_event('test', message='test event')

                # The event shouldn't have been created
                self.assertTrue(len(os.listdir(self.tmp_dir)) == 0)

                # The exception should have been caught and logged
                args = mock_logger_periodic_error.call_args
                exception_message = args[0][1]
                self.assertIn("[EventError] Failed to create events folder", exception_message)

    def test_event_status_event_marked(self):
        es = event.__event_status__

        self.assertFalse(es.event_marked("Foo", "1.2", "FauxOperation"))
        es.mark_event_status("Foo", "1.2", "FauxOperation", True)
        self.assertTrue(es.event_marked("Foo", "1.2", "FauxOperation"))

        event.__event_status__ = event.EventStatus()
        event.init_event_status(self.tmp_dir)
        es = event.__event_status__
        self.assertTrue(es.event_marked("Foo", "1.2", "FauxOperation"))

    def test_event_status_defaults_to_success(self):
        es = event.__event_status__
        self.assertTrue(es.event_succeeded("Foo", "1.2", "FauxOperation"))

    def test_event_status_records_status(self):
        es = event.EventStatus()

        es.mark_event_status("Foo", "1.2", "FauxOperation", True)
        self.assertTrue(es.event_succeeded("Foo", "1.2", "FauxOperation"))

        es.mark_event_status("Foo", "1.2", "FauxOperation", False)
        self.assertFalse(es.event_succeeded("Foo", "1.2", "FauxOperation"))

    def test_event_status_preserves_state(self):
        es = event.__event_status__

        es.mark_event_status("Foo", "1.2", "FauxOperation", False)
        self.assertFalse(es.event_succeeded("Foo", "1.2", "FauxOperation"))

        event.__event_status__ = event.EventStatus()
        event.init_event_status(self.tmp_dir)
        es = event.__event_status__
        self.assertFalse(es.event_succeeded("Foo", "1.2", "FauxOperation"))

    def test_should_emit_event_ignores_unknown_operations(self):
        event.__event_status__ = event.EventStatus()

        self.assertTrue(event.should_emit_event("Foo", "1.2", "FauxOperation", True))
        self.assertTrue(event.should_emit_event("Foo", "1.2", "FauxOperation", False))

        # Marking the event has no effect
        event.mark_event_status("Foo", "1.2", "FauxOperation", True)

        self.assertTrue(event.should_emit_event("Foo", "1.2", "FauxOperation", True))
        self.assertTrue(event.should_emit_event("Foo", "1.2", "FauxOperation", False))

    def test_should_emit_event_handles_known_operations(self):
        event.__event_status__ = event.EventStatus()

        # Known operations always initially "fire"
        for op in event.__event_status_operations__:
            self.assertTrue(event.should_emit_event("Foo", "1.2", op, True))
            self.assertTrue(event.should_emit_event("Foo", "1.2", op, False))

        # Note a success event...
        for op in event.__event_status_operations__:
            event.mark_event_status("Foo", "1.2", op, True)

        # Subsequent success events should not fire, but failures will
        for op in event.__event_status_operations__:
            self.assertFalse(event.should_emit_event("Foo", "1.2", op, True))
            self.assertTrue(event.should_emit_event("Foo", "1.2", op, False))

        # Note a failure event...
        for op in event.__event_status_operations__:
            event.mark_event_status("Foo", "1.2", op, False)

        # Subsequent success events fire and failure do not
        for op in event.__event_status_operations__:
            self.assertTrue(event.should_emit_event("Foo", "1.2", op, True))
            self.assertFalse(event.should_emit_event("Foo", "1.2", op, False))

    @patch('azurelinuxagent.common.event.EventLogger')
    @patch('azurelinuxagent.common.logger.error')
    @patch('azurelinuxagent.common.logger.warn')
    @patch('azurelinuxagent.common.logger.info')
    def test_should_log_errors_if_failed_operation_and_empty_event_dir(self,
                                                                       mock_logger_info,
                                                                       mock_logger_warn,
                                                                       mock_logger_error,
                                                                       mock_reporter):
        mock_reporter.event_dir = None
        add_event("dummy name",
                  version=CURRENT_VERSION,
                  op=WALAEventOperation.Download,
                  is_success=False,
                  message="dummy event message",
                  reporter=mock_reporter)

        self.assertEquals(1, mock_logger_error.call_count)
        self.assertEquals(1, mock_logger_warn.call_count)
        self.assertEquals(0, mock_logger_info.call_count)

        args = mock_logger_error.call_args[0]
        self.assertEquals(('dummy name', 'Download', 'dummy event message', 0), args[1:])

    @patch('azurelinuxagent.common.event.EventLogger')
    @patch('azurelinuxagent.common.logger.error')
    @patch('azurelinuxagent.common.logger.warn')
    @patch('azurelinuxagent.common.logger.info')
    def test_should_log_errors_if_failed_operation_and_not_empty_event_dir(self,
                                                                           mock_logger_info,
                                                                           mock_logger_warn,
                                                                           mock_logger_error,
                                                                           mock_reporter):
        mock_reporter.event_dir = "dummy"

        with patch("azurelinuxagent.common.event.should_emit_event", return_value=True) as mock_should_emit_event:
            with patch("azurelinuxagent.common.event.mark_event_status"):
                with patch("azurelinuxagent.common.event.EventLogger._add_event"):
                    add_event("dummy name",
                              version=CURRENT_VERSION,
                              op=WALAEventOperation.Download,
                              is_success=False,
                              message="dummy event message")

                    self.assertEquals(1, mock_should_emit_event.call_count)
                    self.assertEquals(1, mock_logger_error.call_count)
                    self.assertEquals(0, mock_logger_warn.call_count)
                    self.assertEquals(0, mock_logger_info.call_count)

                    args = mock_logger_error.call_args[0]
                    self.assertEquals(('dummy name', 'Download', 'dummy event message', 0), args[1:])

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    def test_periodic_emits_if_not_previously_sent(self, mock_event):
        event.__event_logger__.reset_periodic()

        event.add_periodic(logger.EVERY_DAY, "FauxEvent")
        self.assertEqual(1, mock_event.call_count)

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    def test_periodic_does_not_emit_if_previously_sent(self, mock_event):
        event.__event_logger__.reset_periodic()

        event.add_periodic(logger.EVERY_DAY, "FauxEvent")
        self.assertEqual(1, mock_event.call_count)

        event.add_periodic(logger.EVERY_DAY, "FauxEvent")
        self.assertEqual(1, mock_event.call_count)

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    def test_periodic_emits_if_forced(self, mock_event):
        event.__event_logger__.reset_periodic()

        event.add_periodic(logger.EVERY_DAY, "FauxEvent")
        self.assertEqual(1, mock_event.call_count)

        event.add_periodic(logger.EVERY_DAY, "FauxEvent", force=True)
        self.assertEqual(2, mock_event.call_count)

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    def test_periodic_emits_after_elapsed_delta(self, mock_event):
        event.__event_logger__.reset_periodic()

        event.add_periodic(logger.EVERY_DAY, "FauxEvent")
        self.assertEqual(1, mock_event.call_count)

        event.add_periodic(logger.EVERY_DAY, "FauxEvent")
        self.assertEqual(1, mock_event.call_count)

        h = hash("FauxEvent"+WALAEventOperation.Unknown+ustr(True))
        event.__event_logger__.periodic_events[h] = \
            datetime.now() - logger.EVERY_DAY - logger.EVERY_HOUR
        event.add_periodic(logger.EVERY_DAY, "FauxEvent")
        self.assertEqual(2, mock_event.call_count)

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    def test_periodic_forwards_args(self, mock_event):
        event.__event_logger__.reset_periodic()
        event_time = datetime.utcnow().__str__()
        event.add_periodic(logger.EVERY_DAY, "FauxEvent", op=WALAEventOperation.Log, is_success=True, duration=0,
                           version=str(CURRENT_VERSION), message="FauxEventMessage", evt_type="", is_internal=False,
                           log_event=True, force=False)
        mock_event.assert_called_once_with("FauxEvent", op=WALAEventOperation.Log, is_success=True, duration=0,
                                           version=str(CURRENT_VERSION), message="FauxEventMessage", evt_type="",
                                           is_internal=False, log_event=True)

    @patch("azurelinuxagent.common.event.datetime")
    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    def test_periodic_forwards_args_default_values(self, mock_event, mock_datetime):
        event.__event_logger__.reset_periodic()
        event.add_periodic(logger.EVERY_DAY, "FauxEvent", message="FauxEventMessage")
        mock_event.assert_called_once_with("FauxEvent", op=WALAEventOperation.Unknown, is_success=True, duration=0,
                                           version=str(CURRENT_VERSION), message="FauxEventMessage", evt_type="",
                                           is_internal=False, log_event=True)

    @patch("azurelinuxagent.common.event.EventLogger.add_event")
    def test_add_event_default_variables(self, mock_add_event):
        add_event('test', message='test event')
        mock_add_event.assert_called_once_with('test', duration=0, evt_type='', is_internal=False, is_success=True,
                                               log_event=True, message='test event', op=WALAEventOperation.Unknown,
                                               version=str(CURRENT_VERSION))

    def test_save_event(self):
        add_event('test', message='test event')
        self.assertTrue(len(os.listdir(self.tmp_dir)) == 1)

        # checking the extension of the file created.
        for filename in os.listdir(self.tmp_dir):
            self.assertEqual(".tld", filename[-4:])

    def test_save_event_message_with_non_ascii_characters(self):
        test_data_dir = os.path.join(data_dir, "events", "collect_and_send_extension_stdout_stderror")
        msg = ""

        with open(os.path.join(test_data_dir, "dummy_stdout_with_non_ascii_characters"), mode="r+b") as stdout:
            with open(os.path.join(test_data_dir, "dummy_stderr_with_non_ascii_characters"), mode="r+b") as stderr:
                msg = read_output(stdout, stderr)

        duration = elapsed_milliseconds(datetime.utcnow())
        log_msg = "{0}\n{1}".format("DummyCmd", "\n".join([line for line in msg.split('\n') if line != ""]))

        with patch("azurelinuxagent.common.event.datetime") as patch_datetime:
            patch_datetime.utcnow = Mock(return_value=datetime.strptime("2019-01-01 01:30:00",
                                                                        '%Y-%m-%d %H:%M:%S'))
            with patch('os.getpid', return_value=42):
                with patch("threading.Thread.getName", return_value="HelloWorldTask"):
                    add_event('test_extension', message=log_msg, duration=duration)

        for tld_file in os.listdir(self.tmp_dir):
            event_str = MonitorHandler.collect_event(os.path.join(self.tmp_dir, tld_file))
            event_json = json.loads(event_str)

            self.assertEqual(len(event_json["parameters"]), 15)

            # Checking the contents passed above, and also validating the default values that were passed in.
            for i in event_json["parameters"]:
                if i["name"] == "Name":
                    self.assertEqual(i["value"], "test_extension")
                elif i["name"] == "Message":
                    self.assertEqual(i["value"], log_msg)
                elif i["name"] == "Version":
                    self.assertEqual(i["value"], str(CURRENT_VERSION))
                elif i['name'] == 'IsInternal':
                    self.assertEqual(i['value'], False)
                elif i['name'] == 'Operation':
                    self.assertEqual(i['value'], 'Unknown')
                elif i['name'] == 'OperationSuccess':
                    self.assertEqual(i['value'], True)
                elif i['name'] == 'Duration':
                    self.assertEqual(i['value'], 0)
                elif i['name'] == 'ExtensionType':
                    self.assertEqual(i['value'], '')
                elif i['name'] == 'ContainerId':
                    self.assertEqual(i['value'], 'UNINITIALIZED')
                elif i['name'] == 'OpcodeName':
                    self.assertEqual(i['value'], '2019-01-01 01:30:00')
                elif i['name'] == 'EventTid':
                    self.assertEqual(i['value'], threading.current_thread().ident)
                elif i['name'] == 'EventPid':
                    self.assertEqual(i['value'], 42)
                elif i['name'] == 'TaskName':
                    self.assertEqual(i['value'], 'HelloWorldTask')
                elif i['name'] == 'KeywordName':
                    self.assertEqual(i['value'], '')
                elif i['name'] == 'GAVersion':
                    self.assertEqual(i['value'], str(CURRENT_AGENT))
                else:
                    self.assertFalse(True, "Contains a field outside the defaults expected. Field Name: {0}".
                                     format(i['name']))

    def test_save_event_message_with_decode_errors(self):
        tmp_file = os.path.join(self.tmp_dir, "tmp_file")
        fileutil.write_file(tmp_file, "This is not JSON data", encoding="utf-16")

        for tld_file in os.listdir(self.tmp_dir):
            try:
                MonitorHandler.collect_event(os.path.join(self.tmp_dir, tld_file))
            except Exception as e:
                self.assertIsInstance(e, EventError)

    def test_save_event_rollover(self):
        # We keep 1000 events only, and the older ones are removed.

        num_of_events = 999
        add_event('test', message='first event')  # this makes number of events to num_of_events + 1.
        for i in range(num_of_events):
            add_event('test', message='test event {0}'.format(i))

        num_of_events += 1 # adding the first add_event.

        events = os.listdir(self.tmp_dir)
        events.sort()
        self.assertTrue(len(events) == num_of_events, "{0} is not equal to {1}".format(len(events), num_of_events))

        first_event = os.path.join(self.tmp_dir, events[0])
        with open(first_event) as first_fh:
            first_event_text = first_fh.read()
            self.assertTrue('first event' in first_event_text)

        add_event('test', message='last event')
        # Adding the above event displaces the first_event

        events = os.listdir(self.tmp_dir)
        events.sort()
        self.assertTrue(len(events) == num_of_events,
                        "{0} events found, {1} expected".format(len(events), num_of_events))

        first_event = os.path.join(self.tmp_dir, events[0])
        with open(first_event) as first_fh:
            first_event_text = first_fh.read()
            self.assertFalse('first event' in first_event_text, "'first event' not in {0}".format(first_event_text))
            self.assertTrue('test event 0' in first_event_text)

        last_event = os.path.join(self.tmp_dir, events[-1])
        with open(last_event) as last_fh:
            last_event_text = last_fh.read()
            self.assertTrue('last event' in last_event_text)

    def test_save_event_cleanup(self):
        for i in range(0, 2000):
            evt = os.path.join(self.tmp_dir, '{0}.tld'.format(ustr(1491004920536531 + i)))
            with open(evt, 'w') as fh:
                fh.write('test event {0}'.format(i))

        events = os.listdir(self.tmp_dir)
        self.assertTrue(len(events) == 2000, "{0} events found, 2000 expected".format(len(events)))
        add_event('test', message='last event')

        events = os.listdir(self.tmp_dir)
        events.sort()
        self.assertTrue(len(events) == 1000, "{0} events found, 1000 expected".format(len(events)))
        first_event = os.path.join(self.tmp_dir, events[0])
        with open(first_event) as first_fh:
            first_event_text = first_fh.read()
            self.assertTrue('test event 1001' in first_event_text)

        last_event = os.path.join(self.tmp_dir, events[-1])
        with open(last_event) as last_fh:
            last_event_text = last_fh.read()
            self.assertTrue('last event' in last_event_text)

    def test_elapsed_milliseconds(self):
        utc_start = datetime.utcnow() + timedelta(days=1)
        self.assertEqual(0, elapsed_milliseconds(utc_start))

    def _assert_default_params_get_correctly_added(self, param_list_actual, parameters_expected):
        default_parameters_expected_names = set(parameters_expected.keys())

        # Converting list of TelemetryEventParam into a dictionary, for easier look up of values.
        param_list_dict = OrderedDict([(param.name, param.value) for param in param_list_actual])

        counter = 0
        for p in default_parameters_expected_names:
            self.assertIn(p, param_list_dict)
            self.assertEqual(param_list_dict[p], parameters_expected[p])
            counter += 1

        self.assertEqual(len(default_parameters_expected_names), counter)

    @patch("azurelinuxagent.common.event.get_container_id_from_env", return_value="TEST_CONTAINER_ID")
    def test_add_default_parameters_to_extension_event(self, *args):
        default_parameters_expected = {"GAVersion": CURRENT_AGENT, 'ContainerId': "TEST_CONTAINER_ID", 'OpcodeName': "",
                                       'EventTid': 0, 'EventPid': 0, "TaskName": "", "KeywordName": ""}

        # When no values are populated in the TelemetryEventParamList.
        extension_param_list_empty = EventLogger.add_default_parameters_to_event([], set_values_for_agent=False)
        self._assert_default_params_get_correctly_added(extension_param_list_empty, default_parameters_expected)

        # When some values are already populated in the TelemetryEventParamList.
        extension_param_list_populated = [TelemetryEventParam('Name', "DummyExtension"),
                                          TelemetryEventParam('Version', CURRENT_VERSION),
                                          TelemetryEventParam('Operation', "DummyOperation"),
                                          TelemetryEventParam('OperationSuccess', True),
                                          TelemetryEventParam('Message', "TestMessage"),
                                          TelemetryEventParam('Duration', 10), TelemetryEventParam('ExtensionType', ''),
                                          TelemetryEventParam('OpcodeName', '')]
        extension_param_list_with_defaults = EventLogger.add_default_parameters_to_event(extension_param_list_populated,
                                                                                         set_values_for_agent=False)
        self._assert_default_params_get_correctly_added(extension_param_list_with_defaults, default_parameters_expected)

        parameters_expected = {"GAVersion": CURRENT_AGENT, 'ContainerId': "TEST_CONTAINER_ID", 'OpcodeName': "",
                               'EventTid': 100, 'EventPid': 10, "TaskName": "", "KeywordName": ""}

        # When some values are already populated in the TelemetryEventParamList.
        extension_param_list_populated = [TelemetryEventParam('Name', "DummyExtension"),
                                          TelemetryEventParam('Version', CURRENT_VERSION),
                                          TelemetryEventParam('Operation', "DummyOperation"),
                                          TelemetryEventParam('OperationSuccess', True),
                                          TelemetryEventParam('Message', "TestMessage"),
                                          TelemetryEventParam('Duration', 10),
                                          TelemetryEventParam('ExtensionType', ''),
                                          TelemetryEventParam('OpcodeName', ''),
                                          TelemetryEventParam('EventTid', 100),
                                          TelemetryEventParam('EventPid', 10)]
        extension_param_list_with_defaults = EventLogger.add_default_parameters_to_event(extension_param_list_populated,
                                                                                         set_values_for_agent=False)
        self._assert_default_params_get_correctly_added(extension_param_list_with_defaults,
                                                        parameters_expected)

    @patch("threading.Thread.getName", return_value="HelloWorldTask")
    @patch('os.getpid', return_value=42)
    @patch("azurelinuxagent.common.event.get_container_id_from_env", return_value="TEST_CONTAINER_ID")
    @patch("azurelinuxagent.common.event.datetime")
    def test_add_default_parameters_to_agent_event(self, patch_datetime, *args):
        patch_datetime.utcnow = Mock(return_value=datetime.strptime("2019-01-01 01:30:00",
                                                                    '%Y-%m-%d %H:%M:%S'))
        default_parameters_expected = {"GAVersion": CURRENT_AGENT,
                                       'ContainerId': "TEST_CONTAINER_ID",
                                       'OpcodeName': "2019-01-01 01:30:00",
                                       'EventTid': threading.current_thread().ident,
                                       'EventPid': 42,
                                       "TaskName": "HelloWorldTask",
                                       "KeywordName": ""}
        agent_param_list_empty = EventLogger.add_default_parameters_to_event([], set_values_for_agent=True)
        self._assert_default_params_get_correctly_added(agent_param_list_empty, default_parameters_expected)

        # When some values are already populated in the TelemetryEventParamList.
        agent_param_list_populated = [TelemetryEventParam('Name', "DummyExtension"),
                                      TelemetryEventParam('Version', CURRENT_VERSION),
                                      TelemetryEventParam('Operation', "DummyOperation"),
                                      TelemetryEventParam('OperationSuccess', True),
                                      TelemetryEventParam('Message', "TestMessage"),
                                      TelemetryEventParam('Duration', 10), TelemetryEventParam('ExtensionType', ''),
                                      TelemetryEventParam('OpcodeName', '')]
        agent_param_list_after_defaults_added = EventLogger.add_default_parameters_to_event(agent_param_list_populated,
                                                                                            set_values_for_agent=True)
        self._assert_default_params_get_correctly_added(agent_param_list_after_defaults_added,
                                                        default_parameters_expected)

        # When some values are already populated in the TelemetryEventParamList, along with some
        # default values already populated and it should be replaced, when set_values_for_agent=True
        agent_param_list_populated = [TelemetryEventParam('Name', "DummyExtension"),
                                      TelemetryEventParam('Version', CURRENT_VERSION),
                                      TelemetryEventParam('Operation', "DummyOperation"),
                                      TelemetryEventParam('OperationSuccess', True),
                                      TelemetryEventParam('Message', "TestMessage"),
                                      TelemetryEventParam('Duration', 10), TelemetryEventParam('ExtensionType', ''),
                                      TelemetryEventParam('OpcodeName', 'timestamp'),
                                      TelemetryEventParam('ContainerId', 'SOME-CONTAINER'),
                                      TelemetryEventParam('EventTid', 10101010), TelemetryEventParam('EventPid', 110),
                                      TelemetryEventParam('TaskName', 'Test-TaskName')]

        agent_param_list_after_defaults_added = EventLogger.add_default_parameters_to_event(agent_param_list_populated,
                                                                                            set_values_for_agent=True)
        self._assert_default_params_get_correctly_added(agent_param_list_after_defaults_added,
                                                        default_parameters_expected)


class TestMetrics(AgentTestCase):
    @patch('azurelinuxagent.common.event.EventLogger.save_event')
    def test_report_metric(self, mock_event):
        event.report_metric("cpu", "%idle", "_total", 10.0)
        self.assertEqual(1, mock_event.call_count)
        event_json = mock_event.call_args[0][0]
        self.assertIn(event.TELEMETRY_EVENT_PROVIDER_ID, event_json)
        self.assertIn("%idle", event_json)
        import json
        event_dictionary = json.loads(event_json)
        self.assertEqual(event_dictionary['providerId'], event.TELEMETRY_EVENT_PROVIDER_ID)
        for parameter in event_dictionary["parameters"]:
            if parameter['name'] == 'Counter':
                self.assertEqual(parameter['value'], '%idle')
                break
        else:
            self.fail("Counter '%idle' not found in event parameters: {0}".format(repr(event_dictionary)))

    def test_save_metric(self):
        category_present, counter_present, instance_present, value_present = False, False, False, False
        report_metric("DummyCategory", "DummyCounter", "DummyInstance", 100)
        self.assertTrue(len(os.listdir(self.tmp_dir)) == 1)

        # checking the extension of the file created.
        for filename in os.listdir(self.tmp_dir):
            self.assertEqual(".tld", filename[-4:])
            perf_metric_event = json.loads(fileutil.read_file(os.path.join(self.tmp_dir, filename)))
            self.assertEqual(perf_metric_event["eventId"], event.TELEMETRY_METRICS_EVENT_ID)
            self.assertEqual(perf_metric_event["providerId"], event.TELEMETRY_EVENT_PROVIDER_ID)
            for i in perf_metric_event["parameters"]:
                self.assertIn(i["name"], ["Category", "Counter", "Instance", "Value", "GAVersion", "ContainerId",
                                          "OpcodeName", "EventTid", "EventPid", "TaskName", "KeywordName"])
                if i["name"] == "Category":
                    self.assertEqual(i["value"], "DummyCategory")
                    category_present = True
                if i["name"] == "Counter":
                    self.assertEqual(i["value"], "DummyCounter")
                    counter_present = True
                if i["name"] == "Instance":
                    self.assertEqual(i["value"], "DummyInstance")
                    instance_present = True
                if i["name"] == "Value":
                    self.assertEqual(i["value"], 100)
                    value_present = True
            
            self.assertTrue(category_present and counter_present and instance_present and value_present)

    def test_cleanup_message(self):
        ev_logger = event.EventLogger()

        self.assertEqual(None, ev_logger._clean_up_message(None))
        self.assertEqual("", ev_logger._clean_up_message(""))
        self.assertEqual("Daemon Activate resource disk failure", ev_logger._clean_up_message(
            "Daemon Activate resource disk failure"))
        self.assertEqual("[M.A.E.CS-2.0.7] Target handler state", ev_logger._clean_up_message(
            '2019/10/07 21:54:16.629444 INFO [M.A.E.CS-2.0.7] Target handler state'))
        self.assertEqual("[M.A.E.CS-2.0.7] Initializing extension M.A.E.CS-2.0.7", ev_logger._clean_up_message(
            '2019/10/07 21:54:17.284385 INFO [M.A.E.CS-2.0.7] Initializing extension M.A.E.CS-2.0.7'))
        self.assertEqual("ExtHandler ProcessGoalState completed [incarnation 4; 4197 ms]", ev_logger._clean_up_message(
            "2019/10/07 21:55:38.474861 INFO ExtHandler ProcessGoalState completed [incarnation 4; 4197 ms]"))
        self.assertEqual("Daemon Azure Linux Agent Version:2.2.43", ev_logger._clean_up_message(
            "2019/10/07 21:52:28.615720 INFO Daemon Azure Linux Agent Version:2.2.43"))
        self.assertEqual('Daemon Cgroup controller "memory" is not mounted. Failed to create a cgroup for the VM Agent;'
                         ' resource usage will not be tracked',
                         ev_logger._clean_up_message('Daemon Cgroup controller "memory" is not mounted. Failed to '
                                                     'create a cgroup for the VM Agent; resource usage will not be '
                                                     'tracked'))
        self.assertEqual('ExtHandler Root directory /sys/fs/cgroup/memory/walinuxagent.extensions does not exist.',
                         ev_logger._clean_up_message("2019/10/08 23:45:05.691037 WARNING ExtHandler Root directory "
                                                     "/sys/fs/cgroup/memory/walinuxagent.extensions does not exist."))
        self.assertEqual("LinuxAzureDiagnostic started to handle.",
                         ev_logger._clean_up_message("2019/10/07 22:02:40 LinuxAzureDiagnostic started to handle."))
        self.assertEqual("VMAccess started to handle.",
                         ev_logger._clean_up_message("2019/10/07 21:56:58 VMAccess started to handle."))
        self.assertEqual(
            '[PERIODIC] ExtHandler Root directory /sys/fs/cgroup/memory/walinuxagent.extensions does not exist.',
            ev_logger._clean_up_message("2019/10/08 23:45:05.691037 WARNING [PERIODIC] ExtHandler Root directory "
                                        "/sys/fs/cgroup/memory/walinuxagent.extensions does not exist."))
        self.assertEqual("[PERIODIC] LinuxAzureDiagnostic started to handle.", ev_logger._clean_up_message(
            "2019/10/07 22:02:40 [PERIODIC] LinuxAzureDiagnostic started to handle."))
        self.assertEqual("[PERIODIC] VMAccess started to handle.",
                         ev_logger._clean_up_message("2019/10/07 21:56:58 [PERIODIC] VMAccess started to handle."))
        self.assertEqual('[PERIODIC] Daemon Cgroup controller "memory" is not mounted. Failed to create a cgroup for '
                         'the VM Agent; resource usage will not be tracked',
                         ev_logger._clean_up_message('[PERIODIC] Daemon Cgroup controller "memory" is not mounted. '
                                                     'Failed to create a cgroup for the VM Agent; resource usage will '
                                                     'not be tracked'))
        self.assertEquals('The time should be in UTC', ev_logger._clean_up_message(
            '2019-11-26T18:15:06.866746Z INFO The time should be in UTC'))
        self.assertEquals('The time should be in UTC', ev_logger._clean_up_message(
            '2019-11-26T18:15:06.866746Z The time should be in UTC'))
        self.assertEquals('[PERIODIC] The time should be in UTC', ev_logger._clean_up_message(
            '2019-11-26T18:15:06.866746Z INFO [PERIODIC] The time should be in UTC'))
        self.assertEquals('[PERIODIC] The time should be in UTC', ev_logger._clean_up_message(
            '2019-11-26T18:15:06.866746Z [PERIODIC] The time should be in UTC'))
