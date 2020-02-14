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
from datetime import datetime, timedelta

from azurelinuxagent.common import event, logger
from azurelinuxagent.common.event import add_event, elapsed_milliseconds, EventLogger, report_metric, \
    WALAEventOperation, parse_xml_event, parse_json_event, parse_event, EVENT_FILE_EXTENSION
from azurelinuxagent.common.exception import EventError
from azurelinuxagent.common.future import OrderedDict, ustr
from azurelinuxagent.common.protocol.wire import GoalState
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventParam
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.extensionprocessutil import read_output
from tests.protocol import mockwiredata, mock_wire_protocol
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_AGENT, CURRENT_VERSION
from tests.common.mocksysinfo import SysInfoData
from tests.tools import AgentTestCase, data_dir, load_data, Mock, patch, PropertyMock


class TestEvent(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)

        self.event_dir = self.tmp_dir
        event.init_event_logger(self.event_dir)

        self.mock_sysinfo = patch("azurelinuxagent.common.sysinfo.SysInfo.get_instance", return_value=SysInfoData)
        self.mock_sysinfo.start()

    def tearDown(self):
        self.mock_sysinfo.stop()

    def test_parse_xml_event(self, *args):
        data_str = load_data('ext/event_from_extension.xml')
        event = parse_xml_event(data_str)
        self.assertNotEqual(None, event)
        self.assertNotEqual(0, event.parameters)
        self.assertTrue(all(param is not None for param in event.parameters))

    def test_parse_json_event(self, *args):
        data_str = load_data('ext/event.json')
        event = parse_json_event(data_str)
        self.assertNotEqual(None, event)
        self.assertNotEqual(0, event.parameters)
        self.assertTrue(all(param is not None for param in event.parameters))

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

            with mock_wire_protocol.create(mockwiredata.DATA_FILE) as protocol:
                goal_state = protocol.client._goal_state

                # Container id is set as an environment variable when parsing the goal state
                container_id = goal_state.container_id
                event.add_event(name='dummy_name')
                data = fileutil.read_file(tmp_file)
                self.assertTrue('{{"name": "ContainerId", "value": "{0}"}}'.format(container_id) in data or
                                '{{"value": "{0}", "name": "ContainerId"}}'.format(container_id), data)

                # Container id is updated as the goal state changes, both in telemetry event and in environment variables
                new_container_id = "z6d5526c-5ac2-4200-b6e2-56f2b70c5ab2"
                protocol.mock_wire_data.set_container_id(new_container_id)
                protocol.client.update_goal_state()

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
        event.add_periodic(logger.EVERY_DAY, "FauxEvent", op=WALAEventOperation.Log, is_success=True, duration=0,
                           version=str(CURRENT_VERSION), message="FauxEventMessage", log_event=True, force=False)
        mock_event.assert_called_once_with("FauxEvent", op=WALAEventOperation.Log, is_success=True, duration=0,
                                           version=str(CURRENT_VERSION), message="FauxEventMessage", log_event=True)

    @patch("azurelinuxagent.common.event.datetime")
    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    def test_periodic_forwards_args_default_values(self, mock_event, mock_datetime):
        event.__event_logger__.reset_periodic()
        event.add_periodic(logger.EVERY_DAY, "FauxEvent", message="FauxEventMessage")
        mock_event.assert_called_once_with("FauxEvent", op=WALAEventOperation.Unknown, is_success=True, duration=0,
                                           version=str(CURRENT_VERSION), message="FauxEventMessage", log_event=True)

    @patch("azurelinuxagent.common.event.EventLogger.add_event")
    def test_add_event_default_variables(self, mock_add_event):
        add_event('test', message='test event')
        mock_add_event.assert_called_once_with('test', duration=0, is_success=True, log_event=True,
                                               message='test event', op=WALAEventOperation.Unknown,
                                               version=str(CURRENT_VERSION))

    @patch('azurelinuxagent.common.logger.verbose')
    def test_collect_event_should_read_event_and_delete_the_file(self, patch_logger_verbose):
        return_time = 42
        filename = ustr(return_time * 1000000) + EVENT_FILE_EXTENSION
        filepath = os.path.join(self.event_dir, filename)

        with patch("time.time", return_value=return_time):
            add_event('test', message='test event')

        self.assertTrue(len(os.listdir(self.event_dir)) == 1)
        EventLogger.collect_event_str(filepath)
        self.assertTrue(len(os.listdir(self.event_dir)) == 0)

        self.assertEquals(patch_logger_verbose.call_count, 2)
        self.assertEquals(patch_logger_verbose.call_args_list[1][0][1], filepath)

    def test_save_event(self):
        add_event('test', message='test event')
        self.assertTrue(len(os.listdir(self.event_dir)) == 1)

        # checking the extension of the file created.
        for filename in os.listdir(self.event_dir):
            self.assertEqual(EVENT_FILE_EXTENSION, filename[-4:])

    def test_save_event_message_with_non_ascii_characters(self):
        test_data_dir = os.path.join(data_dir, "events", "collect_and_send_extension_stdout_stderror")
        msg = ""

        with open(os.path.join(test_data_dir, "dummy_stdout_with_non_ascii_characters"), mode="r+b") as stdout:
            with open(os.path.join(test_data_dir, "dummy_stderr_with_non_ascii_characters"), mode="r+b") as stderr:
                msg = read_output(stdout, stderr)

        duration = elapsed_milliseconds(datetime.utcnow())
        log_msg = "{0}\n{1}".format("DummyCmd", "\n".join([line for line in msg.split('\n') if line != ""]))

        test_datetime = datetime.utcnow()
        with patch("azurelinuxagent.common.event.datetime") as patch_datetime:
            patch_datetime.utcnow = Mock(return_value=test_datetime)
            with patch('os.getpid', return_value=42):
                with patch("threading.Thread.getName", return_value="HelloWorldTask"):
                    add_event('test_extension', message=log_msg, duration=duration)

        for tld_file in os.listdir(self.tmp_dir):
            event_str = EventLogger.collect_event_str(os.path.join(self.tmp_dir, tld_file))
            event = parse_event(event_str)
            self._assert_event_schema_is_complete(event)

    def test_save_event_message_with_decode_errors(self):
        tmp_file = os.path.join(self.tmp_dir, "tmp_file")
        fileutil.write_file(tmp_file, "This is not JSON data", encoding="utf-16")

        for tld_file in os.listdir(self.tmp_dir):
            try:
                EventLogger.collect_event_str(os.path.join(self.tmp_dir, tld_file))
            except Exception as e:
                self.assertIsInstance(e, EventError)

    def test_save_event_rollover(self):
        # We keep 1000 events only, and the older ones are removed.

        num_of_events = 999
        add_event('test', message='first event')  # this makes number of events to num_of_events + 1.
        for i in range(num_of_events):
            add_event('test', message='test event {0}'.format(i))

        num_of_events += 1 # adding the first add_event.

        events = os.listdir(self.event_dir)
        events.sort()
        self.assertTrue(len(events) == num_of_events, "{0} is not equal to {1}".format(len(events), num_of_events))

        first_event = os.path.join(self.event_dir, events[0])
        with open(first_event) as first_fh:
            first_event_text = first_fh.read()
            self.assertTrue('first event' in first_event_text)

        add_event('test', message='last event')
        # Adding the above event displaces the first_event

        events = os.listdir(self.event_dir)
        events.sort()
        self.assertTrue(len(events) == num_of_events,
                        "{0} events found, {1} expected".format(len(events), num_of_events))

        first_event = os.path.join(self.event_dir, events[0])
        with open(first_event) as first_fh:
            first_event_text = first_fh.read()
            self.assertFalse('first event' in first_event_text, "'first event' not in {0}".format(first_event_text))
            self.assertTrue('test event 0' in first_event_text)

        last_event = os.path.join(self.event_dir, events[-1])
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

    def _assert_param_lists_are_equal(self, param_list_actual, parameters_expected):
        parameters_expected_names = set(parameters_expected.keys())

        # Converting list of TelemetryEventParam into a dictionary, for easier look up of values.
        param_list_dict = OrderedDict([(param.name, param.value) for param in param_list_actual])

        for p in parameters_expected_names:
            self.assertIn(p, param_list_dict)
            self.assertEqual(param_list_dict[p], parameters_expected[p])

        self.assertEqual(len(parameters_expected_names), len(param_list_actual))

    def _assert_event_schema_is_complete(self, event):
        # Check that the event has all the necessary telemetry fields before reporting it; valid for all events.

        params_specific = ['Name', 'Version', 'Operation', 'OperationSuccess', 'Message', 'Duration']
        params_common = ['GAVersion', 'ContainerId', 'OpcodeName', 'EventTid', 'EventPid', 'TaskName', 'KeywordName',
                         'ExtensionType', 'IsInternal']
        params_sysinfo = ['OSVersion', 'ExecutionMode', 'RAM', 'Processors', 'VMName', 'TenantName', 'RoleName',
                          'RoleInstanceName', 'Location', 'SubscriptionId', 'ResourceGroupName', 'VMId', 'ImageOrigin']
        params_final = []
        params_final.extend(params_specific)
        params_final.extend(params_common)
        params_final.extend(params_sysinfo)

        event_params_dict = OrderedDict([(param.name, param.value) for param in event.parameters])
        for param_name in params_final:
            self.assertTrue(param_name in event_params_dict.keys())

        self.assertEquals(len(event.parameters), len(params_final))

    def test_add_common_parameters_to_event_should_add_common_parameters(self, *args):
        event = TelemetryEvent()
        event.parameters = []

        test_container_id = 'TEST_CONTAINER_ID'
        test_event_creation_time = datetime.utcnow().strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')
        test_event_tid = 42
        test_event_pid = 24
        test_taskname = 'TEST_THREAD_NAME'

        with patch("azurelinuxagent.common.event.get_container_id_from_env", return_value=test_container_id):
            with patch("threading.Thread.ident", new_callable=PropertyMock(return_value=test_event_tid)):
                with patch("os.getpid", return_value=test_event_pid):
                    with patch("threading.Thread.getName", return_value=test_taskname):
                        EventLogger._add_common_parameters_to_event(event, test_event_creation_time)

        common_parameters_expected = {'GAVersion': CURRENT_AGENT,
                                      'ContainerId': test_container_id,
                                      'OpcodeName': test_event_creation_time,
                                      'EventTid': test_event_tid,
                                      'EventPid': test_event_pid,
                                      'TaskName': test_taskname,
                                      'KeywordName': '',
                                      'ExtensionType': '',
                                      'IsInternal': False}

        self._assert_param_lists_are_equal(event.parameters, common_parameters_expected)

    def test_add_sysinfo_parameters_to_event_should_add_sysinfo_parameters(self, *args):
        event = TelemetryEvent()
        event.parameters = [TelemetryEventParam("Name", "DummyName")]

        with patch("azurelinuxagent.common.sysinfo.SysInfo.get_instance", return_value=SysInfoData):
            EventLogger._add_sysinfo_parameters_to_event(event)

        # Add existing event parameter
        event_parameters_expected = {"Name": "DummyName"}

        # Add sysinfo parameters
        sysinfo_parameters = SysInfoData.get_sysinfo_telemetry_params()
        for sysinfo_param in sysinfo_parameters:
            event_parameters_expected[sysinfo_param.name] = sysinfo_param.value

        self._assert_param_lists_are_equal(event.parameters, event_parameters_expected)

    def trim_extension_parameters_should_keep_only_extension_specific_fields(self, *args):
        # Create an event with all fields from the GuestAgentExtensionEvents schema present and ensure only
        # Name, Version, Operation, OperationSuccess, Message and Duration are kept, since they are the only fields
        # whose values are owned by the extension.
        extension_event = TelemetryEvent()
        extension_event.parameters = [
            TelemetryEventParam('Name', 'TEST_EXTENSION'),
            TelemetryEventParam('GAVersion', 'TEST_GAVersion'),
            TelemetryEventParam('ContainerId', 'TEST_ContainerId'),
            TelemetryEventParam('Version', 'TEST_Version'),
            TelemetryEventParam('Operation', 'TEST_Operation'),
            TelemetryEventParam('OperationSuccess', 'TEST_OperationSuccess'),
            TelemetryEventParam('Message', 'TEST_Message'),
            TelemetryEventParam('Duration', 'TEST_Duration'),
            TelemetryEventParam('OpcodeName', 'TEST_OpcodeName'),
            TelemetryEventParam('EventTid', 'TEST_EventTid'),
            TelemetryEventParam('EventPid', 'TEST_EventPid'),
            TelemetryEventParam('TaskName', 'TEST_TaskName'),
            TelemetryEventParam('KeywordName', 'TEST_KeywordName'),
            TelemetryEventParam('ExtensionType', 'TEST_ExtensionType'),
            TelemetryEventParam('IsInternal', 'TEST_IsInternal'),
            TelemetryEventParam('ExecutionMode', 'TEST_ExecutionMode'),
            TelemetryEventParam('OSVersion', 'TEST_OSVersion'),
            TelemetryEventParam('RAM', 'TEST_RAM'),
            TelemetryEventParam('Processors', 'TEST_Processors'),
            TelemetryEventParam('TenantName', 'TEST_TenantName'),
            TelemetryEventParam('RoleName', 'TEST_RoleName'),
            TelemetryEventParam('RoleInstanceName', 'TEST_RoleInstanceName'),
            TelemetryEventParam('SubscriptionId', 'TEST_SubscriptionId'),
            TelemetryEventParam('ResourceGroupName', 'TEST_ResourceGroupName'),
            TelemetryEventParam('VMId', 'TEST_VMId'),
            TelemetryEventParam('ImageOrigin', 'TEST_ImageOrigin'),
        ]

        extension_only_params = {
            'Name': 'TEST_EXTENSION',
            'Version': 'TEST_Version',
            'Operation': 'TEST_Operation',
            'OperationSuccess': 'TEST_OperationSuccess',
            'Message': 'TEST_Message',
            'Duration': 'TEST_Duration'
        }

        EventLogger.trim_extension_event_parameters(extension_event)
        self._assert_param_lists_are_equal(extension_event.parameters, extension_only_params)

    def test_finalize_event_fields_should_add_all_fields_before_sending_event(self, *args):
        # The method responsible for finalizing an agent or extension event will receive an event with only the core
        # parameters set: Name, Version, Operation, OperationSuccess, Message, and Duration.
        event = TelemetryEvent()
        event.parameters = [
            TelemetryEventParam('Name', 'WALinuxAgent'),
            TelemetryEventParam('Version', 'TEST_Version'),
            TelemetryEventParam('Operation', 'TEST_Operation'),
            TelemetryEventParam('OperationSuccess', 'TEST_OperationSuccess'),
            TelemetryEventParam('Message', 'TEST_Message'),
            TelemetryEventParam('Duration', 'TEST_Duration')
        ]

        EventLogger.finalize_event_fields(event, event_creation_time=datetime.utcnow())

        self.assertNotEqual(None, event)
        self.assertNotEqual(0, event.parameters)
        self.assertTrue(all(param is not None for param in event.parameters))
        self._assert_event_schema_is_complete(event)

    def test_update_old_event_schema_should_only_add_missing_fields_and_keep_existing(self):
        # Create an agent event with only a couple of fields. The test ensures the event will be properly updated
        # by finalizing the parameters schema before it will be reported.
        event = TelemetryEvent()
        event.parameters = [
            TelemetryEventParam('Name', 'WALinuxAgent'),
            TelemetryEventParam('Version', 'TEST_OLD_Version'),
            TelemetryEventParam('IsInternal', False),
            TelemetryEventParam('Operation', 'TEST_OLD_Operation'),
            TelemetryEventParam('OperationSuccess', 'TEST_OLD_OperationSuccess'),
            TelemetryEventParam('Message', 'TEST_OLD_Message'),
            TelemetryEventParam('Duration', 'TEST_OLD_Duration'),
            TelemetryEventParam('ExtensionType', '')
        ]
        old_parameters = {}
        for param in event.parameters:
            old_parameters[param.name] = param.value

        test_container_id = 'TEST_CONTAINER_ID'
        test_event_creation_time = datetime.utcnow().strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')
        test_event_tid = 42
        test_event_pid = 24
        test_taskname = 'TEST_THREAD_NAME'

        with patch("azurelinuxagent.common.event.get_container_id_from_env", return_value=test_container_id):
            with patch("threading.Thread.ident", new_callable=PropertyMock(return_value=test_event_tid)):
                with patch("os.getpid", return_value=test_event_pid):
                    with patch("threading.Thread.getName", return_value=test_taskname):
                        EventLogger._update_old_event_schema(event, test_event_creation_time)

        common_parameters_expected = {'GAVersion': CURRENT_AGENT,
                                      'ContainerId': test_container_id,
                                      'OpcodeName': test_event_creation_time,
                                      'EventTid': test_event_tid,
                                      'EventPid': test_event_pid,
                                      'TaskName': test_taskname,
                                      'KeywordName': '',
                                      'ExtensionType': '',
                                      'IsInternal': False}

        sysinfo_parameters_expected = {}
        sysinfo_parameters = SysInfoData.get_sysinfo_telemetry_params()
        for sysinfo_param in sysinfo_parameters:
            sysinfo_parameters_expected[sysinfo_param.name] = sysinfo_param.value

        updated_parameters = dict(old_parameters)
        updated_parameters.update(common_parameters_expected)
        updated_parameters.update(sysinfo_parameters_expected)

        self._assert_param_lists_are_equal(event.parameters, updated_parameters)

    @patch('azurelinuxagent.common.logger.error')
    def test_update_old_events_on_disk_should_only_update_old_agent_events(self, patch_logger_error, *args):
        add_event(name=AGENT_NAME)
        add_event(name="DummyExtension")

        # Add an agent event which would be produced by an older agent (<2.2.47) and would be missing some fields.
        # Achieve this by making the finalize_event_fields method a no-op.
        with patch("azurelinuxagent.common.event.EventLogger.finalize_event_fields"):
            add_event(name=AGENT_NAME, version="2.2.45")

        self.assertEquals(len(os.listdir(self.event_dir)), 3)
        EventLogger.update_old_daemon_events_on_disk(self.event_dir)

        self.assertEquals(len(os.listdir(self.event_dir)), 3)
        self.assertEquals(patch_logger_error.call_count, 0)

        for tld_file in os.listdir(self.event_dir):
            event_str = EventLogger.collect_event_str(os.path.join(self.tmp_dir, tld_file))
            event = parse_event(event_str)
            self._assert_event_schema_is_complete(event)


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
            self.assertEqual(EVENT_FILE_EXTENSION, filename[-4:])
            perf_metric_event = json.loads(fileutil.read_file(os.path.join(self.tmp_dir, filename)))
            self.assertEqual(perf_metric_event["eventId"], event.TELEMETRY_METRICS_EVENT_ID)
            self.assertEqual(perf_metric_event["providerId"], event.TELEMETRY_EVENT_PROVIDER_ID)
            for i in perf_metric_event["parameters"]:
                self.assertIn(i["name"], ["Category", "Counter", "Instance", "Value", "GAVersion", "ContainerId",
                                          "OpcodeName", "EventTid", "EventPid", "TaskName", "KeywordName",
                                          "ExtensionType", "IsInternal"])
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
