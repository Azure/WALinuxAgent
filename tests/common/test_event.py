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
from datetime import datetime, timedelta

from azurelinuxagent.common.event import add_event, \
    WALAEventOperation, elapsed_milliseconds
from azurelinuxagent.common.exception import EventError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.processutil import read_output
from azurelinuxagent.common.version import CURRENT_VERSION
from azurelinuxagent.ga.monitor import MonitorHandler

from tests.tools import *

import azurelinuxagent.common.event as event


class TestEvent(AgentTestCase):
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

        event.add_periodic(logger.EVERY_DAY, "FauxEvent")
        mock_event.assert_called_once_with(
            "FauxEvent",
            duration=0, evt_type='', is_internal=False, is_success=True,
            log_event=True, message='', op=WALAEventOperation.Unknown,
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

        add_event('test_extension', message=log_msg, duration=duration)

        for tld_file in os.listdir(self.tmp_dir):
            event_str = MonitorHandler.collect_event(os.path.join(self.tmp_dir, tld_file))
            event_json = json.loads(event_str)

            self.assertEqual(len(event_json["parameters"]), 8)

            for i in event_json["parameters"]:
                if i["name"] == "Name":
                    self.assertEqual(i["value"], "test_extension")
                if i["name"] == "Message":
                    self.assertEqual(i["value"], log_msg)

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

    @patch('azurelinuxagent.common.event.EventLogger.save_event')
    def test_report_metric(self, mock_event):
        event.report_metric("cpu", "%idle", "_total", 10.0)
        self.assertEqual(1, mock_event.call_count)
        event_json = mock_event.call_args[0][0]
        self.assertIn("69B669B9-4AF8-4C50-BDC4-6006FA76E975", event_json)
        self.assertIn("%idle", event_json)
        import json
        event_dictionary = json.loads(event_json)
        self.assertEqual(event_dictionary['providerId'], "69B669B9-4AF8-4C50-BDC4-6006FA76E975")
        for parameter in event_dictionary["parameters"]:
            if parameter['name'] == 'Counter':
                self.assertEqual(parameter['value'], '%idle')
                break
        else:
            self.fail("Counter '%idle' not found in event parameters: {0}".format(repr(event_dictionary)))
