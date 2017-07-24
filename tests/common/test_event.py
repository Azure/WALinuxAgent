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
# Requires Python 2.4+ and Openssl 1.0+
#

from __future__ import print_function

from datetime import datetime

import azurelinuxagent.common.event as event
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.event import add_event, \
                                    mark_event_status, should_emit_event
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.version import CURRENT_VERSION

from tests.tools import *


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
        d = tempfile.mkdtemp()
        es = event.EventStatus(tempfile.mkdtemp())

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
        event.__event_status__ = event.EventStatus(tempfile.mkdtemp())

        self.assertTrue(event.should_emit_event("Foo", "1.2", "FauxOperation", True))
        self.assertTrue(event.should_emit_event("Foo", "1.2", "FauxOperation", False))

        # Marking the event has no effect
        event.mark_event_status("Foo", "1.2", "FauxOperation", True)

        self.assertTrue(event.should_emit_event("Foo", "1.2", "FauxOperation", True))
        self.assertTrue(event.should_emit_event("Foo", "1.2", "FauxOperation", False))


    def test_should_emit_event_handles_known_operations(self):
        event.__event_status__ = event.EventStatus(tempfile.mkdtemp())

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

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    def test_periodic_emits_if_not_previously_sent(self, mock_event):
        event.__event_logger__.reset_periodic()

        event.add_periodic(logger.EVERY_DAY, "FauxEvent")
        mock_event.assert_called_once()

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

        h = hash("FauxEvent"+""+ustr(True)+"")
        event.__event_logger__.periodic_messages[h] = \
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
            log_event=True, message='', op='', version=str(CURRENT_VERSION))

    def test_save_event(self):
        add_event('test', message='test event')
        self.assertTrue(len(os.listdir(self.tmp_dir)) == 1)

    def test_save_event_rollover(self):
        add_event('test', message='first event')
        for i in range(0, 999):
            add_event('test', message='test event {0}'.format(i))

        events = os.listdir(self.tmp_dir)
        events.sort()
        self.assertTrue(len(events) == 1000)

        first_event = os.path.join(self.tmp_dir, events[0])
        with open(first_event) as first_fh:
            first_event_text = first_fh.read()
            self.assertTrue('first event' in first_event_text)

        add_event('test', message='last event')
        events = os.listdir(self.tmp_dir)
        events.sort()
        self.assertTrue(len(events) == 1000, "{0} events found, 1000 expected".format(len(events)))

        first_event = os.path.join(self.tmp_dir, events[0])
        with open(first_event) as first_fh:
            first_event_text = first_fh.read()
            self.assertFalse('first event' in first_event_text)
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
