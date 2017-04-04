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

from azurelinuxagent.common.event import init_event_logger, add_event
from azurelinuxagent.common.future import ustr
from tests.tools import *


class TestEvent(AgentTestCase):
    def test_save_event(self):
        tmp_evt = tempfile.mkdtemp()
        init_event_logger(tmp_evt)
        add_event('test', message='test event')
        self.assertTrue(len(os.listdir(tmp_evt)) == 1)
        shutil.rmtree(tmp_evt)

    def test_save_event_rollover(self):
        tmp_evt = tempfile.mkdtemp()
        init_event_logger(tmp_evt)
        add_event('test', message='first event')
        for i in range(0, 999):
            add_event('test', message='test event {0}'.format(i))

        events = os.listdir(tmp_evt)
        events.sort()
        self.assertTrue(len(events) == 1000)

        first_event = os.path.join(tmp_evt, events[0])
        with open(first_event) as first_fh:
            first_event_text = first_fh.read()
            self.assertTrue('first event' in first_event_text)

        add_event('test', message='last event')
        events = os.listdir(tmp_evt)
        events.sort()
        self.assertTrue(len(events) == 1000, "{0} events found, 1000 expected".format(len(events)))

        first_event = os.path.join(tmp_evt, events[0])
        with open(first_event) as first_fh:
            first_event_text = first_fh.read()
            self.assertFalse('first event' in first_event_text)
            self.assertTrue('test event 0' in first_event_text)

        last_event = os.path.join(tmp_evt, events[-1])
        with open(last_event) as last_fh:
            last_event_text = last_fh.read()
            self.assertTrue('last event' in last_event_text)

        shutil.rmtree(tmp_evt)

    def test_save_event_cleanup(self):
        tmp_evt = tempfile.mkdtemp()
        init_event_logger(tmp_evt)

        for i in range(0, 2000):
            evt = os.path.join(tmp_evt, '{0}.tld'.format(ustr(1491004920536531 + i)))
            with open(evt, 'w') as fh:
                fh.write('test event {0}'.format(i))

        events = os.listdir(tmp_evt)
        self.assertTrue(len(events) == 2000, "{0} events found, 2000 expected".format(len(events)))
        add_event('test', message='last event')

        events = os.listdir(tmp_evt)
        events.sort()
        self.assertTrue(len(events) == 1000, "{0} events found, 1000 expected".format(len(events)))
        first_event = os.path.join(tmp_evt, events[0])
        with open(first_event) as first_fh:
            first_event_text = first_fh.read()
            self.assertTrue('test event 1001' in first_event_text)

        last_event = os.path.join(tmp_evt, events[-1])
        with open(last_event) as last_fh:
            last_event_text = last_fh.read()
            self.assertTrue('last event' in last_event_text)
