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

from tests.tools import *
from azurelinuxagent.common.exception import *
from azurelinuxagent.daemon.monitor import *

class TestMonitor(AgentTestCase):
    def test_parse_xml_event(self):
        data_str = load_data('ext/event.xml')
        event = parse_xml_event(data_str)
        self.assertNotEquals(None, event)
        self.assertNotEquals(0, event.parameters)
        self.assertNotEquals(None, event.parameters[0])

