#!/usr/bin/env pypy3

# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
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

import re
from datetime import datetime

from tests_e2e.tests.lib.agent_log import AgentLog

# pylint: disable=W0105
"""
> WALinuxAgent-2.2.18 discovered WALinuxAgent-2.2.47 as an update and will exit
(None, 'WALinuxAgent-2.2.18', '2.2.47')
"""
_UPDATE_PATTERN_00 = re.compile(r'(.*Agent\s)?(\S*)\sdiscovered\sWALinuxAgent-(\S*)\sas an update and will exit')

"""
> Agent WALinuxAgent-2.2.45 discovered update WALinuxAgent-2.2.47 -- exiting
('Agent', 'WALinuxAgent-2.2.45', '2.2.47')
"""
_UPDATE_PATTERN_01 = re.compile(r'(.*Agent)?\s(\S*) discovered update WALinuxAgent-(\S*) -- exiting')

"""
> Normal Agent upgrade discovered, updating to WALinuxAgent-2.9.1.0 -- exiting
('Normal Agent', WALinuxAgent, '2.9.1.0 ')
"""
_UPDATE_PATTERN_02 = re.compile(r'(.*Agent) upgrade discovered, updating to (WALinuxAgent)-(\S*) -- exiting')

"""
> Agent update found, exiting current process to downgrade to the new Agent version 1.3.0.0
(Agent, 'downgrade', '1.3.0.0')
"""
_UPDATE_PATTERN_03 = re.compile(
    r'(.*Agent) update found, exiting current process to (\S*) to the new Agent version (\S*)')


"""
This script return timestamp of update message in the agent log
"""


def main():
    try:
        agentlog = AgentLog()

        for record in agentlog.read():

            for p in [_UPDATE_PATTERN_00, _UPDATE_PATTERN_01, _UPDATE_PATTERN_02, _UPDATE_PATTERN_03]:
                update_match = re.match(p, record.text)
                if update_match:
                    return record.timestamp

        return datetime.min
    except Exception as e:
        raise Exception("Error thrown when searching for update pattern in agent log to get record timestamp: {0}".format(str(e)))


if __name__ == "__main__":
    timestamp = main()
    print(timestamp)
