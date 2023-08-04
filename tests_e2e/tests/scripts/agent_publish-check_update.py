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

from assertpy import fail

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
from tests_e2e.tests.lib.retry import retry_if_false


# pylint: disable=W0105
"""
Post the _LOG_PATTERN_00 changes, the last group sometimes might not have the 'Agent' part at the start of the sentence; thus making it optional.

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
_UPDATE_PATTERN_03 = re.compile(r'(.*Agent) update found, exiting current process to (\S*) to the new Agent version (\S*)')

"""
> Agent WALinuxAgent-2.2.47 is running as the goal state agent
('2.2.47',)
"""
_RUNNING_PATTERN_00 = re.compile(r'.*Agent\sWALinuxAgent-(\S*)\sis running as the goal state agent')


def verify_agent_update_from_log():

    exit_code = 0
    detected_update = False
    update_successful = False
    update_version = ''

    agentlog = AgentLog()

    for record in agentlog.read():
        if 'TelemetryData' in record.text:
            continue

        for p in [_UPDATE_PATTERN_00, _UPDATE_PATTERN_01, _UPDATE_PATTERN_02, _UPDATE_PATTERN_03]:
            update_match = re.match(p, record.text)
            if update_match:
                detected_update = True
                update_version = update_match.groups()[2]
                log.info('found the agent update log: %s', record.text)
                break

        if detected_update:
            running_match = re.match(_RUNNING_PATTERN_00, record.text)
            if running_match and update_version == running_match.groups()[0]:
                update_successful = True
                log.info('found the agent started new version log: %s', record.text)

    if detected_update:
        log.info('update was detected: %s', update_version)
        if update_successful:
            log.info('update was successful')
        else:
            log.warning('update was not successful')
            exit_code = 1
    else:
        log.warning('update was not detected')
        exit_code = 1

    return exit_code == 0


# This method will trace agent update messages in the agent log and determine if the update was successful or not.
def main():
    found: bool = retry_if_false(verify_agent_update_from_log)
    if not found:
        fail('update was not found in the logs')


run_remote_test(main)
