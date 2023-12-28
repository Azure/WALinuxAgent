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
import argparse
import re

from assertpy import fail

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


_UPDATE_PATTERN = re.compile(r'Current Agent (\S*) completed all update checks, exiting current process to (\S*) to the new Agent version (\S*)')


def verify_agent_update_from_log(latest_version, current_version) -> bool:
    """
    Checks if the agent updated to the latest version from current version
    """
    agentlog = AgentLog()

    for record in agentlog.read():
        update_match = re.match(_UPDATE_PATTERN, record.text)
        if update_match:
            log.info('found the agent update log: %s', record.text)
            if update_match.groups()[0] == current_version and update_match.groups()[2] == latest_version:
                return True
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--latest-version', dest="latest_version", required=True)
    parser.add_argument('-c', '--current-version', dest="current_version", required=True)
    args = parser.parse_args()

    found: bool = retry_if_false(lambda: verify_agent_update_from_log(args.latest_version, args.current_version))
    if not found:
        fail('agent update was not found in the logs for latest version {0} from current version {1}'.format(args.latest_version, args.current_version))


if main == '__main__':
    main()
