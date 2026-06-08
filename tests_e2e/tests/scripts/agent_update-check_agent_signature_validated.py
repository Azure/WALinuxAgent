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
# This script verifies that the agent successfully validated the package signature for a given agent version.
# It searches the agent log for the expected signature validation success message.
#
# Usage: agent_update-check_agent_signature_validated.py --version <version>

import argparse
import re

from assertpy import fail

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
from tests_e2e.tests.lib.retry import retry_if_false


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', required=True, help='The agent version to check signature validation for')
    args, _ = parser.parse_known_args()

    log.info("Checking agent log for successful signature validation of agent version %s", args.version)

    agent_log = AgentLog()
    pattern = r"Successfully validated signature for package 'WALinuxAgent-{0}'".format(re.escape(args.version))

    def _check_log():
        for record in agent_log.read():
            if re.search(pattern, record.message):
                log.info("Found signature validation message: %s", record.message)
                return True
        return False

    found = retry_if_false(_check_log, attempts=5, delay=30)
    if not found:
        fail("Did not find expected signature validation success message in agent log for version {0}. "
             "Expected pattern: {1}".format(args.version, pattern))

    log.info("Successfully verified signature was validated for agent version %s", args.version)


run_remote_test(main)
