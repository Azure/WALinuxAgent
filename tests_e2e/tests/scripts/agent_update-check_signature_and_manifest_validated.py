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
# This script verifies that the agent successfully validated the package signature and the handler
# manifest 'signingInfo' for a given agent version. It searches the agent log for the expected
# signature validation success message and the expected handler manifest validation success message.
#
# Usage: agent_update-check_signature_and_manifest_validated.py --version <version>

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

    log.info("Checking agent log for successful signature and handler manifest validation of agent version %s", args.version)

    agent_log = AgentLog()
    signature_pattern = r"Successfully validated signature for package 'WALinuxAgent-{0}'".format(re.escape(args.version))
    manifest_pattern = r"Successfully validated handler manifest 'signingInfo' for agent 'WALinuxAgent-{0}'".format(re.escape(args.version))

    found_messages = {"signature": None, "manifest": None}

    def _check_log():
        for record in agent_log.read():
            if found_messages["signature"] is None and re.search(signature_pattern, record.message):
                found_messages["signature"] = record.message
            if found_messages["manifest"] is None and re.search(manifest_pattern, record.message):
                found_messages["manifest"] = record.message
            if found_messages["signature"] is not None and found_messages["manifest"] is not None:
                return True
        return False

    found = retry_if_false(_check_log, attempts=5, delay=30)
    if not found:
        missing = []
        if found_messages["signature"] is None:
            missing.append("signature validation (pattern: {0})".format(signature_pattern))
        if found_messages["manifest"] is None:
            missing.append("handler manifest validation (pattern: {0})".format(manifest_pattern))
        fail("Did not find expected success message(s) in agent log for version {0}: {1}".format(
            args.version, "; ".join(missing)))

    log.info("Found signature validation message: %s", found_messages["signature"])
    log.info("Found handler manifest validation message: %s", found_messages["manifest"])
    log.info("Successfully verified signature and handler manifest were validated for agent version %s", args.version)


run_remote_test(main)
