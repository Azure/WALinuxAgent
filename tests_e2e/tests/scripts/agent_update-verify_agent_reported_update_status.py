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
# Verify if the agent reported update status to CRP via status file
#
import argparse
import glob
import json

from assertpy import fail

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
from tests_e2e.tests.lib.retry import retry_if_false


def check_agent_reported_update_status(expected_version: str) -> bool:
    agent_status_file = "/var/lib/waagent/history/*/waagent_status.json"
    file_paths = glob.glob(agent_status_file, recursive=True)
    for file in file_paths:
        with open(file, 'r') as f:
            data = json.load(f)
            log.info("Agent status file is %s and it's content %s", file, data)
            status = data["__status__"]
            guest_agent_status = status["aggregateStatus"]["guestAgentStatus"]
            if "updateStatus" in guest_agent_status.keys():
                if guest_agent_status["updateStatus"]["expectedVersion"] == expected_version:
                    log.info("we found the expected version %s in agent status file", expected_version)
                    return True
    log.info("we did not find the expected version %s in agent status file", expected_version)
    return False


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', required=True)
    args = parser.parse_args()

    log.info("checking agent status file to verify if agent reported update status")
    found: bool = retry_if_false(lambda: check_agent_reported_update_status(args.version))
    if not found:
        fail("Agent failed to report update status, so skipping rest of the agent update validations")


run_remote_test(main)

