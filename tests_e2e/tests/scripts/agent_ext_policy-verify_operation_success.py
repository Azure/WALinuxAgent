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
#
import argparse

from assertpy import fail
from datetime import datetime
import time
import re

from azurelinuxagent.common.future import UTC, datetime_min_utc

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.agent_log import AgentLog

# This script verifies the success of an operation using the agent log.
# Enable: check that the agent has reported a successful status for the specified list of extensions
# Uninstall: check that the agent has not reported any status for the specified list of extensions
#
# Usage:
# agent_ext_policy-verify_operation_success.py --extension-list "A" "B" --operation "enable" --after-timestamp "2025-01-13 11:21:40"


def __get_last_reported_status(after_timestamp):
    # Get last reported status from the agent log file. If after_timestamp is specified, return only the status reported
    # after that timestamp, and raise error if not found after 2 tries.
    agent_log = AgentLog()

    retries = 10
    for attempt in range(retries):
        phrase = "All extensions in the goal state have reached a terminal state"
        latest_status = None
        for record in agent_log.read():
            if record.timestamp < after_timestamp:
                continue

            if phrase in record.message:
                if latest_status is None:
                    latest_status = record
                else:
                    if latest_status.timestamp < record.timestamp:
                        latest_status = record

        if latest_status is not None:
            log.info("Latest status: {0}".format(latest_status.message))
            return latest_status

        log.info("Unable to find handler status in agent log on attempt {0}. Retrying...".format(attempt + 1))
        time.sleep(30)

    return None


def check_extension_reported_successful_status(status_message, ext_name: str):
    # Extract extension statuses from the agent record
    pattern = r"\(u?'(" + re.escape(ext_name) + r")', u?'([^']+)'\)"
    match = re.search(pattern, status_message)
    if match is None:
        fail("Agent did not report any status for extension {0}, enable failed.".format(ext_name))
    else:
        status_code = match.group(2).lower()
        log.info("Status code: {0}".format(status_code))
        if status_code not in ["success", "ready"]:
            fail("Agent did not report a successful status for extension {0}, enable failed. Status: {1}".format(ext_name, status_code))
        else:
            log.info("Agent reported a successful status for extension {0}, enable succeeded.".format(ext_name))

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--extension-list', dest='extension_list', required=True, nargs='+',
                        help='Extension name(s) to process. Provide a single name or a space-separated list of names.')

    parser.add_argument('--operation', dest='operation', required=True, choices=['enable', 'uninstall'])
    parser.add_argument("--after-timestamp", dest='after_timestamp', required=False)
    args = parser.parse_args()

    if args.after_timestamp is not None:
        after_datetime = datetime.strptime(args.after_timestamp, '%Y-%m-%d %H:%M:%S').replace(tzinfo=UTC)
    else:
        after_datetime = datetime_min_utc

    status = __get_last_reported_status(after_datetime)
    if status is None:
        fail("Unable to find extension status in agent log.")

    if args.operation == "enable":
        log.info("Checking agent status file to verify that extensions were enabled successfully.")
        for extension in args.extension_list:
            check_extension_reported_successful_status(status.message, extension)

    elif args.operation == "uninstall":
        log.info("Checking agent log to verify that status is not reported for uninstalled extensions.")
        for extension in args.extension_list:
            if extension in status.message:
                fail("Agent reported status for extension {0}, uninstall failed.".format(extension))
            else:
                log.info("Agent did not report status for extension {0}, uninstall succeeded.".format(extension))


if __name__ == "__main__":
    main()