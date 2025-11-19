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
# Checks that the input data is found in the agent log
#
import argparse
import sys
import re

from datetime import datetime
from azurelinuxagent.common.future import UTC, datetime_min_utc
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.agent_log import AgentLog


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--extension-name', dest='extension_name', required=True)
    parser.add_argument('--operation', dest='operation', required=True, choices=['run', 'uninstall'])
    parser.add_argument("--after-timestamp", dest='after_timestamp', required=False)

    args, _ = parser.parse_known_args()

    log.info("Verifying that agent log shows {0} failure due to policy".format(args.operation))
    pattern = (r".*Extension will not be processed: failed to {0} extension '{1}' because it is not specified as an allowed extension.*"
               .format(args.operation, re.escape(args.extension_name)))
    agent_log = AgentLog()

    if args.after_timestamp is None:
        after_datetime = datetime_min_utc
    else:
        after_datetime = datetime.strptime(args.after_timestamp, '%Y-%m-%d %H:%M:%S').replace(tzinfo=UTC)

    try:
        for record in agent_log.read():
            if record.timestamp > after_datetime:
                if re.search(pattern, record.message):
                    log.info("Found expected error in agent log: {0}".format(record.message))
                    sys.exit(0)

    except Exception as e:
        log.info("Error thrown when searching for test data in agent log: {0}".format(str(e)))

    log.info("Did not find expected error in agent log. Expected to find pattern: {0}".format(pattern))
    sys.exit(1)


if __name__ == "__main__":
    main()