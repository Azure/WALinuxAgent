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
import sys

from pathlib import Path
from tests_e2e.tests.lib.agent_log import AgentLog


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", dest='data', required=True)
    args, _ = parser.parse_known_args()

    print("Verifying data: {0} in waagent.log".format(args.data))
    found = False

    try:
        found = AgentLog(Path(args.path)).is_data_in_waagent_log(args.data)
        if found:
            print("Found data: {0} in agent log".format(args.data))
        else:
            print("Did not find data: {0} in agent log".format(args.data))
    except Exception as e:
        print("Error thrown when searching for test data in agent log: {0}".format(ustr(e)))

    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()