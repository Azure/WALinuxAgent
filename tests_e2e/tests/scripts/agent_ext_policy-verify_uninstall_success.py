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


def extension_found_in_agent_status_file(ext_name: str) -> bool:
    # Check if the provided extension name is present in the agent status file, under handlerAggregateStatus.
    # If the name is not present, the uninstall operation was successful.
    agent_status_file = "/var/lib/waagent/history/*/waagent_status.json"
    file_paths = glob.glob(agent_status_file, recursive=True)
    for file in file_paths:
        with open(file, 'r') as f:
            data = json.load(f)
            log.info("Agent status file (%s): %s", file, data)
            handler_status = data["aggregateStatus"]["handlerAggregateStatus"]
            if any(handler["handlerName"].lower() == ext_name.lower() for handler in handler_status):
                return True
            return False


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--extension-name', dest='name', required=True)
    args = parser.parse_args()

    log.info("Checking agent status file to verify that the uninstalled extension is not present in reported status")
    if extension_found_in_agent_status_file(args.name):
        fail("Handler status was found in the status file for extension {0}, uninstall failed.".format(args.name))
    else:
        log.info("Handler status was not found in the status file for extension {0}, uninstall succeeded.".format(args.name))


if __name__ == "__main__":
    main()
