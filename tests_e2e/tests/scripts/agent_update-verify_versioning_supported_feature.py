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
# Verify if the agent reported supportedfeature VersioningGovernance flag to CRP via status file
#
import glob
import json

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
from tests_e2e.tests.lib.retry import retry_if_false


def check_agent_supports_versioning() -> bool:
    agent_status_file = "/var/lib/waagent/history/*/waagent_status.json"
    file_paths = glob.glob(agent_status_file, recursive=True)
    for file in file_paths:
        with open(file, 'r') as f:
            data = json.load(f)
            log.info("Agent status file is %s and it's content %s", file, data)
            status = data["__status__"]
            supported_features = status["supportedFeatures"]
            for supported_feature in supported_features:
                if supported_feature["Key"] == "VersioningGovernance":
                    return True
    return False


def main():
    log.info("checking agent status file for VersioningGovernance supported feature flag")
    found: bool = retry_if_false(check_agent_supports_versioning)
    if not found:
        raise Exception("Agent failed to report supported feature flag. So, skipping agent update validations "
                        "since CRP will not send RSM requested version in GS if feature flag not found in status")


run_remote_test(main)



