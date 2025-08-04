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
import glob
import sys
import re

from datetime import datetime
from azurelinuxagent.common.future import UTC, datetime_min_utc
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.agent_log import AgentLog

# This script verifies that signature was validated for the specified extension.
# Usage: ext_signature_validation-check_signature_validated.py --extension-name "CustomScript"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--extension-name', dest='extension_name', required=True)
    parser.add_argument("--after-timestamp", dest='after_timestamp', required=False)

    args, _ = parser.parse_known_args()

    log.info("Verifying that {0} package signature was validated.".format(args.extension_name))
    sig_pattern = (r".*Successfully validated signature for package '.*{0}.*'".format(re.escape(args.extension_name)))
    man_pattern = (r".*Successfully validated handler manifest 'signingInfo' for extension '.*{0}.*'".format(re.escape(args.extension_name)))
    agent_log = AgentLog()

    if args.after_timestamp is None:
        after_datetime = datetime_min_utc
    else:
        after_datetime = datetime.strptime(args.after_timestamp, '%Y-%m-%d %H:%M:%S').replace(tzinfo=UTC)

    try:
        # Check for the signature validation and manifest validation messages
        sig_validated = False
        man_validated = False

        for record in agent_log.read():
            if record.timestamp > after_datetime:
                if re.search(sig_pattern, record.message):
                    log.info("Found message indicating that signature was successfully validated: {0}".format(record.message))
                    sig_validated = True
                if re.search(man_pattern, record.message):
                    log.info("Found message indicating that manifest was successfully validated: {0}".format(record.message))
                    man_validated = True

        if not sig_validated:
            log.info("Did not find expected signature validation message in agent log. Expected pattern: {0}".format(sig_pattern))
            sys.exit(1)

        if not man_validated:
            log.info("Did not find expected manifest validation message in agent log. Expected pattern: {0}".format(man_pattern))
            sys.exit(1)

        # Check for the signature validation state file
        log.info("Checking that signature validation state file exists.")
        state_file_pattern = "/var/lib/waagent/*{0}*/package_validated".format(args.extension_name)
        matched_files = glob.glob(state_file_pattern)
        if matched_files is None or len(matched_files) == 0:
            log.info("No signature validation state file found for extension '{0}'".format(args.extension_name))
            sys.exit(1)

        if len(matched_files) > 1:
            log.info("Expected exactly one signature validation state file, but found {0}.".format(len(matched_files)))

        log.info("Signature validation state file found for extension '{0}'".format(args.extension_name))
        sys.exit(0)

    except Exception as e:
        log.info("Error thrown when checking that signature was validated: {0}".format(str(e)))
        sys.exit(1)


if __name__ == "__main__":
    main()
