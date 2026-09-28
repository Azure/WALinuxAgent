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
import re
import json

from assertpy import fail
from datetime import datetime
from azurelinuxagent.common.future import UTC, datetime_min_utc
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.agent_log import AgentLog

# This script verifies that signature was validated for the specified extension.
# Usage: ext_signature_validation-check_signature_validated.py --extension-name "CustomScript"


def check_signature_validation_state(extension_name, version=None):
    # Check that the HandlerStatus file contains "signature_validated": true
    if version is not None:
        handler_status_file = "/var/lib/waagent/*{0}-{1}*/config/HandlerStatus".format(extension_name, version)
    else:
        handler_status_file = "/var/lib/waagent/*{0}*/config/HandlerStatus".format(extension_name)
    matched_files = glob.glob(handler_status_file)
    if matched_files is None or len(matched_files) == 0:
        fail("No HandlerStatus file found for extension '{0}'".format(extension_name))

    if len(matched_files) > 1:
        fail("Expected exactly one one HandlerStatus file, but found {0}.".format(len(matched_files)))

    with open(matched_files[0], 'r') as f:
        data = json.load(f)
        signature_validated = data.get("signature_validated")
        if signature_validated:
            log.info("Signature validation state successfully saved to HandlerStatus, 'signature_validated' is True as expected")
        else:
            fail(f"Expected 'signature_validated' to be True in HandlerStatus, but got: {signature_validated}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--extension-name', dest='extension_name', required=True)
    parser.add_argument('--extension-version', dest='extension_version', required=False)
    parser.add_argument("--after-timestamp", dest='after_timestamp', required=False)

    args, _ = parser.parse_known_args()

    log.info("Verifying that {0} package signature was validated.".format(args.extension_name))
    sig_pattern = (r".*Successfully validated signature for package '.*{0}.*'".format(re.escape(args.extension_name)))
    man_pattern = (r".*Successfully validated handler manifest 'signingInfo' for extension '.*{0}.*'".format(re.escape(args.extension_name)))
    agent_log = AgentLog()

    if args.after_timestamp is None:
        after_datetime = datetime_min_utc
    else:
        after_datetime = datetime.strptime(args.after_timestamp, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=UTC)

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
            fail("Did not find expected signature validation message in agent log. Expected pattern: {0}".format(sig_pattern))

        if not man_validated:
            fail("Did not find expected manifest validation message in agent log. Expected pattern: {0}".format(man_pattern))

        # Check that the handler status file indicates that signature was validated.
        log.info("Checking that signature validation state in HandlerStatus file.")
        check_signature_validation_state(args.extension_name, args.extension_version)

        log.info("Signature validation state was set correctly for extension '{0}'".format(args.extension_name))

    except Exception as e:
        fail("Error thrown when checking that signature was validated: {0}".format(str(e)))


if __name__ == "__main__":
    main()
