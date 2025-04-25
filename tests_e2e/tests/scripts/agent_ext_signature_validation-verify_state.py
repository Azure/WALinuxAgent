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

# This script verifies that a "signature_validated" state file exists for the specified extension.
# Usage: agent_ext_signature_validation-verify_state.py --extension-name "CustomScript"


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--extension-name', dest='extension_name', required=True, help='Extension name to process.')

    args = parser.parse_args()

    state_file_pattern = f"/var/lib/waagent/*{args.extension_name}*/package_validated"
    matched_files = glob.glob(state_file_pattern)
    if matched_files is None or len(matched_files) == 0:
        raise FileNotFoundError(f"No signature validation state file found for extension '{args.extension_name}'.")

    if len(matched_files) > 1:
        raise Exception(f"Expected exactly one signature validation state file for extension '{args.extension_name}', found {len(matched_files)}.")

    print(f"Signature validation state file found for extension '{args.extension_name}'")


if __name__ == "__main__":
    main()
