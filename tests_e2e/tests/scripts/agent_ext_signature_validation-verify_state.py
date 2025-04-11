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

# This script verifies that a "signature_validated" state file exists for the specified extension
# and that it contains the expected validation state.
# Usage: agent_ext_signature_validation-verify_state.py --extension-name "CustomScript" --expected-state "SignatureAndManifestValidated"

DEFAULT_EXPECTED_STATE = "SignatureAndManifestValidated"


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--extension-name', dest='extension_name', required=True, help='Extension name to process.')
    parser.add_argument('--expected-state', dest='expected_state', required=False, default=DEFAULT_EXPECTED_STATE,
                        help='Expected signature validation state.')

    args = parser.parse_args()

    state_file_pattern = f"/var/lib/waagent/*{args.extension_name}*/signature_validation_state"
    matched_files = glob.glob(state_file_pattern)
    if matched_files is None or len(matched_files) == 0:
        raise FileNotFoundError(f"No signature validation state file found for extension '{args.extension_name}'.")

    if len(matched_files) > 1:
        raise Exception(f"Expected exactly one signature validation state file for extension '{args.extension_name}', found {len(matched_files)}.")

    path = matched_files[0]
    try:
        with open(path, 'r') as f:
            content = f.read().strip()
            if content == args.expected_state:
                print(f"Signature validation state matches expected value '{args.expected_state}'")
                return
            else:
                raise Exception(f"Signature validation state mismatch. Expected '{args.expected_state}', found '{content}'.")
    except Exception as e:
        raise Exception(f"Error reading or validating file '{path}': {e}")




if __name__ == "__main__":
    main()
