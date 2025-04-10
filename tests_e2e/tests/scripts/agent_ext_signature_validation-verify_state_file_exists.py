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
# Usage: agent_ext_signature_validation-verify_state_file_exists.py --extension-name "CustomScript"


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--extension-name', dest='extension_name', required=True, help='Extension name to process.')
    args = parser.parse_args()

    state_file = f"/var/lib/waagent/*{args.extension_name}*/signature_validated"

    if glob.glob(state_file) is not None:
        print("Signature validation state file exists")
    else:
        raise Exception(f"Signature validation state file not found for extension {args.extension_name}")


if __name__ == "__main__":
    main()
