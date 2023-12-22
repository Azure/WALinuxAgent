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
# Gets the timestamp for when the provided extension was enabled
#

import argparse
import json
import os
import sys

from pathlib import Path


def main():
    """
    Returns the timestamp of when the provided extension was enabled
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--ext", dest='ext', required=True)
    args, _ = parser.parse_known_args()

    # Extension enabled time is in extension extension status file
    ext_dirs = [item for item in os.listdir(Path('/var/lib/waagent')) if item.startswith(args.ext)]
    if not ext_dirs:
        print("Extension {0} directory does not exist".format(args.ext), file=sys.stderr)
        sys.exit(1)
    ext_status_path = Path('/var/lib/waagent/' + ext_dirs[0] + '/status')
    ext_status_files = os.listdir(ext_status_path)
    ext_status_files.sort()
    if not ext_status_files:
        # Extension did not report a status
        print("Extension {0} did not report a status".format(args.ext), file=sys.stderr)
        sys.exit(1)
    latest_ext_status_path = os.path.join(ext_status_path, ext_status_files[-1])
    ext_status_file = open(latest_ext_status_path, 'r')
    ext_status = json.loads(ext_status_file.read())

    # Example status file
    # [
    #     {
    #         "status": {
    #             "status": "success",
    #             "formattedMessage": {
    #                 "lang": "en-US",
    #                 "message": "Enable succeeded"
    #             },
    #             "operation": "Enable",
    #             "code": "0",
    #             "name": "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent"
    #         },
    #         "version": "1.0",
    #         "timestampUTC": "2023-12-12T23:14:45Z"
    #     }
    # ]
    msg = ""
    if len(ext_status) == 0 or not ext_status[0]['status']:
        msg = "Extension {0} did not report a status".format(args.ext)
    elif not ext_status[0]['status']['operation'] or ext_status[0]['status']['operation'] != 'Enable':
        msg = "Extension {0} did not report a status for enable operation".format(args.ext)
    elif ext_status[0]['status']['status'] != 'success':
        msg = "Extension {0} did not report success for the enable operation".format(args.ext)
    elif not ext_status[0]['timestampUTC']:
        msg = "Extension {0} did not report the time the enable operation succeeded".format(args.ext)
    else:
        print(ext_status[0]['timestampUTC'])
        sys.exit(0)

    print(msg, file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
