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
# The script updates the handlerManifest.json file for a given extension.
#
#

import argparse
import glob
import json
import os.path
import shutil
import sys

from tests_e2e.tests.lib.logging import log

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--extension-name', dest='extension_name', required=True, help='Name of the extension to update the handlerManifest for')
    operation = parser.add_argument_group('Main operation')
    operation_parser = operation.add_mutually_exclusive_group(required=True)
    operation_parser.add_argument('--properties', dest='properties', nargs='+', help='List of property=value to update in the handlerManifest file')
    operation_parser.add_argument("--reset", dest='reset', action='store_true', help='Reset the handlerManifest file to the default values')

    args, _ = parser.parse_known_args()
    extension_name = args.extension_name
    properties = args.properties
    reset = args.reset

    # Check for the handlerManifest   file
    log.info("Checking that handlerManifest file exists.")
    manifest_file_pattern = "/var/lib/waagent/*{0}*/HandlerManifest.json".format(extension_name)
    matched_files = glob.glob(manifest_file_pattern)
    if matched_files is None or len(matched_files) == 0:
        log.info("No handlerManifest.json file found for extension '{0}'".format(extension_name))
        sys.exit(1)

    manifest_file = matched_files[0]
    log.info("HandlerManifest file found for extension '{0}': {1}".format(extension_name, manifest_file))

    if reset:
        log.info("Resetting handlerManifest file for extension '{0}' to default values".format(extension_name))
        # Reset the handlerManifest file to the default values
        backup_file = manifest_file + ".bak"
        if os.path.exists(backup_file):
            shutil.copy(backup_file, manifest_file)
            log.info("Reset handlerManifest file for extension '{0}' to default values".format(extension_name))
        else:
            log.info("No backup file found to reset the handlerManifest file for extension '{0}'".format(extension_name))
        sys.exit(0)

    if len(properties) == 0:
        log.info("No properties provided to update in the handlerManifest file for extension '{0}'".format(extension_name))
        sys.exit(1)

    shutil.copy(manifest_file, manifest_file + ".bak")

    # Sample handlerManifest.json structure:
    # [
    #   {
    #     "version": 1.0,
    #     "handlerManifest": {
    #       "installCommand": "bin/custom-script-shim install",
    #       "uninstallCommand": "bin/custom-script-shim uninstall",
    #       "updateCommand": "bin/custom-script-shim update",
    #       "enableCommand": "bin/custom-script-shim enable",
    #       "disableCommand": "bin/custom-script-shim disable",
    #       "rebootAfterInstall": false,
    #       "reportHeartbeat": false,
    #       "updateMode": "UpdateWithInstall"
    #     },
    #     "signingInfo": {
    #       "type": "CustomScript",
    #       "publisher": "Microsoft.Azure.Extensions",
    #       "version": "2.1.13"
    #     }
    #   }
    # ]

    with open(manifest_file, 'r') as file:
        data = json.load(file)

    commands = data[0]['handlerManifest']

    for prop in properties:
        # Split the property into cmd_name and cmd_value
        if '=' not in prop:
            log.info("Property '{0}' is not in the format 'cmd_name=cmd_value'".format(prop))
            sys.exit(1)

        cmd_name, cmd_value = prop.split('=', 1)
        log.info("Updating command '{0}' with value '{1}'".format(cmd_name, cmd_value))

        # Update the handlerManifest file
        log.info("Updating handlerManifest file for extension '{0}' for cmd '{1}' and value '{2}'".format(extension_name, cmd_name, cmd_value))
        commands[cmd_name] = cmd_value

    with open(manifest_file, 'w') as file:
        json.dump(data, file, indent=4)

    log.info("Updated the handlerManifest file for extension '{0}'".format(extension_name))
    sys.exit(0)


if __name__ == "__main__":
    main()
