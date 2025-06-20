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
# Displays a set of properties from an object in the goal state.
#
# Currently, it only supports the basic goal state, certificates, and the extensions goal state. Support for other objects
# can be added as needed.
#
# If multiple properties are specified, the output is a JSON object with a member for each of the properties. If no
# properties are specified, a default property is displayed:
#
#     * basic goal state - incarnation
#     * certificates - summary
#     * extensions goal state - id
#
# Examples:
#       # get_goal_state.py
#       1
#
#       # get_goal_state.py -p incarnation
#       1
#
#       # get_goal_state.py --certificates
#       [{'thumbprint': 'DF940808B0BB7823492E28E2E233860CDD317588', 'hasPrivateKey': False}, {'thumbprint': '0E3139B2153423AAE88433898A3A30255E24F5C4', 'hasPrivateKey': True}]
#
#       get_goal_state.py --extensions_goal_state --properties id source
#       {"id": "incarnation_1", "source": "Fabric"}
#
import argparse
import json
import os
import sys

from azurelinuxagent.common.conf import get_lib_dir
from azurelinuxagent.common.protocol.util import ENDPOINT_FILE_NAME
from azurelinuxagent.common.protocol.wire import WireProtocol, GoalState, GoalStateProperties


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--json', action='store_true', help='Force JSON output')
    parser.add_argument('-p', '--properties', nargs='*', help='Display the value of the given property')
    parser.add_mutually_exclusive_group()
    parser.add_argument('-c', '--certificates', action='store_true', help='Display the certificate thumbprints')
    parser.add_argument('-e', '--extensions_goal_state', action='store_true', help='Display the Extensions Goal State')
    args = parser.parse_args()

    if args.certificates:
        data = _get_goal_state(GoalStateProperties.Certificates).certs
        default_property = "summary"
    elif args.extensions_goal_state:
        data = _get_goal_state(GoalStateProperties.ExtensionsGoalState).extensions_goal_state
        default_property = "id"
    else:
        data = _get_goal_state()
        default_property = "incarnation"

    properties = args.properties if args.properties is not None else [default_property]

    if len(properties) == 1:
        value = data.__getattribute__(properties[0])
        if args.json:
            print(json.dumps(value, indent=4))
        else:
            print(value)
    else:
        output = {}
        for p in properties:
            output[p] = data.__getattribute__(p)
        print(json.dumps(output, indent=4))


def _get_goal_state(goal_state_properties: GoalStateProperties = 0x0):
    with (open(os.path.join(get_lib_dir(), ENDPOINT_FILE_NAME), "r")) as endpoint_file:
        endpoint = endpoint_file.read().rstrip()

    protocol = WireProtocol(endpoint)
    return GoalState(protocol.client, goal_state_properties=goal_state_properties, save_to_history=False, silent=True)


if __name__ == "__main__":
    main()
sys.exit(0)
