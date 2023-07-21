#!/usr/bin/env python3

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

from typing import Any, Dict

from tests_e2e.tests.lib.update_arm_template import UpdateArmTemplate


class DenyOutboundConnections(UpdateArmTemplate):
    """
    Updates the ARM template to set osProfile.linuxConfiguration.provisionVMAgent to false.
    """
    def update(self, template: Dict[str, Any]) -> None:
        #
        # NOTE: LISA's template uses this function to generate the value for osProfile.linuxConfiguration. The function is
        #       under the 'lisa' namespace.
        #
        #     "getLinuxConfiguration": {
        #         "parameters": [
        #             {
        #                 "name": "keyPath",
        #                 "type": "string"
        #             },
        #             {
        #                 "name": "publicKeyData",
        #                 "type": "string"
        #             }
        #         ],
        #         "output": {
        #             "type": "object",
        #             "value": {
        #                 "disablePasswordAuthentication": true,
        #                 "ssh": {
        #                     "publicKeys": [
        #                         {
        #                             "path": "[parameters('keyPath')]",
        #                             "keyData": "[parameters('publicKeyData')]"
        #                         }
        #                     ]
        #                 },
        #                 "provisionVMAgent": true
        #             }
        #         }
        #     }
        #
        # The code below sets template['functions'][i]['members']['getLinuxConfiguration']['output']['value']['provisionVMAgent'] to True,
        # where template['functions'][i] is the 'lisa' namespace.
        #
        functions = template.get("functions")
        if functions is None:
            raise Exception('Cannot find "functions" in the LISA template.')
        for namespace in functions:
            name = namespace.get("namespace")
            if name is None:
                raise Exception(f'Cannot find "namespace" in the LISA template: {namespace}')
            if name == "lisa":
                members = namespace.get('members')
                if members is None:
                    raise Exception(f'Cannot find the members of the lisa namespace in the LISA template: {namespace}')
                get_linux_configuration = members.get('getLinuxConfiguration')
                if get_linux_configuration is None:
                    raise Exception(f'Cannot find the "getLinuxConfiguration" function the lisa namespace in the LISA template: {namespace}')
                output = get_linux_configuration.get('output')
                if output is None:
                    raise Exception(f'Cannot find the "output" of the getLinuxConfiguration function in the LISA template: {get_linux_configuration}')
                value = output.get('value')
                if value is None:
                    raise Exception(f"Cannot find the output's value of the getLinuxConfiguration function in the LISA template: {get_linux_configuration}")
                value['provisionVMAgent'] = False
                break
        else:
            raise Exception(f'Cannot find the "lisa" namespace in the LISA template: {functions}')

