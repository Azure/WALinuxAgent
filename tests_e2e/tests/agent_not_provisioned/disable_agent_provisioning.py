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


class DisableAgentProvisioning(UpdateArmTemplate):
    """
    Updates the ARM template to set osProfile.linuxConfiguration.provisionVMAgent to false.
    """
    def update(self, template: Dict[str, Any], is_lisa_template: bool) -> None:
        if not is_lisa_template:
            raise Exception('This test can only customize LISA ARM templates.')

        #
        # NOTE: LISA's template uses this function to generate the value for osProfile.linuxConfiguration. The function is
        #       under the 'lisa' namespace. We set 'provisionVMAgent' to False.
        #
        #     "getLinuxConfiguration": {
        #         "parameters": [
        #             ...
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
        get_linux_configuration = self.get_lisa_function(template, 'getLinuxConfiguration')
        output = self.get_function_output(get_linux_configuration)
        if output.get('customData') is not None:
            raise Exception(f"The getOSProfile function already has a 'customData'. Won't override it. Definition: {get_linux_configuration}")
        output['provisionVMAgent'] = False

