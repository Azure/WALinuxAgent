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
import base64

from typing import Any, Dict

from tests_e2e.tests.agent_wait_for_cloud_init.agent_wait_for_cloud_init import AgentWaitForCloudInit
from tests_e2e.tests.lib.update_arm_template import UpdateArmTemplate


class AddCloudInitScript(UpdateArmTemplate):
    """
    Adds AgentWaitForCloudInit.CloudInitScript to the ARM template as osProfile.customData.
    """
    def update(self, template: Dict[str, Any], is_lisa_template: bool) -> None:
        if not is_lisa_template:
            raise Exception('This test can only customize LISA ARM templates.')

        #
        # cloud-init configuration needs to be added in the osProfile.customData property as a base64-encoded string.
        #
        # LISA uses the getOSProfile function to generate the value for osProfile; add customData to its output, checking that we do not
        # override any existing value (the current LISA template does not have any).
        #
        #    "getOSProfile": {
        #        "parameters": [
        #            ...
        #        ],
        #        "output": {
        #            "type": "object",
        #            "value": {
        #                "computername": "[parameters('computername')]",
        #                "adminUsername": "[parameters('admin_username')]",
        #                "adminPassword": "[if(parameters('has_password'), parameters('admin_password'), json('null'))]",
        #                "linuxConfiguration": "[if(parameters('has_linux_configuration'), parameters('linux_configuration'), json('null'))]"
        #            }
        #        }
        #    }
        #
        encoded_script = base64.b64encode(AgentWaitForCloudInit.CloudInitScript.encode('utf-8')).decode('utf-8')

        get_os_profile = self.get_lisa_function(template, 'getOsProfile')
        output = self.get_function_output(get_os_profile)
        if output.get('customData') is not None:
            raise Exception(f"The getOSProfile function already has a 'customData'. Won't override it. Definition: {get_os_profile}")
        output['customData'] = encoded_script

