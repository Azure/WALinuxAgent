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

import json

from typing import Any, Dict, List

from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry
from tests_e2e.tests.lib.update_arm_template import UpdateArmTemplate

# Name of the security group added by this class
NETWORK_SECURITY_GROUP: str = "waagent-nsg"


class AddNetworkSecurityGroup(UpdateArmTemplate):
    """
    Updates the ARM template to add a network security group allowing SSH access from the current machine.
    """
    def update(self, template: Dict[str, Any]) -> None:
        resources: List[Dict[str, Any]] = template["resources"]

        # Append the NSG to the list of resources
        network_security_group = json.loads(f"""{{
            "type": "Microsoft.Network/networkSecurityGroups",
            "name": "{NETWORK_SECURITY_GROUP}",
            "location": "[parameters('location')]",
            "apiVersion": "2020-05-01",
            "properties": {{
                "securityRules": []
            }}
        }}""")
        resources.append(network_security_group)

        # Add the SSH rule, but if anything fails just go ahead without it
        try:
            network_security_group["properties"]["securityRules"].append(json.loads(f"""{{
                "name": "waagent-ssh",
                "properties": {{
                    "description": "Allows inbound SSH connections from the orchestrator machine.",
                    "protocol": "Tcp",
                    "sourcePortRange": "*",
                    "destinationPortRange": "22",
                    "sourceAddressPrefix": "{self._my_ip_address}",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 100,
                    "direction": "Inbound"
                }}
            }}"""))
        except Exception as e:
            log.warning("******** Waagent: Failed to create Allow security rule for SSH, skipping rule: %s", e)


        #
        # Add reference to the NSG to the properties of the subnets.
        #
        # The subnets are a copy property of the virtual network in LISA's ARM template:
        #
        #     {
        #         "condition": "[empty(parameters('virtual_network_resource_group'))]",
        #         "apiVersion": "2020-05-01",
        #         "type": "Microsoft.Network/virtualNetworks",
        #         "name": "[parameters('virtual_network_name')]",
        #         "location": "[parameters('location')]",
        #         "properties": {
        #             "addressSpace": {
        #                 "addressPrefixes": [
        #                     "10.0.0.0/16"
        #                 ]
        #             },
        #             "copy": [
        #                 {
        #                     "name": "subnets",
        #                     "count": "[parameters('subnet_count')]",
        #                     "input": {
        #                         "name": "[concat(parameters('subnet_prefix'), copyIndex('subnets'))]",
        #                         "properties": {
        #                             "addressPrefix": "[concat('10.0.', copyIndex('subnets'), '.0/24')]"
        #                         }
        #                     }
        #                 }
        #             ]
        #         }
        #     }
        #
        network_resource = self._get_resource(resources, "Microsoft.Network/virtualNetworks")

        # Add a dependency on the NSG
        nsg_reference = f"[resourceId('Microsoft.Network/networkSecurityGroups', '{NETWORK_SECURITY_GROUP}')]"
        network_resource_dependencies = network_resource.get("dependsOn")
        if network_resource_dependencies is None:
            network_resource["dependsOn"] = [nsg_reference]
        else:
            network_resource_dependencies.append(nsg_reference)

        subnets_copy = network_resource["properties"].get("copy") if network_resource.get("properties") is not None else None
        if subnets_copy is None:
            raise Exception("Cannot find the copy property of the virtual network in the ARM template")

        subnets = [i for i in subnets_copy if "name" in i and i["name"] == 'subnets']
        if len(subnets) == 0:
            raise Exception("Cannot find the subnets of the virtual network in the ARM template")

        subnets_input = subnets[0].get("input")
        if subnets_input is None:
            raise Exception("Cannot find the input property of the subnets in the ARM template")

        nsg_reference = json.loads(f"""{{
          "networkSecurityGroup": {{
            "id": "[resourceId('Microsoft.Network/networkSecurityGroups', '{NETWORK_SECURITY_GROUP}')]"
          }}
        }}""")

        subnets_properties = subnets_input.get("properties")
        if subnets_properties is None:
            subnets_input["properties"] = nsg_reference
        else:
            subnets_properties.update(nsg_reference)

    @property
    def _my_ip_address(self) -> str:
        """
        Gets the IP address of the current machine.
        """
        if self.__my_ip_address is None:
            def get_my_address():
                # Forcing -4 option to fetch the ipv4 address
                cmd = ["curl", "-4", "ifconfig.io/ip"]
                stdout = shellutil.run_command(cmd)
                return stdout.strip()
            self.__my_ip_address = retry(get_my_address, attempts=3, delay=10)
        return self.__my_ip_address

    __my_ip_address: str = None
