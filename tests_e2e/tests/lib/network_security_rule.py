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

from typing import Any, Dict

from tests_e2e.tests.lib.update_arm_template import UpdateArmTemplate


class NetworkSecurityRule:
    """
    Provides methods to add network security rules to the given ARM template.

    The security rules are added under _NETWORK_SECURITY_GROUP, which is also added to the template.
    """
    def __init__(self, template: Dict[str, Any], is_lisa_template: bool):
        self._template = template
        self._is_lisa_template = is_lisa_template

    _NETWORK_SECURITY_GROUP: str = "waagent-nsg"

    def add_allow_ssh_rule(self, ip_address: str) -> None:
        self.add_security_rule(
            json.loads(f"""{{
                "name": "waagent-ssh",
                "properties": {{
                    "description": "Allows inbound SSH connections from the orchestrator machine.",
                    "protocol": "Tcp",
                    "sourcePortRange": "*",
                    "destinationPortRange": "22",
                    "sourceAddressPrefix": "{ip_address}",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 100,
                    "direction": "Inbound"
                }}
            }}"""))

    def add_security_rule(self, security_rule: Dict[str, Any]) -> None:
        self._get_network_security_group()["properties"]["securityRules"].append(security_rule)

    def _get_network_security_group(self) -> Dict[str, Any]:
        resources: Dict[str, Dict[str, Any]] = self._template["resources"]
        #
        # If the NSG already exists, just return it
        #
        try:
            return UpdateArmTemplate.get_resource_by_name(resources, self._NETWORK_SECURITY_GROUP, "Microsoft.Network/networkSecurityGroups")
        except KeyError:
            pass

        #
        # Otherwise, create it and append it to the list of resources
        #
        network_security_group = json.loads(f"""{{
            "type": "Microsoft.Network/networkSecurityGroups",
            "name": "{self._NETWORK_SECURITY_GROUP}",
            "location": "[resourceGroup().location]",
            "apiVersion": "2020-05-01",
            "properties": {{
                "securityRules": []
            }}
        }}""")
        nsg_reference = "network_security_groups"
        resources[nsg_reference] = network_security_group

        #
        # Add a dependency on the NSG to the virtual network
        #
        network_resource = UpdateArmTemplate.get_resource(resources, "Microsoft.Network/virtualNetworks")
        network_resource_dependencies = network_resource.get("dependsOn")
        if network_resource_dependencies is None:
            network_resource["dependsOn"] = [nsg_reference]
        else:
            network_resource_dependencies.append(nsg_reference)

        #
        # Add a reference to the NSG to the properties of the subnets.
        #
        nsg_reference = json.loads(f"""{{
          "networkSecurityGroup": {{
            "id": "[resourceId('Microsoft.Network/networkSecurityGroups', '{self._NETWORK_SECURITY_GROUP}')]"
          }}
        }}""")

        if self._is_lisa_template:
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
            subnets_copy = network_resource["properties"].get("copy") if network_resource.get("properties") is not None else None
            if subnets_copy is None:
                raise Exception("Cannot find the copy property of the virtual network in the ARM template")

            subnets = [i for i in subnets_copy if "name" in i and i["name"] == 'subnets']
            if len(subnets) == 0:
                raise Exception("Cannot find the subnets of the virtual network in the ARM template")

            subnets_input = subnets[0].get("input")
            if subnets_input is None:
                raise Exception("Cannot find the input property of the subnets in the ARM template")

            subnets_properties = subnets_input.get("properties")
            if subnets_properties is None:
                subnets_input["properties"] = nsg_reference
            else:
                subnets_properties.update(nsg_reference)
        else:
            #
            # The subnets are simple property of the virtual network in template for scale sets:
            #     {
            #         "apiVersion": "2023-06-01",
            #         "type": "Microsoft.Network/virtualNetworks",
            #         "name": "[variables('virtualNetworkName')]",
            #         "location": "[resourceGroup().location]",
            #         "properties": {
            #             "addressSpace": {
            #                 "addressPrefixes": [
            #                     "[variables('vnetAddressPrefix')]"
            #                 ]
            #             },
            #             "subnets": [
            #                 {
            #                     "name": "[variables('subnetName')]",
            #                     "properties": {
            #                         "addressPrefix": "[variables('subnetPrefix')]",
            #                     }
            #                 }
            #             ]
            #         }
            #     }
            subnets = network_resource["properties"].get("subnets") if network_resource.get("properties") is not None else None
            if subnets is None:
                raise Exception("Cannot find the subnets property of the virtual network in the ARM template")

            subnets_properties = subnets[0].get("properties")
            if subnets_properties is None:
                subnets["properties"] = nsg_reference
            else:
                subnets_properties.update(nsg_reference)

        return network_security_group
