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

import json
from typing import Any

_NSG_RESOURCE_TEMPLATE = """
{
    "type": "Microsoft.Network/networkSecurityGroups",
    "name": "internal-nsg",
    "location": "[parameters('location')]",
    "apiVersion": "2020-05-01",
    "properties": {
        "securityRules": [
            {
                "name": "ssh_rule",
                "properties": {
                    "description": "Locks inbound down to ssh default port 22.",
                    "protocol": "Tcp",
                    "sourcePortRange": "*",
                    "destinationPortRange": "22",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 110,
                    "direction": "Inbound"
                }
            },
            {
                "name": "outbound_rule",
                "properties": {
                    "description": "Locks outbound access.",
                    "protocol": "*",
                    "sourcePortRange": "*",
                    "destinationPortRange": "*",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "Internet",
                    "access": "Deny",
                    "priority": 200,
                    "direction": "Outbound"
                }
            }
        ]
    }
}
"""

_NSG_REFERENCE = """
{
  "networkSecurityGroup": {
    "id": "[resourceId('Microsoft.Network/networkSecurityGroups', 'internal-nsg')]"
  }
}
"""
_NSG_RESOURCE_ID_TEMPLATE = (
    "[resourceId('Microsoft.Network/networkSecurityGroups', 'internal-nsg')]"
)


def update_arm_template(template: Any) -> None:
    nsg_resource = json.loads(_NSG_RESOURCE_TEMPLATE)

    resources = template["resources"]
    resources.append(nsg_resource)

    # add dependency
    deployment_resource = _get_resource(
        resources, "Microsoft.Resources/deployments"
    )
    deployment_resource["dependsOn"].append(_NSG_RESOURCE_ID_TEMPLATE)

    # add reference
    template_resources = deployment_resource["properties"]["template"]["resources"]
    network_interface_resource = _get_resource(
        template_resources, "Microsoft.Network/networkInterfaces"
    )
    network_interface_resource["properties"].update(json.loads(_NSG_REFERENCE))


def _get_resource(resources: Any, type_name: str) -> Any:
    for item in resources:
        if item["type"] == type_name:
            return item
    else:
        raise Exception(f"Cannot find a resource of type {type_name} in the ARM template")
