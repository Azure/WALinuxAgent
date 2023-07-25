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

from typing import Any, Dict

from tests_e2e.tests.lib.add_network_security_group import NETWORK_SECURITY_GROUP
from tests_e2e.tests.lib.update_arm_template import UpdateArmTemplate


class DenyOutboundConnections(UpdateArmTemplate):
    """
    Updates the ARM template to add a security rule that denies all outbound connections.
    """
    def update(self, template: Dict[str, Any]) -> None:
        resources = template["resources"]
        nsg = self._get_resource_by_name(resources, NETWORK_SECURITY_GROUP, "Microsoft.Network/networkSecurityGroups")
        properties = nsg.get("properties")

        if properties is None:
            raise Exception("Cannot find the properties of the Network Security Group in the ARM template")

        security_rules = properties.get("securityRules")
        if security_rules is None:
            raise Exception("Cannot find the security rules of the Network Security Group in the ARM template")

        security_rules.append(json.loads("""{
            "name": "waagent-no-outbound",
            "properties": {
                "description": "Denies all outbound connections.",
                "protocol": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
                "sourceAddressPrefix": "*",
                "destinationAddressPrefix": "Internet",
                "access": "Deny",
                "priority": 200,
                "direction": "Outbound"
            }
        }"""))

