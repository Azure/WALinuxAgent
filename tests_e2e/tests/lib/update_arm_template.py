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

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class UpdateArmTemplate(ABC):

    @abstractmethod
    def update(self, template: Dict[str, Any], is_lisa_template: bool) -> None:
        """
        Derived classes implement this method to customize the ARM template used to create the test VMs. The 'template' parameter is a dictionary
        created from the template's JSON document, as parsed by json.loads().

        If the 'is_lisa_template' parameter is True, the template was created by LISA. The original JSON document is located at
        https://github.com/microsoft/lisa/blob/main/lisa/sut_orchestrator/azure/arm_template.json
        """

    @staticmethod
    def _get_resource(resources: List[Dict[str, Any]], type_name: str) -> Any:
        """
        Returns the first resource of the specified type in the given 'resources' list.
        """
        for item in resources:
            if item["type"] == type_name:
                return item
        raise Exception(f"Cannot find a resource of type {type_name} in the ARM template")

    @staticmethod
    def _get_resource_by_name(resources: List[Dict[str, Any]], resource_name: str, type_name: str) -> Any:
        """
        Returns the first resource of the specified type and name in the given 'resources' list.
        """
        for item in resources:
            if item["type"] == type_name and item["name"] == resource_name:
                return item
        raise Exception(f"Cannot find a resource {resource_name} of type {type_name} in the ARM template")


