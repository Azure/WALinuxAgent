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
from typing import Any, Dict


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
    def get_resource(resources: Dict[str, Dict[str, Any]], type_name: str) -> Any:
        """
        Returns the first resource of the specified type in the given 'resources' list.

        Raises KeyError if no resource of the specified type is found.
        """
        for item in resources.values():
            if item["type"] == type_name:
                return item
        raise KeyError(f"Cannot find a resource of type {type_name} in the ARM template")

    @staticmethod
    def get_resource_by_name(resources: Dict[str, Dict[str, Any]], resource_name: str, type_name: str) -> Any:
        """
        Returns the first resource of the specified type and name in the given 'resources' list.

        Raises KeyError if no resource of the specified type and name is found.
        """
        for item in resources.values():
            if item["type"] == type_name and item["name"] == resource_name:
                return item
        raise KeyError(f"Cannot find a resource {resource_name} of type {type_name} in the ARM template")

    @staticmethod
    def get_lisa_function(template: Dict[str, Any], function_name: str) -> Dict[str, Any]:
        """
        Looks for the given function name in the LISA namespace and returns its definition. Raises KeyError if the function is not found.
        """
        #
        # NOTE: LISA's functions are in the "lisa" namespace, for example:
        #
        # "functions": [
        #     {
        #         "namespace": "lisa",
        #         "members": {
        #             "getOSProfile": {
        #                 "parameters": [
        #                     {
        #                         "name": "computername",
        #                         "type": "string"
        #                     },
        #                     etc.
        #                 ],
        #                 "output": {
        #                     "type": "object",
        #                     "value": {
        #                         "computername": "[parameters('computername')]",
        #                         "adminUsername": "[parameters('admin_username')]",
        #                         "adminPassword": "[if(parameters('has_password'), parameters('admin_password'), json('null'))]",
        #                         "linuxConfiguration": "[if(parameters('has_linux_configuration'), parameters('linux_configuration'), json('null'))]"
        #                     }
        #                 }
        #             },
        #         }
        #     }
        # ]
        functions = template.get("functions")
        if functions is None:
            raise Exception('Cannot find "functions" in the LISA template.')

        for namespace in functions:
            name = namespace.get("namespace")
            if name is None:
                raise Exception(f'Cannot find "namespace" in the LISA template: {namespace}')
            if name == "lisa":
                lisa_functions = namespace.get('members')
                if lisa_functions is None:
                    raise Exception(f'Cannot find the members of the lisa namespace in the LISA template: {namespace}')
                function_definition = lisa_functions.get(function_name)
                if function_definition is None:
                    raise KeyError(f'Cannot find function {function_name} in the lisa namespace in the LISA template: {namespace}')
                return function_definition
        raise Exception(f'Cannot find the "lisa" namespace in the LISA template: {functions}')

    @staticmethod
    def get_function_output(function: Dict[str, Any]) -> Dict[str, Any]:
        """
        Returns the "value" property of the output for the given function.

        Sample function:

            {
                "parameters": [
                    {
                        "name": "computername",
                        "type": "string"
                    },
                    etc.
                ],
                "output": {
                    "type": "object",
                    "value": {
                        "computername": "[parameters('computername')]",
                        "adminUsername": "[parameters('admin_username')]",
                        "adminPassword": "[if(parameters('has_password'), parameters('admin_password'), json('null'))]",
                        "linuxConfiguration": "[if(parameters('has_linux_configuration'), parameters('linux_configuration'), json('null'))]"
                    }
                }
            }
        """
        output = function.get('output')
        if output is None:
            raise Exception(f'Cannot find the "output" of the given function: {function}')
        value = output.get('value')
        if value is None:
            raise Exception(f"Cannot find the output's value of the given function: {function}")
        return value
