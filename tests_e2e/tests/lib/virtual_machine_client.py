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

#
# This module includes facilities to execute operations on virtual machines (list extensions, restart, etc).
#

from typing import Any, Dict, List

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineExtension, VirtualMachineInstanceView, VirtualMachine
from azure.mgmt.resource import ResourceManagementClient
from msrestazure.azure_cloud import Cloud

from tests_e2e.tests.lib.azure_clouds import AZURE_CLOUDS
from tests_e2e.tests.lib.azure_client import AzureClient
from tests_e2e.tests.lib.identifiers import VmIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import execute_with_retry


class VirtualMachineClient(AzureClient):
    """
    Provides operations on virtual machine (get instance view, update, restart, etc).
    """
    def __init__(self, vm: VmIdentifier):
        super().__init__()
        self._identifier: VmIdentifier = vm
        cloud: Cloud = AZURE_CLOUDS[vm.cloud]
        credential: DefaultAzureCredential = DefaultAzureCredential(authority=cloud.endpoints.active_directory)
        self._compute_client = ComputeManagementClient(
            credential=credential,
            subscription_id=vm.subscription,
            base_url=cloud.endpoints.resource_manager,
            credential_scopes=[cloud.endpoints.resource_manager + "/.default"])
        self._resource_client = ResourceManagementClient(
            credential=credential,
            subscription_id=vm.subscription,
            base_url=cloud.endpoints.resource_manager,
            credential_scopes=[cloud.endpoints.resource_manager + "/.default"])

    def get_description(self) -> VirtualMachine:
        """
        Retrieves the description of the virtual machine.
        """
        log.info("Retrieving description for %s", self._identifier)
        return execute_with_retry(
            lambda: self._compute_client.virtual_machines.get(
                resource_group_name=self._identifier.resource_group,
                vm_name=self._identifier.name))

    def get_instance_view(self) -> VirtualMachineInstanceView:
        """
        Retrieves the instance view of the virtual machine
        """
        log.info("Retrieving instance view for %s", self._identifier)
        return execute_with_retry(lambda: self._compute_client.virtual_machines.get(
            resource_group_name=self._identifier.resource_group,
            vm_name=self._identifier.name,
            expand="instanceView"
        ).instance_view)

    def get_extensions(self) -> List[VirtualMachineExtension]:
        """
        Retrieves the extensions installed on the virtual machine
        """
        log.info("Retrieving extensions for %s", self._identifier)
        return execute_with_retry(
            lambda: self._compute_client.virtual_machine_extensions.list(
                resource_group_name=self._identifier.resource_group,
                vm_name=self._identifier.name))

    def update(self, properties: Dict[str, Any], timeout: int = AzureClient._DEFAULT_TIMEOUT) -> None:
        """
        Updates a set of properties on the virtual machine
        """
        # location is a required by begin_create_or_update, always add it
        properties_copy = properties.copy()
        properties_copy["location"] = self._identifier.location

        log.info("Updating %s with properties: %s", self._identifier, properties_copy)

        self._execute_async_operation(
            lambda: self._compute_client.virtual_machines.begin_create_or_update(
                self._identifier.resource_group,
                self._identifier.name,
                properties_copy),
            operation_name=f"Update {self._identifier}",
            timeout=timeout)

    def restart(self, timeout: int = AzureClient._DEFAULT_TIMEOUT) -> None:
        """
        Restarts the virtual machine or scale set
        """
        self._execute_async_operation(
            lambda: self._compute_client.virtual_machines.begin_restart(
                resource_group_name=self._identifier.resource_group,
                vm_name=self._identifier.name),
            operation_name=f"Restart {self._identifier}",
            timeout=timeout)

    def __str__(self):
        return f"{self._identifier}"




