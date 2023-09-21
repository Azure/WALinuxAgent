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
# This module includes facilities to execute operations on virtual machines scale sets (list extensions, add extensions, etc).
#

from typing import Any, Dict, List

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineScaleSet, VirtualMachineScaleSetInstanceView, VirtualMachineScaleSetExtension, VirtualMachineScaleSetVM
from azure.mgmt.resource import ResourceManagementClient
from msrestazure.azure_cloud import Cloud

from tests_e2e.tests.lib.azure_clouds import AZURE_CLOUDS
from tests_e2e.tests.lib.azure_client import AzureClient
from tests_e2e.tests.lib.identifiers import VmssIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import execute_with_retry


class VirtualMachineScaleSetClient(AzureClient):
    """
    Provides operations on virtual machine scale set (template deployment, etc).
    """
    def __init__(self, vmss: VmssIdentifier):
        super().__init__()
        self._identifier: VmssIdentifier = vmss
        cloud: Cloud = AZURE_CLOUDS[vmss.cloud]
        credential: DefaultAzureCredential = DefaultAzureCredential(authority=cloud.endpoints.active_directory)
        self._compute_client = ComputeManagementClient(
            credential=credential,
            subscription_id=vmss.subscription,
            base_url=cloud.endpoints.resource_manager,
            credential_scopes=[cloud.endpoints.resource_manager + "/.default"])
        self._resource_client = ResourceManagementClient(
            credential=credential,
            subscription_id=vmss.subscription,
            base_url=cloud.endpoints.resource_manager,
            credential_scopes=[cloud.endpoints.resource_manager + "/.default"])

    def get_model(self) -> VirtualMachineScaleSet:
        """
        Retrieves the model of the virtual machine scale set.
        """
        log.info("Retrieving VM model for %s", self._identifier)
        return execute_with_retry(
            lambda: self._compute_client.virtual_machine_scale_sets.get(
                resource_group_name=self._identifier.resource_group,
                vm_scale_set_name=self._identifier.name))

    def get_instance_view(self) -> VirtualMachineScaleSetInstanceView:
        """
        Retrieves the instance view of the virtual machine scale set
        """
        log.info("Retrieving instance view for %s", self._identifier)
        return execute_with_retry(lambda: self._compute_client.virtual_machine_scale_sets.get(
            resource_group_name=self._identifier.resource_group,
            vm_scale_set_name=self._identifier.name,
            expand="instanceView"
        ).instance_view)

    def get_extensions(self) -> List[VirtualMachineScaleSetExtension]:
        """
        Retrieves the extensions installed on the virtual machine scale set
        """
        log.info("Retrieving extensions for %s", self._identifier)
        return execute_with_retry(
            lambda: self._compute_client.virtual_machine_scale_set_extensions.list(
                resource_group_name=self._identifier.resource_group,
                vm_scale_set_name=self._identifier.name))

    def get_vm_instance_names(self) -> List[str]:
        """
        Retrieves the vm instances of a virtual machine scale set
        """
        log.info("Retrieving vm instances for %s", self._identifier)
        vms = execute_with_retry(
            lambda: self._compute_client.virtual_machine_scale_set_vms.list(
                resource_group_name=self._identifier.resource_group,
                virtual_machine_scale_set_name=self._identifier.name))
        return [vm.name for vm in vms]

    def __str__(self):
        return f"{self._identifier}"




