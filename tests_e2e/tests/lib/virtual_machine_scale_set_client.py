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

from typing import List, Dict

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachine
from azure.mgmt.network import NetworkManagementClient  # pylint: disable=E0401, E0611
from azure.mgmt.network.models import NetworkInterface, PublicIPAddress  # pylint: disable=E0401, E0611
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
        self._network_client = NetworkManagementClient(
            credential=credential,
            subscription_id=vmss.subscription,
            base_url=cloud.endpoints.resource_manager,
            credential_scopes=[cloud.endpoints.resource_manager + "/.default"])

    def get_vm_instance_names(self) -> List[str]:
        """
        Retrieves the names of the vm instances in the virtual machine scale set
        """
        log.info("Retrieving vm instances for %s", self._identifier)
        vms = execute_with_retry(
            lambda: self._compute_client.virtual_machine_scale_set_vms.list(
                resource_group_name=self._identifier.resource_group,
                virtual_machine_scale_set_name=self._identifier.name))
        return [vm.name for vm in vms]

    def delete_extension(self, extension: str, timeout: int = AzureClient._DEFAULT_TIMEOUT) -> None:
        """
        Performs a delete operation on the extension
        """
        self._execute_async_operation(
            lambda: self._compute_client.virtual_machine_scale_set_extensions.begin_delete(
                resource_group_name=self._identifier.resource_group,
                vm_scale_set_name=self._identifier.name,
                vmss_extension_name=extension),
            operation_name=f"Delete {extension} from {self._identifier}",
            timeout=timeout)

    def get_virtual_machines(self) -> List[Dict[str, str]]:
        """
        Gets the virtual machines in the scale set. Returns a List of Dicts describing the virtual machine by their
        name and public ip address:
        {
            "name": vm_name,
            "ip": vm_public_ip_address
        }
        """
        virtual_machines: List[Dict[str, str]] = []
        for vm in self.get_vm_instance_names():
            vm_model: VirtualMachine = self._compute_client.virtual_machines.get(
                resource_group_name=self._identifier.resource_group,
                vm_name=vm
            )
            nic: NetworkInterface = self._network_client.network_interfaces.get(
                resource_group_name=self._identifier.resource_group,
                network_interface_name=vm_model.network_profile.network_interfaces[0].id.split('/')[-1]
            )
            public_ip: PublicIPAddress = self._network_client.public_ip_addresses.get(
                resource_group_name=self._identifier.resource_group,
                public_ip_address_name=nic.ip_configurations[0].public_ip_address.id.split('/')[-1]
            )
            virtual_machines.append(
                {
                    "name": vm,
                    "ip": public_ip.ip_address
                }
            )
        return virtual_machines

    def __str__(self):
        return f"{self._identifier}"
