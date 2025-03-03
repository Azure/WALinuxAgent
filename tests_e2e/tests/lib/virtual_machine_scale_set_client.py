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
# This module includes facilities to execute operations on virtual machines scale sets (list instances, delete, etc).
#

import re

from typing import List

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineScaleSetVM, VirtualMachineScaleSetInstanceView
from azure.mgmt.network import NetworkManagementClient

from tests_e2e.tests.lib.azure_sdk_client import AzureSdkClient
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import execute_with_retry


class VmssInstanceIpAddress(object):
    """
    IP address of a virtual machine scale set instance
    """
    def __init__(self, instance_name: str, ip_address: str):
        self.instance_name: str = instance_name
        self.ip_address: str = ip_address

    def __str__(self):
        return f"{self.instance_name}:{self.ip_address}"


class VirtualMachineScaleSetClient(AzureSdkClient):
    """
    Provides operations on virtual machine scale sets.
    """
    def __init__(self, cloud: str, location: str, subscription: str, resource_group: str, name: str):
        super().__init__()
        self.cloud: str = cloud
        self.location = location
        self.subscription: str = subscription
        self.resource_group: str = resource_group
        self.name: str = name
        self._compute_client = AzureSdkClient.create_client(ComputeManagementClient, cloud, subscription)
        self._network_client = AzureSdkClient.create_client(NetworkManagementClient, cloud, subscription)

    def list_vms(self) -> List[VirtualMachineScaleSetVM]:
        """
        Returns the VM instances of the virtual machine scale set
        """
        log.info("Retrieving instances of scale set %s", self)
        return list(self._compute_client.virtual_machine_scale_set_vms.list(resource_group_name=self.resource_group, virtual_machine_scale_set_name=self.name))

    def get_instances_ip_address(self) -> List[VmssInstanceIpAddress]:
        """
        Returns a list containing the IP addresses of scale set instances
        """
        log.info("Retrieving IP addresses of scale set %s", self)
        ip_addresses = self._network_client.public_ip_addresses.list_virtual_machine_scale_set_public_ip_addresses(resource_group_name=self.resource_group, virtual_machine_scale_set_name=self.name)
        ip_addresses = list(ip_addresses)

        def parse_instance(resource_id: str) -> str:
            # the resource_id looks like /subscriptions/{subs}}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmss}/virtualMachines/{instance}/networkInterfaces/{netiace}/ipConfigurations/ipconfig1/publicIPAddresses/{name}
            match = re.search(r'virtualMachines/(?P<instance>[0-9])/networkInterfaces', resource_id)
            if match is None:
                raise Exception(f"Unable to parse instance from IP address ID:{resource_id}")
            return match.group('instance')

        return [VmssInstanceIpAddress(instance_name=f"{self.name}_{parse_instance(a.id)}", ip_address=a.ip_address) for a in ip_addresses if a.ip_address is not None]

    def delete_extension(self, extension: str, timeout: int = AzureSdkClient._DEFAULT_TIMEOUT) -> None:
        """
        Deletes the given operation
        """
        log.info("Deleting extension %s from %s", extension, self)
        self._execute_async_operation(
            operation=lambda: self._compute_client.virtual_machine_scale_set_extensions.begin_delete(resource_group_name=self.resource_group, vm_scale_set_name=self.name, vmss_extension_name=extension),
            operation_name=f"Delete {extension} from {self}",
            timeout=timeout)

    def get_instance_view(self) -> VirtualMachineScaleSetInstanceView:
        """
        Retrieves the instance view of the virtual machine
        """
        log.info("Retrieving instance view for %s", self)
        return execute_with_retry(lambda: self._compute_client.virtual_machine_scale_sets.get_instance_view(
            resource_group_name=self.resource_group,
            vm_scale_set_name=self.name
        ))

    def __str__(self):
        return f"{self.resource_group}:{self.name}"

