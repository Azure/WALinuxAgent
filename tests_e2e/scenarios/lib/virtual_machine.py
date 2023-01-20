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
# This module includes facilities to execute some operations on virtual machines and scale sets (list extensions, restart, etc).
#

from abc import ABC, abstractmethod
from builtins import TimeoutError
from typing import Any, List

from azure.core.polling import LROPoller
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineExtension, VirtualMachineScaleSetExtension, VirtualMachineInstanceView, VirtualMachineScaleSetInstanceView
from azure.mgmt.resource import ResourceManagementClient

from tests_e2e.scenarios.lib.identifiers import VmIdentifier
from tests_e2e.scenarios.lib.logging import log
from tests_e2e.scenarios.lib.retry import execute_with_retry


class VirtualMachineBaseClass(ABC):
    """
    Abstract base class for VirtualMachine and VmScaleSet.

    Defines the interface common to both classes and provides the implementation of some methods in that interface.
    """
    def __init__(self, vm: VmIdentifier):
        super().__init__()
        self._identifier: VmIdentifier = vm
        self._compute_client = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=vm.subscription)
        self._resource_client = ResourceManagementClient(credential=DefaultAzureCredential(), subscription_id=vm.subscription)

    @abstractmethod
    def get_instance_view(self) -> Any:  # Returns VirtualMachineInstanceView or VirtualMachineScaleSetInstanceView
        """
        Retrieves the instance view of the virtual machine or scale set
        """

    @abstractmethod
    def get_extensions(self) -> Any:  # Returns List[VirtualMachineExtension] or List[VirtualMachineScaleSetExtension]
        """
        Retrieves the extensions installed on the virtual machine or scale set
        """

    def restart(self, timeout=5 * 60) -> None:
        """
        Restarts the virtual machine or scale set
        """
        log.info("Initiating restart of %s", self._identifier)

        poller: LROPoller = execute_with_retry(self._begin_restart)

        poller.wait(timeout=timeout)

        if not poller.done():
            raise TimeoutError(f"Failed to restart {self._identifier.name} after {timeout} seconds")

        log.info("Restarted %s", self._identifier.name)

    @abstractmethod
    def _begin_restart(self) -> LROPoller:
        """
        Derived classes must provide the implementation for this method using their corresponding begin_restart() implementation
        """

    def __str__(self):
        return f"{self._identifier}"


class VirtualMachine(VirtualMachineBaseClass):
    def get_instance_view(self) -> VirtualMachineInstanceView:
        log.info("Retrieving instance view for %s", self._identifier)
        return execute_with_retry(lambda: self._compute_client.virtual_machines.get(
            resource_group_name=self._identifier.resource_group,
            vm_name=self._identifier.name,
            expand="instanceView"
        ).instance_view)

    def get_extensions(self) -> List[VirtualMachineExtension]:
        log.info("Retrieving extensions for %s", self._identifier)
        return execute_with_retry(lambda: self._compute_client.virtual_machine_extensions.list(
            resource_group_name=self._identifier.resource_group,
            vm_name=self._identifier.name))

    def _begin_restart(self) -> LROPoller:
        return self._compute_client.virtual_machines.begin_restart(
            resource_group_name=self._identifier.resource_group,
            vm_name=self._identifier.name)


class VmScaleSet(VirtualMachineBaseClass):
    def get_instance_view(self) -> VirtualMachineScaleSetInstanceView:
        log.info("Retrieving instance view for %s", self._identifier)

        # TODO: Revisit this implementation. Currently this method returns the instance view of the first VM instance available.
        # For the instance view of the complete VMSS, use the compute_client.virtual_machine_scale_sets function
        # https://docs.microsoft.com/en-us/python/api/azure-mgmt-compute/azure.mgmt.compute.v2019_12_01.operations.virtualmachinescalesetsoperations?view=azure-python
        for vm in execute_with_retry(lambda: self._compute_client.virtual_machine_scale_set_vms.list(self._identifier.resource_group, self._identifier.name)):
            try:
                return execute_with_retry(lambda: self._compute_client.virtual_machine_scale_set_vms.get_instance_view(
                    resource_group_name=self._identifier.resource_group,
                    vm_scale_set_name=self._identifier.name,
                    instance_id=vm.instance_id))
            except Exception as e:
                log.warning("Unable to retrieve instance view for scale set instance %s. Trying out other instances.\nError: %s", vm, e)

        raise Exception(f"Unable to retrieve instance view of any instances for scale set {self._identifier}")


    @property
    def vm_func(self):
        return self._compute_client.virtual_machine_scale_set_vms

    @property
    def extension_func(self):
        return self._compute_client.virtual_machine_scale_set_extensions

    def get_extensions(self) -> List[VirtualMachineScaleSetExtension]:
        log.info("Retrieving extensions for %s", self._identifier)
        return execute_with_retry(lambda: self._compute_client.virtual_machine_scale_set_extensions.list(
            resource_group_name=self._identifier.resource_group,
            vm_scale_set_name=self._identifier.name))

    def _begin_restart(self) -> LROPoller:
        return self._compute_client.virtual_machine_scale_sets.begin_restart(
            resource_group_name=self._identifier.resource_group,
            vm_scale_set_name=self._identifier.name)
