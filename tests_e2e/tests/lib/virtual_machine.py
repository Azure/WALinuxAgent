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
from azure.mgmt.compute.models import VirtualMachineExtension, VirtualMachineScaleSetExtension, VirtualMachineInstanceView, VirtualMachineScaleSetInstanceView, VirtualMachine, VirtualMachineScaleSetVM
from azure.mgmt.resource import ResourceManagementClient
from msrestazure.azure_cloud import Cloud

from tests_e2e.tests.lib.azure_clouds import AZURE_CLOUDS
from tests_e2e.tests.lib.identifiers import VmIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import execute_with_retry


class VirtualMachineBaseClass(ABC):
    """
    Abstract base class for VirtualMachine and VmScaleSet.

    Defines the interface common to both classes and provides the implementation of some methods in that interface.
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

    @abstractmethod
    def get(self) -> Any:
        """
        Retrieves the information about the virtual machine or scale set
        """

    def create_or_update(self, parameters=None, timeout=5 * 60) -> None:
        """
        Creates or updates the virtual machine or scale set with custom settings
        """
        if parameters is None:
            parameters = {}

        log.info("Creating/Updating VM for %s", self._identifier)

        poller: LROPoller = execute_with_retry(lambda: self._begin_create_or_update(parameters))

        poller.wait(timeout=timeout)

        if not poller.done():
            raise TimeoutError(f"Failed to restart {self._identifier.name} after {timeout} seconds")

    @abstractmethod
    def _begin_create_or_update(self, parameters) -> Any:
        """
        Derived classes must provide the implementation for this method using their corresponding begin_create_or_update() implementation
        """

    def __str__(self):
        return f"{self._identifier}"


class VmMachine(VirtualMachineBaseClass):
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

    def get(self) -> VirtualMachine:
        log.info("Retrieving vm information for %s", self._identifier)
        return execute_with_retry(lambda: self._compute_client.virtual_machines.get(
            resource_group_name=self._identifier.resource_group,
            vm_name=self._identifier.name))

    def _begin_restart(self) -> LROPoller:
        return self._compute_client.virtual_machines.begin_restart(
            resource_group_name=self._identifier.resource_group,
            vm_name=self._identifier.name)

    def _begin_create_or_update(self, parameters) -> LROPoller:
        return self._compute_client.virtual_machines.begin_create_or_update(self._identifier.resource_group, self._identifier.name, parameters)


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

    def get(self) -> List[VirtualMachineScaleSetVM]:
        log.info("Retrieving vm information for %s", self._identifier)
        vmss_vm_list: List[VirtualMachineScaleSetVM] = []
        for vm in execute_with_retry(lambda: self._compute_client.virtual_machine_scale_set_vms.list(self._identifier.resource_group, self._identifier.name)):
            try:
                vmss_vm: VirtualMachineScaleSetVM = execute_with_retry(self._compute_client.virtual_machine_scale_set_vms.get(
                    resource_group_name=self._identifier.resource_group, vm_scale_set_name=self._identifier.name, instance_id=vm.instance_id))
                vmss_vm_list.append(vmss_vm)

            except Exception as e:
                log.warning("Unable to retrieve vm information for scale set instance %s. Trying out other instances.\nError: %s", vm, e)

        return vmss_vm_list

    def _begin_restart(self) -> LROPoller:
        return self._compute_client.virtual_machine_scale_sets.begin_restart(
            resource_group_name=self._identifier.resource_group,
            vm_scale_set_name=self._identifier.name)

    def _begin_create_or_update(self, parameters) -> None:
        # TODO: Revisit this implementation
        return