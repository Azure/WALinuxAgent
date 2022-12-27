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
# This module includes facilities to execute VM extension operations (enable, remove, etc) on single virtual machines (using
# class VmExtension) or virtual machine scale sets (using class VmssExtension).
#

import uuid

from abc import ABC, abstractmethod
from typing import Dict, Any

from azure.core.polling import LROPoller
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineExtension, VirtualMachineScaleSetExtension, VirtualMachineExtensionInstanceView
from azure.identity import DefaultAzureCredential

from tests_e2e.scenarios.lib.identifiers import VmIdentifier, VmExtensionIdentifier
from tests_e2e.scenarios.lib.logging_utils import LoggingHandler
from tests_e2e.scenarios.lib.retry import execute_with_retry


_TIMEOUT = 5 * 60  # Timeout for extension operations (in seconds)


class _VmExtensionBaseClass(ABC, LoggingHandler):
    """
    Abstract base class for VmExtension and VmssExtension.

    Defines the interface common to both classes and provides the implementation of some methods in that interface.
    """
    def __init__(self, vm: VmIdentifier, extension: VmExtensionIdentifier, resource_name: str):
        super().__init__()
        self._vm: VmIdentifier = vm
        self._identifier = extension
        self._resource_name = resource_name
        self._compute_client: ComputeManagementClient = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=vm.subscription)

    def enable(
        self,
        settings: Dict[str, Any] = None,
        protected_settings: Dict[str, Any] = None,
        auto_upgrade_minor_version: bool = True,
        force_update: bool = False,
        force_update_tag: str = None
    ) -> None:
        """
        Performs an enable operation on the extension.

        NOTE: 'force_update' is not a parameter of the actual ARM API. It is provided for convenience: If set to True,
              the 'force_update_tag' can be left unspecified and this method will generate a random tag.
        """
        if force_update_tag is not None and not force_update:
            raise ValueError("If force_update_tag is provided then force_update must be set to true")

        if force_update and force_update_tag is None:
            force_update_tag = str(uuid.uuid4())

        kwargs = {
            "settings": settings,
            "protected_settings": protected_settings,
            "auto_upgrade_minor_version": auto_upgrade_minor_version,
            "force_update_tag": force_update_tag
        }

        self.log.info("Enabling %s: %s", self._identifier, kwargs)

        result: VirtualMachineExtension = execute_with_retry(lambda: self._begin_enable(**kwargs).result(timeout=_TIMEOUT))

        if result.provisioning_state != 'Succeeded':
            raise Exception(f"Enable {self._identifier} failed. Provisioning state: {result.provisioning_state}")

    @abstractmethod
    def _begin_enable(
        self,
        settings: Dict[str, Any] = None,
        protected_settings: Dict[str, Any] = None,
        auto_upgrade_minor_version: bool = True,
        force_update_tag: str = None
    ) -> LROPoller[Any]:  # Can return LROPoller[VirtualMachineExtension] or LROPoller[VirtualMachineScaleSetExtension]
        """
        Derived classes must provide the implementation for this method using their corresponding begin_create_or_update() implementation
        """

    @abstractmethod
    def get_instance_view(self) -> VirtualMachineExtensionInstanceView:  # TODO: Check type for scale sets
        """
        Retrieves the instance view of the extension
        """

    @abstractmethod
    def delete(self) -> None:
        """
        Performs a delete operation on the extension
        """


class VmExtension(_VmExtensionBaseClass):
    """
    Extension operations on a single virtual machine.
    """
    def _begin_enable(
        self,
        settings: Dict[str, Any] = None,
        protected_settings: Dict[str, Any] = None,
        auto_upgrade_minor_version: bool = True,
        force_update_tag: str = None
    ) -> LROPoller[VirtualMachineExtension]:

        vme = VirtualMachineExtension(
            publisher=self._identifier.publisher,
            location=self._vm.location,
            type_properties_type=self._identifier.type,
            type_handler_version=self._identifier.version,
            auto_upgrade_minor_version=auto_upgrade_minor_version,
            settings=settings,
            protected_settings=protected_settings,
            force_update_tag=force_update_tag)

        return self._compute_client.virtual_machine_extensions.begin_create_or_update(
            self._vm.resource_group,
            self._vm.name,
            self._resource_name,
            vme)

    def get_instance_view(self) -> VirtualMachineExtensionInstanceView:
        self.log.info("Retrieving instance view for %s...", self._identifier)

        return execute_with_retry(lambda: self._compute_client.virtual_machine_extensions.get(
            resource_group_name=self._vm.resource_group,
            vm_name=self._vm.name,
            vm_extension_name=self._resource_name,
            expand="instanceView"
        ).instance_view)

    def delete(self) -> None:
        self.log.info("Removing %s", self._identifier)

        execute_with_retry(lambda: self._compute_client.virtual_machine_extensions.begin_delete(
            self._vm.resource_group,
            self._vm.name,
            self._resource_name
        ).wait(timeout=_TIMEOUT))


class VmssExtension(_VmExtensionBaseClass):
    """
    Extension operations on virtual machine scale sets.
    """
    def _begin_enable(
        self,
        settings: Dict[str, Any] = None,
        protected_settings: Dict[str, Any] = None,
        auto_upgrade_minor_version: bool = True,
        force_update_tag: str = None
    ) -> LROPoller[VirtualMachineScaleSetExtension]:

        vmsse = VirtualMachineScaleSetExtension(
            publisher=self._identifier.publisher,
            location=self._vm.location,
            type_properties_type=self._identifier.type,
            type_handler_version=self._identifier.version,
            auto_upgrade_minor_version=auto_upgrade_minor_version,
            settings=settings,
            protected_settings=protected_settings,
            force_update_tag=force_update_tag)

        return self._compute_client.virtual_machine_scale_set_extensions.begin_create_or_update(
            self._vm.resource_group,
            self._vm.name,
            self._resource_name,
            vmsse)

    def get_instance_view(self) -> VirtualMachineExtensionInstanceView:  # TODO: Check return type
        self.log.info("Retrieving instance view for %s...", self._identifier)

        return execute_with_retry(lambda: self._compute_client.virtual_machine_scale_set_extensions.get(
                resource_group_name=self._vm.resource_group,
                vm_scale_set_name=self._vm.name,
                vmss_extension_name=self._resource_name,
                expand="instanceView"
            ).instance_view)

    def delete(self) -> None:  # TODO: Implement this method
        raise NotImplementedError()

    def delete_from_instance(self, instance_id: str) -> None:
        self.log.info("Removing %s", self._identifier)

        execute_with_retry(lambda: self._compute_client.virtual_machine_scale_set_vm_extensions.begin_delete(
            resource_group_name=self._vm.resource_group,
            vm_scale_set_name=self._vm.name,
            vm_extension_name=self._resource_name,
            instance_id=instance_id
        ).wait(timeout=_TIMEOUT))

