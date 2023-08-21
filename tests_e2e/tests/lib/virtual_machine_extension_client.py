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
# This module includes facilities to execute VM extension operations (enable, remove, etc).
#

import uuid

from assertpy import assert_that, soft_assertions
from typing import Any, Callable, Dict

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineExtension, VirtualMachineExtensionInstanceView
from azure.identity import DefaultAzureCredential
from msrestazure.azure_cloud import Cloud

from tests_e2e.tests.lib.azure_clouds import AZURE_CLOUDS
from tests_e2e.tests.lib.azure_client import AzureClient
from tests_e2e.tests.lib.identifiers import VmIdentifier, VmExtensionIdentifier
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import execute_with_retry


class VirtualMachineExtensionClient(AzureClient):
    """
    Client for operations virtual machine extensions.
    """
    def __init__(self, vm: VmIdentifier, extension: VmExtensionIdentifier, resource_name: str = None):
        super().__init__()
        self._vm: VmIdentifier = vm
        self._identifier = extension
        self._resource_name = resource_name or extension.type
        cloud: Cloud = AZURE_CLOUDS[vm.cloud]
        credential: DefaultAzureCredential = DefaultAzureCredential(authority=cloud.endpoints.active_directory)
        self._compute_client: ComputeManagementClient = ComputeManagementClient(
            credential=credential,
            subscription_id=vm.subscription,
            base_url=cloud.endpoints.resource_manager,
            credential_scopes=[cloud.endpoints.resource_manager + "/.default"])

    def get_instance_view(self) -> VirtualMachineExtensionInstanceView:
        """
        Retrieves the instance view of the extension
        """
        log.info("Retrieving instance view for %s...", self._identifier)

        return execute_with_retry(lambda: self._compute_client.virtual_machine_extensions.get(
            resource_group_name=self._vm.resource_group,
            vm_name=self._vm.name,
            vm_extension_name=self._resource_name,
            expand="instanceView"
        ).instance_view)

    def enable(
        self,
        settings: Dict[str, Any] = None,
        protected_settings: Dict[str, Any] = None,
        auto_upgrade_minor_version: bool = True,
        force_update: bool = False,
        force_update_tag: str = None,
        timeout: int = AzureClient._DEFAULT_TIMEOUT
    ) -> None:
        """
        Performs an enable operation on the extension.

        NOTE: 'force_update' is not a parameter of the actual ARM API. It is provided here for convenience: If set to True,
              the 'force_update_tag' can be left unspecified and this method will generate a random tag.
        """
        if force_update_tag is not None and not force_update:
            raise ValueError("If force_update_tag is provided then force_update must be set to true")

        if force_update and force_update_tag is None:
            force_update_tag = str(uuid.uuid4())

        extension_parameters = VirtualMachineExtension(
            publisher=self._identifier.publisher,
            location=self._vm.location,
            type_properties_type=self._identifier.type,
            type_handler_version=self._identifier.version,
            auto_upgrade_minor_version=auto_upgrade_minor_version,
            settings=settings,
            protected_settings=protected_settings,
            force_update_tag=force_update_tag)

        # Hide the protected settings from logging
        if protected_settings is not None:
            extension_parameters.protected_settings = "*****[REDACTED]*****"
        log.info("Enabling %s", self._identifier)
        log.info("%s", extension_parameters)
        # Now set the actual protected settings before invoking the extension
        extension_parameters.protected_settings = protected_settings

        result: VirtualMachineExtension = self._execute_async_operation(
            lambda: self._compute_client.virtual_machine_extensions.begin_create_or_update(
                self._vm.resource_group,
                self._vm.name,
                self._resource_name,
                extension_parameters),
            operation_name=f"Enable {self._identifier}",
            timeout=timeout)

        log.info("Provisioning state: %s", result.provisioning_state)

    def delete(self, timeout: int = AzureClient._DEFAULT_TIMEOUT) -> None:
        """
        Performs a delete operation on the extension
        """
        self._execute_async_operation(
            lambda: self._compute_client.virtual_machine_extensions.begin_delete(
                self._vm.resource_group,
                self._vm.name,
                self._resource_name),
            operation_name=f"Delete {self._identifier}",
            timeout=timeout)

    def assert_instance_view(
            self,
            expected_status_code: str = "ProvisioningState/succeeded",
            expected_version: str = None,
            expected_message: str = None,
            assert_function: Callable[[VirtualMachineExtensionInstanceView], None] = None
    ) -> None:
        """
        Asserts that the extension's instance view matches the given expected values. If 'expected_version' and/or 'expected_message'
        are omitted, they are not validated.

        If 'assert_function' is provided, it is invoked passing as parameter the instance view. This function can be used to perform
        additional validations.
        """
        instance_view = self.get_instance_view()

        with soft_assertions():
            if expected_version is not None:
                # Compare only the major and minor versions (i.e. the first 2 items in the result of split())
                installed_version = instance_view.type_handler_version
                assert_that(expected_version.split(".")[0:2]).described_as("Unexpected extension version").is_equal_to(installed_version.split(".")[0:2])

            assert_that(instance_view.statuses).described_as(f"Expected 1 status, got: {instance_view.statuses}").is_length(1)
            status = instance_view.statuses[0]

            if expected_message is not None:
                assert_that(expected_message in status.message).described_as(f"{expected_message} should be in the InstanceView message ({status.message})").is_true()

            assert_that(status.code).described_as("InstanceView status code").is_equal_to(expected_status_code)

            if assert_function is not None:
                assert_function(instance_view)

        log.info("The instance view matches the expected values")

    def __str__(self):
        return f"{self._identifier}"




