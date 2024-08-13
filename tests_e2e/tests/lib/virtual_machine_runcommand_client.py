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
# This module includes facilities to execute VM extension runcommand operations (enable, remove, etc).
#
import json
from typing import Any, Dict, Callable
from assertpy import soft_assertions, assert_that

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineRunCommand, VirtualMachineRunCommandScriptSource, VirtualMachineRunCommandInstanceView

from tests_e2e.tests.lib.azure_sdk_client import AzureSdkClient
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import execute_with_retry
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIdentifier


class VirtualMachineRunCommandClient(AzureSdkClient):
    """
    Client for operations virtual machine RunCommand extensions.
    """
    def __init__(self, vm: VirtualMachineClient, extension: VmExtensionIdentifier, resource_name: str = None):
        super().__init__()
        self._vm: VirtualMachineClient = vm
        self._identifier = extension
        self._resource_name = resource_name or extension.type
        self._compute_client: ComputeManagementClient = AzureSdkClient.create_client(ComputeManagementClient, self._vm.cloud, self._vm.subscription)

    def get_instance_view(self) -> VirtualMachineRunCommandInstanceView:
        """
        Retrieves the instance view of the run command extension
        """
        log.info("Retrieving instance view for %s...", self._identifier)

        return execute_with_retry(lambda: self._compute_client.virtual_machine_run_commands.get_by_virtual_machine(
            resource_group_name=self._vm.resource_group,
            vm_name=self._vm.name,
            run_command_name=self._resource_name,
            expand="instanceView"
        ).instance_view)

    def enable(
        self,
        settings: Dict[str, Any] = None,
        timeout: int = AzureSdkClient._DEFAULT_TIMEOUT
    ) -> None:
        """
        Performs an enable operation on the run command extension.
        """
        run_command_parameters = VirtualMachineRunCommand(
            location=self._vm.location,
            source=VirtualMachineRunCommandScriptSource(
                script=settings.get("source") if settings is not None else settings
            )
        )

        log.info("Enabling %s", self._identifier)
        log.info("%s", run_command_parameters)

        result: VirtualMachineRunCommand = self._execute_async_operation(
            lambda: self._compute_client.virtual_machine_run_commands.begin_create_or_update(
                self._vm.resource_group,
                self._vm.name,
                self._resource_name,
                run_command_parameters),
            operation_name=f"Enable {self._identifier}",
            timeout=timeout)

        log.info("Provisioning state: %s", result.provisioning_state)

    def delete(self, timeout: int = AzureSdkClient._DEFAULT_TIMEOUT) -> None:
        """
        Performs a delete operation on the run command extension
        """
        self._execute_async_operation(
            lambda: self._compute_client.virtual_machine_run_commands.begin_delete(
                self._vm.resource_group,
                self._vm.name,
                self._resource_name),
            operation_name=f"Delete {self._identifier}",
            timeout=timeout)

    def assert_instance_view(
            self,
            expected_status_code: str = "Succeeded",
            expected_exit_code: int = 0,
            expected_message: str = None,
            assert_function: Callable[[VirtualMachineRunCommandInstanceView], None] = None
    ) -> None:
        """
        Asserts that the run command's instance view matches the given expected values. If 'expected_message' is
        omitted, it is not validated.

        If 'assert_function' is provided, it is invoked passing as parameter the instance view. This function can be used to perform
        additional validations.
        """
        instance_view = self.get_instance_view()
        log.info("Instance view:\n%s", json.dumps(instance_view.serialize(), indent=4))

        with soft_assertions():
            if expected_message is not None:
                assert_that(expected_message in instance_view.output).described_as(f"{expected_message} should be in the InstanceView message ({instance_view.output})").is_true()

            assert_that(instance_view.execution_state).described_as("InstanceView execution state").is_equal_to(expected_status_code)
            assert_that(instance_view.exit_code).described_as("InstanceView exit code").is_equal_to(expected_exit_code)

            if assert_function is not None:
                assert_function(instance_view)

        log.info("The instance view matches the expected values")

    def __str__(self):
        return f"{self._identifier}"
