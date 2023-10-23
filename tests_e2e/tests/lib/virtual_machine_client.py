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

import datetime
import json
import time
from typing import Any, Dict, List

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineExtension, VirtualMachineInstanceView, VirtualMachine
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import NetworkInterface, PublicIPAddress
from azure.mgmt.resource import ResourceManagementClient

from tests_e2e.tests.lib.azure_sdk_client import AzureSdkClient
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import execute_with_retry
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient


class VirtualMachineClient(AzureSdkClient):
    """
    Provides operations on virtual machines (get instance view, update, restart, etc).
    """
    def __init__(self, cloud: str, location: str, subscription: str, resource_group: str, name: str):
        super().__init__()
        self.cloud: str = cloud
        self.location = location
        self.subscription: str = subscription
        self.resource_group: str = resource_group
        self.name: str = name
        self._compute_client = AzureSdkClient.create_client(ComputeManagementClient, cloud, subscription)
        self._resource_client = AzureSdkClient.create_client(ResourceManagementClient, cloud, subscription)
        self._network_client = AzureSdkClient.create_client(NetworkManagementClient, cloud, subscription)

    def get_ip_address(self) -> str:
        """
        Retrieves the public IP address of the virtual machine
        """
        vm_model = self.get_model()
        nic: NetworkInterface = self._network_client.network_interfaces.get(
            resource_group_name=self.resource_group,
            network_interface_name=vm_model.network_profile.network_interfaces[0].id.split('/')[-1])  # the name of the interface is the last component of the id
        public_ip: PublicIPAddress = self._network_client.public_ip_addresses.get(
            resource_group_name=self.resource_group,
            public_ip_address_name=nic.ip_configurations[0].public_ip_address.id.split('/')[-1])  # the name of the ip address is the last component of the id
        return public_ip.ip_address

    def get_model(self) -> VirtualMachine:
        """
        Retrieves the model of the virtual machine.
        """
        log.info("Retrieving VM model for %s", self)
        return execute_with_retry(
            lambda: self._compute_client.virtual_machines.get(
                resource_group_name=self.resource_group,
                vm_name=self.name))

    def get_instance_view(self) -> VirtualMachineInstanceView:
        """
        Retrieves the instance view of the virtual machine
        """
        log.info("Retrieving instance view for %s", self)
        return execute_with_retry(lambda: self._compute_client.virtual_machines.get(
            resource_group_name=self.resource_group,
            vm_name=self.name,
            expand="instanceView"
        ).instance_view)

    def get_extensions(self) -> List[VirtualMachineExtension]:
        """
        Retrieves the extensions installed on the virtual machine
        """
        log.info("Retrieving extensions for %s", self)
        return execute_with_retry(
            lambda: self._compute_client.virtual_machine_extensions.list(
                resource_group_name=self.resource_group,
                vm_name=self.name))

    def update(self, properties: Dict[str, Any], timeout: int = AzureSdkClient._DEFAULT_TIMEOUT) -> None:
        """
        Updates a set of properties on the virtual machine
        """
        # location is a required by begin_create_or_update, always add it
        properties_copy = properties.copy()
        properties_copy["location"] = self.location

        log.info("Updating %s with properties: %s", self, properties_copy)

        self._execute_async_operation(
            lambda: self._compute_client.virtual_machines.begin_create_or_update(
                self.resource_group,
                self.name,
                properties_copy),
            operation_name=f"Update {self}",
            timeout=timeout)

    def reapply(self, timeout: int = AzureSdkClient._DEFAULT_TIMEOUT) -> None:
        """
        Reapplies the goal state on the virtual machine
        """
        self._execute_async_operation(
            lambda: self._compute_client.virtual_machines.begin_reapply(self.resource_group, self.name),
            operation_name=f"Reapply {self}",
            timeout=timeout)

    def restart(
        self,
        wait_for_boot,
        ssh_client: SshClient = None,
        boot_timeout: datetime.timedelta = datetime.timedelta(minutes=5),
        timeout: int = AzureSdkClient._DEFAULT_TIMEOUT) -> None:
        """
        Restarts (reboots) the virtual machine.

        NOTES:
            * If wait_for_boot is True, an SshClient must be provided in order to verify that the restart was successful.
            * 'timeout' is the timeout for the restart operation itself, while 'boot_timeout' is the timeout for waiting
               the boot to complete.
        """
        if wait_for_boot and ssh_client is None:
            raise ValueError("An SshClient must be provided if wait_for_boot is True")

        before_restart = datetime.datetime.utcnow()

        self._execute_async_operation(
            lambda: self._compute_client.virtual_machines.begin_restart(
                resource_group_name=self.resource_group,
                vm_name=self.name),
            operation_name=f"Restart {self}",
            timeout=timeout)

        if not wait_for_boot:
            return

        start = datetime.datetime.utcnow()
        while datetime.datetime.utcnow() < start + boot_timeout:
            log.info("Waiting for VM %s to boot", self)
            time.sleep(15)  # Note that we always sleep at least 1 time, to give the reboot time to start
            instance_view = self.get_instance_view()
            power_state = [s.code for s in instance_view.statuses if "PowerState" in s.code]
            if len(power_state) != 1:
                raise Exception(f"Could not find PowerState in the instance view statuses:\n{json.dumps(instance_view.statuses)}")
            log.info("VM's Power State: %s", power_state[0])
            if power_state[0] == "PowerState/running":
                # We may get an instance view captured before the reboot actually happened; verify
                # that the reboot actually happened by checking the system's uptime.
                log.info("Verifying VM's uptime to ensure the reboot has completed...")
                try:
                    uptime = ssh_client.run_command("cat /proc/uptime | sed 's/ .*//'", attempts=1).rstrip()  # The uptime is the first field in the file
                    log.info("Uptime: %s", uptime)
                    boot_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=float(uptime))
                    if boot_time > before_restart:
                        log.info("VM %s completed boot and is running. Boot time: %s", self, boot_time)
                        return
                    log.info("The VM has not rebooted yet. Restart time: %s. Boot time: %s", before_restart, boot_time)
                except CommandError as e:
                    if e.exit_code == 255 and "Connection refused" in str(e):
                        log.info("VM %s is not yet accepting SSH connections", self)
                    else:
                        raise
        raise Exception(f"VM {self} did not boot after {boot_timeout}")

    def __str__(self):
        return f"{self.resource_group}:{self.name}"
