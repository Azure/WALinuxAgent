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
import argparse
import os

from abc import ABC
from pathlib import Path

from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_scale_set_client import VirtualMachineScaleSetClient
from tests_e2e.tests.lib.ssh_client import SshClient


class AgentTestContext(ABC):
    """
    Base class for the execution context of agent tests; includes the working directories and SSH info for the tests.
    """
    DEFAULT_SSH_PORT = 22

    def __init__(self, working_directory: Path, username: str, identity_file: Path, ssh_port: int):
        self.working_directory: Path = working_directory
        self.username: str = username
        self.identity_file: Path = identity_file
        self.ssh_port: int = ssh_port

    @staticmethod
    def _create_argument_parser() -> argparse.ArgumentParser:
        """
        Creates an ArgumentParser that includes the arguments common to the concrete classes derived from AgentTestContext
        """
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', '--cloud', dest="cloud", required=False, choices=['AzureCloud', 'AzureChinaCloud', 'AzureUSGovernment'], default="AzureCloud")
        parser.add_argument('-g', '--group', required=True)
        parser.add_argument('-l', '--location', required=True)
        parser.add_argument('-s', '--subscription', required=True)

        parser.add_argument('-w', '--working-directory', dest="working_directory", required=False, default=str(Path().home() / "tmp"))

        parser.add_argument('-u', '--username', required=False, default=os.getenv("USER"))
        parser.add_argument('-k', '--identity-file', dest="identity_file", required=False, default=str(Path.home() / ".ssh" / "id_rsa"))
        parser.add_argument('-p', '--ssh-port', dest="ssh_port", required=False, default=AgentTestContext.DEFAULT_SSH_PORT)

        return parser


class AgentVmTestContext(AgentTestContext):
    """
    Execution context for agent tests targeted to individual VMs.
    """
    def __init__(self, working_directory: Path, vm: VirtualMachineClient, ip_address: str, username: str, identity_file: Path, ssh_port: int = AgentTestContext.DEFAULT_SSH_PORT):
        super().__init__(working_directory, username, identity_file, ssh_port)
        self.vm: VirtualMachineClient = vm
        self.ip_address: str = ip_address

    def create_ssh_client(self) -> SshClient:
        """
        Convenience method to create an SSH client using the connection info from the context.
        """
        return SshClient(
            ip_address=self.ip_address,
            username=self.username,
            identity_file=self.identity_file,
            port=self.ssh_port)

    @staticmethod
    def from_args():
        """
        Creates an AgentVmTestContext from the command line arguments.
        """
        parser = AgentTestContext._create_argument_parser()
        parser.add_argument('-vm', '--vm', required=True)
        parser.add_argument('-a', '--ip-address', dest="ip_address", required=False)  # Use the vm name as default

        args = parser.parse_args()

        working_directory: Path = Path(args.working_directory)
        if not working_directory.exists():
            working_directory.mkdir(exist_ok=True)

        vm = VirtualMachineClient(cloud=args.cloud, location=args.location, subscription=args.subscription, resource_group=args.group, name=args.vm)
        ip_address = args.ip_address if args.ip_address is not None else args.vm
        return AgentVmTestContext(working_directory=working_directory, vm=vm, ip_address=ip_address, username=args.username, identity_file=Path(args.identity_file), ssh_port=args.ssh_port)


class AgentVmssTestContext(AgentTestContext):
    """
    Execution context for agent tests targeted to VM Scale Sets.
    """
    def __init__(self, working_directory: Path, vmss: VirtualMachineScaleSetClient, username: str, identity_file: Path, ssh_port: int = AgentTestContext.DEFAULT_SSH_PORT):
        super().__init__(working_directory, username, identity_file, ssh_port)
        self.vmss: VirtualMachineScaleSetClient = vmss

    @staticmethod
    def from_args():
        """
        Creates an AgentVmssTestContext from the command line arguments.
        """
        parser = AgentTestContext._create_argument_parser()
        parser.add_argument('-vmss', '--vmss', required=True)

        args = parser.parse_args()

        working_directory: Path = Path(args.working_directory)
        if not working_directory.exists():
            working_directory.mkdir(exist_ok=True)

        vmss = VirtualMachineScaleSetClient(cloud=args.cloud, location=args.location, subscription=args.subscription, resource_group=args.group, name=args.vmss)
        return AgentVmssTestContext(working_directory=working_directory, vmss=vmss, username=args.username, identity_file=Path(args.identity_file), ssh_port=args.ssh_port)

