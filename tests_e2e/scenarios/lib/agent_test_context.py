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

from pathlib import Path

import tests_e2e
from tests_e2e.scenarios.lib.identifiers import VmIdentifier


class AgentTestContext:
    """
    Execution context for agent tests. Defines the test VM, working directories and connection info for the tests.
    """
    class Paths:
        def __init__(
            self,
            remote_working_directory: Path,
            # E1101: Instance of 'list' has no '_path' member (no-member)
            test_source_directory: Path = Path(tests_e2e.__path__._path[0]),  # pylint: disable=E1101
            working_directory: Path = Path().home()/"waagent-tmp"
        ):
            self._test_source_directory: Path = test_source_directory
            self._working_directory: Path = working_directory
            self._remote_working_directory: Path = remote_working_directory

    class Connection:
        def __init__(
            self,
            ip_address: str,
            username: str,
            private_key_file: Path,
            ssh_port: int = 22
        ):
            self._ip_address: str = ip_address
            self._username: str = username
            self._private_key_file: Path = private_key_file
            self._ssh_port: int = ssh_port

    def __init__(self, vm: VmIdentifier, paths: Paths, connection: Connection):
        self._vm: VmIdentifier = vm
        self._paths = paths
        self._connection = connection

    @property
    def vm(self) -> VmIdentifier:
        """
        The test VM (the VM on which the tested Agent is running)
        """
        return self._vm

    @property
    def vm_ip_address(self) -> str:
        """
        The IP address of the test VM
        """
        return self._connection._ip_address

    @property
    def test_source_directory(self) -> Path:
        """
        Root directory for the source code of the tests. Used to build paths to specific scripts.
        """
        return self._paths._test_source_directory

    @property
    def working_directory(self) -> Path:
        """
        Tests create temporary files under this directory
        """
        return self._paths._working_directory

    @property
    def remote_working_directory(self) -> Path:
        """
        Tests create temporary files under this directory on the test VM
        """
        return self._paths._remote_working_directory

    @property
    def username(self) -> str:
        """
        The username to use for SSH connections
        """
        return self._connection._username

    @property
    def private_key_file(self) -> Path:
        """
        The file containing the private SSH key for the username
        """
        return self._connection._private_key_file

    @property
    def ssh_port(self) -> int:
        """
        Port for SSH connections
        """
        return self._connection._ssh_port

    @staticmethod
    def from_args():
        """
        Creates an AgentTestContext from the command line arguments.
        """
        parser = argparse.ArgumentParser()
        parser.add_argument('--group', required=True)
        parser.add_argument('--location', required=True)
        parser.add_argument('--subscription', required=True)
        parser.add_argument('--vm', required=True)

        parser.add_argument('--remote_working_directory', required=False, default=Path('/home')/os.getenv("USER"))
        parser.add_argument('--test_source_directory', required=False)  # Use the default defined by AgentTestContext.Paths
        parser.add_argument('--working_directory', required=False)  # Use the default defined by AgentTestContext.Paths

        parser.add_argument('--ip_address', required=False)  # Use the vm name as default
        parser.add_argument('--username', required=False, default=os.getenv("USER"))
        parser.add_argument('--private_key_file', required=False, default=Path.home()/".ssh"/"id_rsa")
        parser.add_argument('--ssh_port', required=False)  # Use the default defined by AgentTestContext.Connections

        args = parser.parse_args()

        paths_kwargs = {"remote_working_directory": args.remote_working_directory}
        if args.test_source_directory is not None:
            paths_kwargs["test_source_directory"] = args.test_source_directory
        if args.working_directory is not None:
            paths_kwargs["working_directory"] = args.working_directory

        connection_kwargs = {
            "ip_address": args.ip_address if args.ip_address is not None else args.vm,
            "username": args.username,
            "private_key_file": args.private_key_file
        }
        if args.ssh_port is not None:
            connection_kwargs["ssh_port"] = args.ssh_port

        return AgentTestContext(
            vm=VmIdentifier(
                location=args.location,
                subscription=args.subscription,
                resource_group=args.group,
                name=args.vm),
            paths=AgentTestContext.Paths(**paths_kwargs),
            connection=AgentTestContext.Connection(**connection_kwargs))
