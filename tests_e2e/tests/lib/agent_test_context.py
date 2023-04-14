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
from tests_e2e.tests.lib.identifiers import VmIdentifier
from tests_e2e.tests.lib.ssh_client import SshClient


class AgentTestContext:
    """
    Execution context for agent tests. Defines the test VM, working directories and connection info for the tests.

    NOTE: The context is shared by all tests in the same runbook execution. Tests within the same test suite
          are executed sequentially, but multiple test suites may be executed concurrently depending on the
          concurrency level of the runbook.
    """
    class Paths:
        DEFAULT_TEST_SOURCE_DIRECTORY = Path(tests_e2e.__path__[0])

        def __init__(
            self,
            working_directory: Path,
            remote_working_directory: Path,
            test_source_directory: Path = DEFAULT_TEST_SOURCE_DIRECTORY
        ):
            self._test_source_directory: Path = test_source_directory
            self._working_directory: Path = working_directory
            self._remote_working_directory: Path = remote_working_directory

    class Connection:
        DEFAULT_SSH_PORT = 22

        def __init__(
            self,
            ip_address: str,
            username: str,
            private_key_file: Path,
            ssh_port: int = DEFAULT_SSH_PORT
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
        Tests can create temporary files under this directory.

        """
        return self._paths._working_directory

    @property
    def remote_working_directory(self) -> Path:
        """
        Tests can create temporary files under this directory on the test VM.
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

    def create_ssh_client(self) -> SshClient:
        return SshClient(
            ip_address=self.vm_ip_address,
            username=self.username,
            private_key_file=self.private_key_file,
            port=self.ssh_port)

    @staticmethod
    def from_args():
        """
        Creates an AgentTestContext from the command line arguments.
        """
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', '--cloud', dest="cloud", required=False, choices=['AzureCloud', 'AzureChinaCloud', 'AzureUSGovernment'], default="AzureCloud")
        parser.add_argument('-g', '--group', required=True)
        parser.add_argument('-l', '--location', required=True)
        parser.add_argument('-s', '--subscription', required=True)
        parser.add_argument('-vm', '--vm', required=True)

        parser.add_argument('-rw', '--remote-working-directory', dest="remote_working_directory", required=False, default=str(Path('/home')/os.getenv("USER")))
        parser.add_argument('-t', '--test-source-directory', dest="test_source_directory", required=False, default=str(AgentTestContext.Paths.DEFAULT_TEST_SOURCE_DIRECTORY))
        parser.add_argument('-w', '--working-directory', dest="working_directory", required=False, default=str(Path().home()/"tmp"))

        parser.add_argument('-a', '--ip-address', dest="ip_address", required=False)  # Use the vm name as default
        parser.add_argument('-u', '--username', required=False, default=os.getenv("USER"))
        parser.add_argument('-k', '--private-key-file', dest="private_key_file", required=False, default=str(Path.home()/".ssh"/"id_rsa"))
        parser.add_argument('-p', '--ssh-port', dest="ssh_port", required=False, default=AgentTestContext.Connection.DEFAULT_SSH_PORT)

        args = parser.parse_args()

        working_directory = Path(args.working_directory)
        if not working_directory.exists():
            working_directory.mkdir(exist_ok=True)

        return AgentTestContext(
            vm=VmIdentifier(
                cloud=args.cloud,
                location=args.location,
                subscription=args.subscription,
                resource_group=args.group,
                name=args.vm),
            paths=AgentTestContext.Paths(
                working_directory=Path(working_directory),
                remote_working_directory=Path(args.remote_working_directory),
                test_source_directory=Path(args.test_source_directory)),
            connection=AgentTestContext.Connection(
                ip_address=args.ip_address if args.ip_address is not None else args.vm,
                username=args.username,
                private_key_file=Path(args.private_key_file),
                ssh_port=args.ssh_port))
