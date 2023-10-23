#!/usr/bin/env python3

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
# This test verifies that the Agent can download and extract KeyVault certificates that use different encryption algorithms (currently EC and RSA).
#
from assertpy import fail

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient


class KeyvaultCertificates(AgentVmTest):
    def run(self):
        test_certificates = {
            'C49A06B3044BD1778081366929B53EBF154133B3': {
                'AzureCloud':        'https://waagenttests.vault.azure.net/secrets/ec-cert/39862f0c6dff4b35bc8a83a5770c2102',
                'AzureChinaCloud':   'https://waagenttests.vault.azure.cn/secrets/ec-cert/bb610217ef70412bb3b3c8d7a7fabfdc',
                'AzureUSGovernment': 'https://waagenttests.vault.usgovcloudapi.net/secrets/ec-cert/9c20ef55c7074a468f04a168b3488933'
            },
            '2F846E657258E50C7011E1F68EA9AD129BA4AB31': {
                'AzureCloud':        'https://waagenttests.vault.azure.net/secrets/rsa-cert/0b5eac1e66fb457bb3c3419fce17e705',
                'AzureChinaCloud':   'https://waagenttests.vault.azure.cn/secrets/rsa-cert/98679243f8d6493e95281a852d8cee00',
                'AzureUSGovernment': 'https://waagenttests.vault.usgovcloudapi.net/secrets/rsa-cert/463a8a6be3b3436d85d3d4e406621c9e'
            }
        }
        thumbprints = test_certificates.keys()
        certificate_urls = [u[self._context.vm.cloud] for u in test_certificates.values()]

        # The test certificates should be downloaded to these locations
        expected_certificates = " ".join([f"/var/lib/waagent/{t}.{{crt,prv}}" for t in thumbprints])

        # The test may be running on a VM that has already been tested (e.g. while debugging the test), so we need to delete any existing test certificates first
        # (note that rm -f does not fail if the given files do not exist)
        ssh_client: SshClient = self._context.create_ssh_client()
        log.info("Deleting any existing test certificates on the test VM.")
        existing_certificates = ssh_client.run_command(f"rm -f -v {expected_certificates}", use_sudo=True)
        if existing_certificates == "":
            log.info("No existing test certificates were found on the test VM.")
        else:
            log.info("Some test certificates had already been downloaded to the test VM (they have been deleted now):\n%s", existing_certificates)

        vm: VirtualMachineClient = VirtualMachineClient(cloud=self._context.vm.cloud, location=self._context.vm.location, resource_group=self._context.vm.resource_group, name=self._context.vm.name)

        osprofile = {
            "location": self._context.vm.location,
            "properties": {
                "osProfile": {
                    "secrets": [
                        {
                            "sourceVault": {
                                "id": f"/subscriptions/{self._context.vm.subscription}/resourceGroups/waagent-tests/providers/Microsoft.KeyVault/vaults/waagenttests"
                            },
                            "vaultCertificates": [{"certificateUrl": url} for url in certificate_urls]
                        }
                    ],
                }
            }
        }
        log.info("updating the vm's osProfile with the certificates to download:\n%s", osprofile)
        vm.update(osprofile)

        # If the test has already run on the VM, force a new goal state to ensure the certificates are downloaded since the VM model most likely already had the certificates
        # and the update operation would not have triggered a goal state
        if existing_certificates != "":
            log.info("Reapplying the goal state to ensure the test certificates are downloaded.")
            vm.reapply()

        try:
            output = ssh_client.run_command(f"ls {expected_certificates}", use_sudo=True)
            log.info("Found all the expected certificates:\n%s", output)
        except CommandError as error:
            if error.stdout != "":
                log.info("Found some of the expected certificates:\n%s", error.stdout)
            fail(f"Failed to find certificates\n{error.stderr}")


if __name__ == "__main__":
    KeyvaultCertificates.run_from_command_line()
