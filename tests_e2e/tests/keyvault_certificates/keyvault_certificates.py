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
import datetime
import time

from assertpy import fail

from azurelinuxagent.common.future import UTC

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient


class KeyvaultCertificates(AgentVmTest):
    def run(self):
        test_certificates = {
            'C714CBBBDCD6EB48B05E4F69E2E8BCBB87D244BE': {
                'AzureCloud':        'https://waagenttests.vault.azure.net/secrets/ec-cert/f2239d3eedf34312a0f219c556df336a',
                'AzureChinaCloud':   'https://waagenttests.vault.azure.cn/secrets/ec-cert/089d16e330dc4ba5b0414c3f8e5f46cb',
                'AzureUSGovernment': 'https://waagenttests.vault.usgovcloudapi.net/secrets/ec-cert/5f19e3b70c6b42dd93e67767a16a75f7'
            },
            'C9CDEECA5D7D1A7EFA0EBD93B745438DB4C01C60': {
                'AzureCloud':        'https://waagenttests.vault.azure.net/secrets/rsa-cert/2cb3997a1d8740618d77b24f85359c5c',
                'AzureChinaCloud':   'https://waagenttests.vault.azure.cn/secrets/rsa-cert/a1a6047c02d84d2da5300fec70b0d070',
                'AzureUSGovernment': 'https://waagenttests.vault.usgovcloudapi.net/secrets/rsa-cert/100dd15190f2485fa200ab948afc1d2e'
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
        self._context.vm.update(osprofile)

        # If the test has already run on the VM, force a new goal state to ensure the certificates are downloaded since the VM model most likely already had the certificates
        # and the update operation would not have triggered a goal state
        if existing_certificates != "":
            log.info("Reapplying the goal state to ensure the test certificates are downloaded.")
            self._context.vm.reapply()

        # If the goal state includes only the certificates, but no extensions, the update/reapply operations may complete before the Agent has downloaded the certificates
        # so we retry for a few minutes to ensure the certificates are downloaded.
        timed_out = datetime.datetime.now(UTC) + datetime.timedelta(minutes=5)
        while True:
            try:
                output = ssh_client.run_command(f"ls {expected_certificates}", use_sudo=True)
                log.info("Found all the expected certificates:\n%s", output)
                break
            except CommandError as error:
                if error.stdout == "":
                    if datetime.datetime.now(UTC) < timed_out:
                        log.info("The certificates have not been downloaded yet, will retry after a short delay.")
                        time.sleep(30)
                        continue
                else:
                    log.info("Found some of the expected certificates:\n%s", error.stdout)
                fail(f"Failed to find certificates\n{error.stderr}")


if __name__ == "__main__":
    KeyvaultCertificates.run_from_command_line()
