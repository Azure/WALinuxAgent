#!/usr/bin/env python3
#
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
import json
import random
import requests
import uuid

from typing import Any, Dict, List

from tests_e2e.tests.lib.agent_test import AgentVmTest, AgentTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds


class Fips(AgentVmTest):
    def __init__(self, context: AgentTestContext) -> None:
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()
        self._distro = None  # initialized on run()

    def run(self):
        self._distro = self._ssh_client.run_command("get_distro.py").rstrip()

        log.info("Executing test on %s [%s] - IP address: %s", self._context.vm, self._distro, self._context.ip_address)
        log.info("")

        self._opt_in_to_fips()
        log.info("")

        if self._distro.startswith("ubuntu_22"):
            self._enable_fips_on_ubuntu_22()
        elif self._distro.startswith("rhel_9"):
            self._enable_fips_on_rhel_9()
        else:
            raise Exception(f'Unsupported distro: {self._distro}')
        log.info("")

        #
        # Delete any certificates and keys that have been downloaded so far, since we do not want extensions to pick up any leftover files that may have been
        # created before enabling FIPS. Then, force the creation of a new PFX package.
        #
        # Since the VM is now opted-in to FIPS 140-3, CRP will encrypt protected settings and Fabric will produce a PFX using algorithms compliant with 140-3.
        # Note that these operations can change the public IP address of the VM, so we need to refresh it.
        #
        log.info("Deleting all certificates and keys in /var/lib/waagent...")
        self._ssh_client.run_command("find /var/lib/waagent -name '*.crt' -o -name '*.prv' -delete", use_sudo=True).rstrip()
        self._force_new_pfx()
        log.info("")

        #
        # Execute an extension with protected settings to ensure the tenant certificate can be decrypted under FIPS
        #
        custom_script = VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript, resource_name="CustomScript")
        log.info("Executing %s using protected settings to verify they can be decrypted when FIPS 140-3 is enabled.", custom_script)
        message = f"Hello {uuid.uuid4()}!"
        custom_script.enable(
            settings={},
            protected_settings={
                'commandToExecute': f"echo \'{message}\'"
            }
        )
        custom_script.assert_instance_view(expected_message=message)
        log.info("%s executed successfully.", custom_script)

    def _opt_in_to_fips(self) -> None:
        #
        # Currently support for FIPS 140-3 is in public preview and VMs need to be explicitly opted-in. Also, the SDK has not been updated
        # with the properties for FIPS 140-3, so we use ARM requests to opt-in.
        #
        # The machine may be opted-in already; we check that first.
        #
        log.info("Verifying whether the VM is opted-in to FIPS 140-3...")
        get_instance_view = self._context.vm.create_resource_manager_request(requests.get, '?$expand=instanceView&api-version=2024-11-01')
        response = get_instance_view()
        if response.status_code != 200:
            raise Exception(f"GET instance view failed (status: {response.status_code}): {response.text}")
        instance_view = response.json()
        try:
            additional_capabilities = instance_view['properties']['additionalCapabilities']
            enable_fips_140_3_encryption = additional_capabilities.get('enableFips1403Encryption')
            if enable_fips_140_3_encryption == True:
                log.info("%s is already opted-in to FIPS 140-3", self._context.vm)
                return
        except KeyError:
            # the VM does not have any additional capabilites; continue with the opt-in
            pass
        log.info("The VM is not opted-in...")

        #
        # Set the enableFips1403Encryption additional capability to opt-in.
        #
        log.info("Opting-in to FIPS 140-3...")
        put_capabilities = self._context.vm.create_resource_manager_request(requests.put, '?api-version=2024-11-01')
        response = put_capabilities(data=json.dumps({
            "location": self._context.vm.location,
            "properties": {
                "additionalCapabilities": {
                    "enableFips1403Encryption": True
                }
            }
        }))
        if response.status_code != 200:
            raise Exception(f"PUT additional capabilities  failed (status: {response.status_code}): {response.text}")
        log.info("Opt-in completed...")

    def _enable_fips_on_ubuntu_22(self) -> None:
        #
        # See https://ubuntu.com/tutorials/using-the-ubuntu-pro-client-to-enable-fips#4-enabling-fips-crypto-modules
        #
        log.info("Enabling FIPS on Ubuntu 22...")

        # Skip this if FIPS is already enabled
        is_enabled_command = "test -f {0} && test $(cat {0}) = 1 && echo yes || true".format("/proc/sys/crypto/fips_enabled")
        enabled = self._ssh_client.run_command(is_enabled_command).rstrip()
        if enabled == "yes":
            log.info("FIPS is already enabled.")
            return

        stdout = self._ssh_client.run_command('pro enable fips-updates --assume-yes', use_sudo=True).rstrip()
        log.info("Enabled FIPS.\n\t%s", stdout.replace('\n', '\n\t'))

        log.info("Restarting VM to activate FIPS...")
        self._context.vm.restart(wait_for_boot=True, ssh_client=self._ssh_client)
        log.info("Restart completed.")

        enabled = self._ssh_client.run_command(is_enabled_command).rstrip()
        if enabled != "yes":
            raise Exception("Failed to enable FIPS on Ubuntu 22; aborting test!!!!")
        log.info("FIPS was enabled successfully.")

    def _enable_fips_on_rhel_9(self) -> None:
        #
        # See https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/switching-rhel-to-fips-mode_security-hardening
        #
        log.info("Enabling FIPS on RHEL 9...")

        # Skip this if FIPS is already enabled
        def is_enabled():
            try:
                self._ssh_client.run_command('fips-mode-setup --is-enabled').rstrip()
            except CommandError as error:
                if error.exit_code == 2:
                    return False
                raise
            return True

        if is_enabled():
            return

        stdout = self._ssh_client.run_command('fips-mode-setup --enable', use_sudo=True).rstrip()
        log.info("Enabled FIPS.\n\t%s", stdout.replace('\n', '\n\t'))

        log.info("Restarting VM to activate FIPS...")
        self._context.vm.restart(wait_for_boot=True, ssh_client=self._ssh_client)
        log.info("Restart completed.")

        if not is_enabled():
            raise Exception("Failed to enable FIPS on Ubuntu; aborting test!!!!")
        log.info("FIPS was enabled successfully.")

    def _force_new_pfx(self):
        #
        # Our documentation recommends 2 alternatives to force a new PFX; use any of them randomly.
        #
        random.seed()

        if random.choice([1, 2]) == 1:
            log.info("Adding a keyvault certificate to the osProfile to force a new PFX...")
            self._context.vm.update({
                "properties": {
                    "osProfile": {
                        "secrets": [
                            {
                                "sourceVault": {
                                    "id": f"/subscriptions/{self._context.vm.subscription}/resourceGroups/waagent-tests/providers/Microsoft.KeyVault/vaults/waagenttests-canary"
                                },
                                "vaultCertificates": [{"certificateUrl": "https://waagenttests-canary.vault.azure.net/secrets/rsa/85d92c80443e44058cb034b2008e1e75"}]
                            }
                        ],
                    }
                }
            })
        else:
            if self._distro == 'rhel_95':
                #
                # TODO: Remove this workaround once the pre-installed Agent RHEL 9.5 is updated to support FIPS 140-3.
                #
                # The current Daemon on RHEL 95 (2.7.0.6) has not been updated to support FIPS 140-3 and goes into an infinite loop while trying to fetch the certificates in the goal
                # state. The reason is that, even if it cannot decrypt the response from the WireServer, 2.7.0.6 assumes that Certificates.pem always exists; if it does not, it goes
                # into an infinite retry loop. To prevent this, before deallocating and reallocating, ensure that there is a Certificates.pem file, even if it is empty.
                #
                # The agent may remove the new file if it fetches the goal state certificate (after the VM restart in the previous step) and fails to decrypt it while we create the file below.
                # Therefore, stop the agent service to prevent it from removing the file.
                output = self._ssh_client.run_command('agent-service stop', use_sudo=True)
                log.info(output)
                pem_file = '/var/lib/waagent/Certificates.pem'
                log.info("Ensuring that %s exists...", pem_file)
                self._ssh_client.run_command(f"touch {pem_file}", use_sudo=True)

            log.info("Deallocating and re-allocating %s to force a new tenant certificate in order to create a new PFX...", self._context.vm)
            log.info("Deallocating %s...", self._context.vm)
            self._context.vm.deallocate()
            log.info("Re-allocating %s...", self._context.vm)
            self._context.vm.start()
            log.info("Refreshing the IP address of %s...", self._context.vm)
            self._context.refresh_ip_addresses()
            self._ssh_client = self._context.create_ssh_client()
            log.info("IP address after re-allocation: %s", self._context.ip_address)

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        ignore_rules = [
            #
            # These warnings/errors are produced by the test, so they are expected
            #
            #	 2025-07-30T02:15:50.523569Z WARNING ExtHandler Error converting PFX to PEM [-nomacver: True]: '/usr/bin/openssl pkcs12 -nodes -password pass: -in /var/lib/waagent/Certificates.pfx -out /var/lib/waagent/Certificates.pem -nomacver' failed: 1 (Error outputting keys and certificates
            #	 805B3ABA317F0000:error:0308010C:digital envelope routines:inner_evp_generic_fetch:unsupported:../crypto/evp/evp_fetch.c:349:Global default library context, Algorithm (PKCS12KDF : 0), Properties (<null>)
            #	 805B3ABA317F0000:error:1180006B:PKCS12 routines:PKCS12_PBE_keyivgen_ex:key gen error:../crypto/pkcs12/p12_crpt.c:55:)
            #
            #	 2025-07-30T02:15:50.693154Z WARNING ExtHandler Error converting PFX to PEM [-nomacver: False]: '/usr/bin/openssl pkcs12 -nodes -password pass: -in /var/lib/waagent/Certificates.pfx -out /var/lib/waagent/Certificates.pem' failed: 1 (Error verifying PKCS12 MAC; no PKCS12KDF support.
            #	 Use -nomacver if MAC verification is not required.)
            #
            #	 2025-07-30T02:15:50.694099Z ERROR ExtHandler Error fetching the goal state certificates: Cannot convert PFX to PEM
            #
            {
                'message': 'Error converting PFX to PEM',
                'if': lambda r: r.level == "WARNING"
            },
            {
                'message': 'Error fetching the goal state certificates: Cannot convert PFX to PEM',
                'if': lambda r: r.level == "ERROR"
            }
        ]
        #
        # The current Daemon on RHEL_95 tries to fetch the certificates during initialization and has not been updated to support FIPS 140-3
        #
        #		2025-07-31T19:06:59.878313Z ERROR Daemon Daemon Failed to decrypt /var/lib/waagent/Certificates.p7m (return code: 1)
        #
        # 		[stdout]
        #
        # 		[stderr]
        # 		Error decrypting CMS structure
        # 		00DED7E6A77F0000:error:0308010C:digital envelope routines:inner_evp_generic_fetch:unsupported:crypto/evp/evp_fetch.c:355:Global default library context, Algorithm (DES-EDE3-CBC : 65), Properties ()
        # 		00DED7E6A77F0000:error:17000065:CMS routines:ossl_cms_EncryptedContent_init_bio:cipher initialisation error:crypto/cms/cms_enc.c:79:
        # 		2025-07-31T19:07:06.309758Z ERROR Daemon Daemon Failed to decrypt /var/lib/waagent/Certificates.p7m (return code: 1)
        # 		[stdout]
        #
        if self._distro == 'rhel_95':
            ignore_rules.append({
                'message': 'Failed to decrypt /var/lib/waagent/Certificates.p7m',
                'if': lambda r: r.prefix == "Daemon"

            })

        return ignore_rules


if __name__ == "__main__":
    Fips.run_from_command_line()

