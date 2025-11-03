# Windows Azure Linux Agent
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
# Requires Python 2.6+ and Openssl 1.0+
#
import os
import contextlib

from tests.lib.tools import AgentTestCase, data_dir, patch, i_am_root
from azurelinuxagent.ga.signing_certificate_util import write_signing_certificates
from azurelinuxagent.ga.signature_validation_util import validate_signature
from azurelinuxagent.common.utils import shellutil


class TestSignatureValidationSudo(AgentTestCase):
    """
    Tests signature validation scenarios involving certificate expiry, simulated by moving the system clock forward.
    Since modifying system time requires admin privileges, tests in this suite must be run with sudo.
    """
    def setUp(self):
        AgentTestCase.setUp(self)
        write_signing_certificates()
        self.vm_access_zip_path = os.path.join(data_dir, "signing/Microsoft.OSTCExtensions.Edp.VMAccessForLinux__1.7.0.zip")
        vm_access_signature_path = os.path.join(data_dir, "signing/vm_access_signature.txt")
        with open(vm_access_signature_path, 'r') as f:
            self.vm_access_signature = f.read()
        self.package_name_and_version = "Microsoft.OSTCExtensions.Edp.VMAccessForLinux-1.5.0"

    def tearDown(self):
        patch.stopall()
        AgentTestCase.tearDown(self)

    @staticmethod
    @contextlib.contextmanager
    def create_mock_run_command():
        calls = []

        original_run_command = shellutil.run_command

        def run_command_mock(cmd, *args, **kwargs):
            calls.append((cmd, args, kwargs))
            return original_run_command(cmd, *args, **kwargs)

        with patch("azurelinuxagent.ga.signature_validation_util.run_command", side_effect=run_command_mock):
            yield calls

    @staticmethod
    def _validate_signature_in_another_year(target_year, package_path, signature, package_name_and_version):
        original_system_year = None
        try:
            original_system_year = shellutil.run_command(["date", "+%Y"]).strip()
            delta = target_year - int(original_system_year)
            if delta > 0:
                shellutil.run_command(["sudo", "date", "-s", "{0} years".format(delta)])
            validate_signature(package_path, signature, package_name_and_version)
        except shellutil.CommandError as ex:
            raise Exception("Failed to retrieve or update system time.\nExit code: {0}\nError details: {1}".format(ex.returncode, ex.stderr))
        finally:
            if original_system_year is not None:
                current_system_year = shellutil.run_command(["date", "+%Y"]).strip()
                if current_system_year != original_system_year:
                    delta = int(current_system_year) - int(original_system_year)
                    shellutil.run_command(["sudo", "date", "-s", "-{0} years".format(delta)])

    def test_should_validate_signature_for_package_signed_with_expired_root_cert(self):
        # Root certificate expires in 2036. This test changes system time to 2037 to simulate root cert expiry.
        # Signature validation should still pass, because the signature was generated when the root certificate was unexpired.
        self.assertTrue(i_am_root(), "Test does not run when non-root")
        TestSignatureValidationSudo._validate_signature_in_another_year(2037, self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)

    def test_should_validate_signature_for_package_signed_with_expired_intermediate_cert(self):
        # Root certificate expires in 2036. This test changes system time to 2037 to simulate root cert expiry.
        # Signature validation should still pass, because the signature was generated when the root certificate was unexpired.
        self.assertTrue(i_am_root(), "Test does not run when non-root")
        TestSignatureValidationSudo._validate_signature_in_another_year(2027, self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)

    def test_should_validate_signature_for_package_signed_with_leaf_root_cert(self):
        # Leaf certificate expires in September 2025. This test changes system time to 2026 to simulate root cert expiry.
        # Signature validation should still pass, because the signature was generated when the root certificate was unexpired.
        self.assertTrue(i_am_root(), "Test does not run when non-root")
        TestSignatureValidationSudo._validate_signature_in_another_year(2026, self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)

    def test_validate_signature_should_use_systemd_run(self):
        with patch("azurelinuxagent.ga.signature_validation_util.CGroupConfigurator.get_instance") as mock_get_instance:
            mock_instance = mock_get_instance.return_value
            mock_instance.enabled.return_value = True
            with self.create_mock_run_command() as run_command_calls:
                validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)

            # Check if 'openssl cms -verify' was called with systemd-run
            systemd_run_called = any(
                all(s in " ".join(cmd) for s in ["systemd-run", "openssl", "cms", "-verify"])
                for cmd, _, _ in run_command_calls
            )

            self.assertTrue(
                systemd_run_called,
                "Expected 'validate_signature' to run using 'systemd-run'. "
                "Commands called:\n{0}".format("\n".join(str(cmd) for cmd, _, _ in run_command_calls))
            )