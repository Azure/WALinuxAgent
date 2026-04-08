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
import contextlib
import os
import re

from tests.lib.tools import AgentTestCase, data_dir, patch, i_am_root, MagicMock
from azurelinuxagent.ga.signing_certificate_util import write_signing_certificates
from azurelinuxagent.ga.signature_validation_util import validate_signature, SignatureValidationError
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.ga.cgroupconfigurator import EXT_SIGNATURE_VALIDATION_CGROUPS_UNIT_NAME
from azurelinuxagent.common.future import ustr


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

        # Regex for 'openssl cms -verify' for the test zip package
        self.openssl_cmd_pattern = re.compile(r".*openssl\s+cms\s+-verify.*-content\s+{0}\b".format(re.escape(self.vm_access_zip_path)))

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


    @contextlib.contextmanager
    def _create_cgroupconfigurator_mock(self, cgroups_enabled):
        with patch("azurelinuxagent.ga.signature_validation_util.CGroupConfigurator.get_instance") as mock_get_instance:
            mock_cgroups_api = MagicMock()
            mock_cgroups_api.get_accounting_properties.return_value = ((), ())
            mock_instance = MagicMock()
            mock_instance.get_cgroups_api.return_value = mock_cgroups_api
            mock_instance.enabled.return_value = cgroups_enabled
            mock_instance.disable = MagicMock()
            mock_get_instance.return_value = mock_instance
            yield mock_instance

    def test_validate_signature_should_use_systemd_run(self):
        self.assertTrue(i_am_root(), "Test does not run when non-root")
        with self._create_cgroupconfigurator_mock(cgroups_enabled=True):
            original_run_command = shellutil.run_command
            run_command_calls = []

            def mock_run_command(command, *args, **kwargs):
                run_command_calls.append(' '.join(command))
                return original_run_command(command, *args, **kwargs)

            with patch("azurelinuxagent.ga.signature_validation_util.run_command", side_effect=mock_run_command):
                validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)

            # Check if 'openssl cms -verify' was called with systemd-run for the specified extension
            systemd_run_called = any(
                cmd.startswith('systemd-run') and self.openssl_cmd_pattern.search(cmd)
                for cmd in run_command_calls
            )
            self.assertTrue(
                systemd_run_called,
                "Expected 'validate_signature' to run using 'systemd-run'. "
                "Commands called:\n{0}".format("\n".join(run_command_calls))
            )

    def test_validate_signature_should_not_use_systemd_run_when_cgroups_disabled(self):
        with self._create_cgroupconfigurator_mock(cgroups_enabled=False):
            original_run_command = shellutil.run_command
            run_command_calls = []

            def mock_run_command(command, *args, **kwargs):
                run_command_calls.append(' '.join(command))
                return original_run_command(command, *args, **kwargs)

            with patch("azurelinuxagent.ga.signature_validation_util.run_command", side_effect=mock_run_command):
                validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)

            # Find all openssl cms -verify calls
            openssl_calls = [cmd for cmd in run_command_calls if self.openssl_cmd_pattern.search(cmd)]

            self.assertEqual(1, len(openssl_calls), msg="Openssl cms -verify command should have been called exactly once")
            self.assertFalse(openssl_calls[0].startswith('systemd-run'),
                           msg="Openssl cms -verify command should not have been called with systemd-run when cgroups disabled")

    def test_validate_signature_should_raise_error_on_openssl_failure(self):
        with self._create_cgroupconfigurator_mock(cgroups_enabled=True):
            original_run_command = shellutil.run_command

            def mock_run_command(command, *args, **kwargs):
                cmd = ' '.join(command)
                if self.openssl_cmd_pattern.search(cmd):
                    error_msg = 'Running as unit: {0}\nVerification failure'.format(EXT_SIGNATURE_VALIDATION_CGROUPS_UNIT_NAME)
                    raise shellutil.CommandError(command=cmd, return_code=1, stdout="", stderr=error_msg)
                return original_run_command(command, *args, **kwargs)

            with patch("azurelinuxagent.ga.signature_validation_util.run_command", side_effect=mock_run_command):
                with self.assertRaises(SignatureValidationError, msg="Expected signature validation to raise due to OpenSSL error"):
                    validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)

    def test_validate_signature_should_retry_on_systemd_error(self):
        with self._create_cgroupconfigurator_mock(cgroups_enabled=True) as mock_cgroup:
            original_run_command = shellutil.run_command
            run_command_calls = []

            def mock_run_command(command, *args, **kwargs):
                cmd = ' '.join(command)
                run_command_calls.append(cmd)
                if cmd.startswith('systemd-run'):
                    error_msg = 'Unit {0} not found.'.format(EXT_SIGNATURE_VALIDATION_CGROUPS_UNIT_NAME)
                    raise shellutil.CommandError(command=cmd, return_code=1, stdout=ustr(""), stderr=ustr(error_msg))
                return original_run_command(command, *args, **kwargs)

            with patch("azurelinuxagent.ga.signature_validation_util.run_command", side_effect=mock_run_command):
                validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)

            # Find all openssl cms -verify calls
            openssl_calls = [cmd for cmd in run_command_calls if self.openssl_cmd_pattern.search(cmd)]

            self.assertEqual(2, len(openssl_calls), msg="Expected exactly 2 openssl calls (first with systemd-run, second direct)")

            # First openssl cms verify call should use systemd-run
            self.assertTrue(openssl_calls[0].startswith('systemd-run'), msg="First openssl call should have used systemd-run, got: {0}".format(openssl_calls[0]))

            # Second openssl cms verify call should be direct (not using systemd-run)
            self.assertFalse(openssl_calls[1].startswith('systemd-run'),
                           msg="Second openssl call should be direct (without systemd-run), got: {0}".format(openssl_calls[1]))

            # Verify that cgroups were disabled
            self.assertEqual(1, mock_cgroup.disable.call_count, "disable() should have been called exactly once")
            reason = mock_cgroup.disable.call_args[1]['reason']
            self.assertTrue(reason.startswith("'systemd-run' invocation failed for signature validation"),
                            msg="Expected cgroup disable reason to indicate systemd-run error during signature validation")
