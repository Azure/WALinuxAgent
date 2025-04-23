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

from tests.lib.tools import AgentTestCase, data_dir, patch, i_am_root
from azurelinuxagent.ga.signing_certificate_util import write_signing_certificates
from azurelinuxagent.ga.signature_validation import validate_signature
from azurelinuxagent.common.utils import shellutil


class TestSignatureValidationSudo(AgentTestCase):
    """
    Tests signature validation scenarios involving certificate expiry, simulated by moving the system clock forward.
    Since modifying system time requires admin privileges, tests in this suite must be run with sudo.
    """
    def setUp(self):
        AgentTestCase.setUp(self)
        write_signing_certificates()
        self.null_ext_zip_path = os.path.join(data_dir, "signing/null_extension.zip")
        null_ext_sig_path = os.path.join(data_dir, "signing/null_extension_signature.txt")
        with open(null_ext_sig_path, 'r') as f:
            self.null_ext_signature = f.read()

    def tearDown(self):
        patch.stopall()
        AgentTestCase.tearDown(self)

    @staticmethod
    def _validate_signature_in_another_year(target_year, package_path, signature):
        original_system_year = None
        try:
            original_system_year = shellutil.run_command(["date", "+%Y"]).strip()
            delta = target_year - int(original_system_year)
            if delta > 0:
                shellutil.run_command(["sudo", "date", "-s", "{0} years".format(delta)])
            validate_signature(package_path, signature)
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
        TestSignatureValidationSudo._validate_signature_in_another_year(2037, self.null_ext_zip_path, self.null_ext_signature)

    def test_should_validate_signature_for_package_signed_with_expired_intermediate_cert(self):
        # Root certificate expires in 2036. This test changes system time to 2037 to simulate root cert expiry.
        # Signature validation should still pass, because the signature was generated when the root certificate was unexpired.
        self.assertTrue(i_am_root(), "Test does not run when non-root")
        TestSignatureValidationSudo._validate_signature_in_another_year(2027, self.null_ext_zip_path, self.null_ext_signature)

