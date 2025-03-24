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
import re

from tests.lib.tools import AgentTestCase, data_dir, patch
from azurelinuxagent.ga.signing_certificates import write_signing_certificates
from azurelinuxagent.ga.signature_validation import validate_signature, SignatureValidationError


class TestSignatureValidation(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        write_signing_certificates()
        self.null_ext_zip_path = os.path.join(data_dir, "signing/NullExtension.zip")
        null_ext_sig_path = os.path.join(data_dir, "signing/NullExtensionSignature.txt")
        with open(null_ext_sig_path, 'r') as f:
            self.null_ext_signature = f.read()

    def tearDown(self):
        patch.stopall()
        AgentTestCase.tearDown(self)

    def test_should_validate_signature_successfully(self):
        # Test that signature can be validated with no exception thrown
        validate_signature(self.null_ext_zip_path, self.null_ext_signature)

    def test_should_raise_error_if_signature_is_invalid(self):
        # This signature is correctly formatted but belongs to a different extension (CSE),
        # signature validation should fail for null extension
        with open(os.path.join(data_dir, "signing/invalid_signature.txt"), 'r') as f:
            invalid_signature = f.read()
            with self.assertRaises(SignatureValidationError):
                validate_signature(self.null_ext_zip_path, invalid_signature)

    def test_should_raise_error_if_package_is_invalid(self):
        # This is the null extension zip package with one byte modified, signature validation should fail
        modified_ext = os.path.join(data_dir, "signing/NullExtensionModified.zip")
        with self.assertRaises(SignatureValidationError):
            validate_signature(modified_ext, self.null_ext_signature)

    def test_should_raise_error_on_expired_signing_certificate(self):
        # This is a valid but expired Microsoft root certificate - signature validation should fail
        expired_root_cert_path = os.path.join(data_dir, "signing/expired_root_cert.pem")
        with patch("azurelinuxagent.ga.signature_validation.get_microsoft_signing_certificate_path", return_value=expired_root_cert_path):
            expected_error_msg = "Verify error:unable to get local issuer certificate"
            with self.assertRaisesRegex(SignatureValidationError, expected_error_msg, msg="Should have raised SignatureValidationError indicating that local issuer certificate could not be verified"):
                validate_signature(self.null_ext_zip_path, self.null_ext_signature)

    def test_should_raise_error_on_incorrect_signing_certificate(self):
        # This certificate is valid (not expired) but does not match the one used for signing - signature validation should fail
        incorrect_root_cert_path = os.path.join(data_dir, "signing/incorrect_root_cert.pem")
        with patch("azurelinuxagent.ga.signature_validation.get_microsoft_signing_certificate_path", return_value=incorrect_root_cert_path):
            expected_error_msg = "Verify error:unable to get local issuer certificate"
            with self.assertRaisesRegex(SignatureValidationError, expected_error_msg, msg="Should have raised SignatureValidationError indicating that local issuer certificate could not be verified"):
                validate_signature(self.null_ext_zip_path, self.null_ext_signature)

    def test_should_raise_error_on_missing_signing_certificate(self):
        root_cert_path = os.path.join(self.tmp_dir, "missing_root_cert.pem")
        if os.path.exists(root_cert_path):
            os.remove(root_cert_path)

        with patch("azurelinuxagent.ga.signature_validation.get_microsoft_signing_certificate_path", return_value=root_cert_path):
            expected_error_regex = r'Error loading file.*' + re.escape(root_cert_path) + r'.*No such file or directory'
            with self.assertRaisesRegex(expected_exception=SignatureValidationError,
                                        expected_regex=expected_error_regex,
                                        msg="Should have raised SignatureValidationError indicating that certificate could not be found"):
                validate_signature(self.null_ext_zip_path, self.null_ext_signature)

