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
import sys

from tests.lib.tools import AgentTestCase, data_dir, patch, skip_if_predicate_true
from azurelinuxagent.ga.signing_certificate_util import write_signing_certificates
from azurelinuxagent.ga.signature_validation import validate_signature, SignatureValidationError
from azurelinuxagent.common.event import WALAEventOperation


class TestSignatureValidation(AgentTestCase):
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

    def test_should_validate_signature_successfully(self):
        """
        Test that the signature can be validated successfully without raising an exception.

        Note: The test extension was signed with an expired leaf certificate (expired 2024), but it
        should still validate successfully because the signature was generated when all certs were unexpired.
        Currently, we do not have a version of NullExtension signed with an unexpired cert. While we could request a
        newly signed version, leaf certs expire fairly quickly (within a year) and we would need to frequently update
        the test with a new signature and package.
        """
        validate_signature(self.null_ext_zip_path, self.null_ext_signature)

    def test_should_raise_error_if_signature_does_not_match_package(self):
        # This signature is correctly formatted but belongs to a different extension (CSE),
        # signature validation should fail for null extension
        with open(os.path.join(data_dir, "signing/invalid_signature.txt"), 'r') as f:
            invalid_signature = f.read()
            with self.assertRaises(SignatureValidationError, msg="Signature is invalid, should have raised error"):
                validate_signature(self.null_ext_zip_path, invalid_signature)

    def test_should_raise_error_if_package_is_tampered_with(self):
        # This is the null extension zip package with one byte modified, signature validation should fail
        modified_ext = os.path.join(data_dir, "signing/null_extension_modified.zip")
        with self.assertRaises(SignatureValidationError, msg="Zip package does not match signature, should have raised error"):
            validate_signature(modified_ext, self.null_ext_signature)

    def test_should_raise_error_on_incorrect_signing_certificate(self):
        # The root certificate used here is valid (unexpired) and issued by the Microsoft CA, but it does not match the
        # one that signed the package - signature validation should fail.
        incorrect_root_cert_path = os.path.join(data_dir, "signing/incorrect_microsoft_root_cert.pem")
        with patch("azurelinuxagent.ga.signature_validation.get_microsoft_signing_certificate_path", return_value=incorrect_root_cert_path):
            with self.assertRaises(SignatureValidationError, msg="Signing certificate does not match, should have raised error") as ex:
                validate_signature(self.null_ext_zip_path, self.null_ext_signature)
            expected_error_regex = r"Verify\s*error\s*:\s*unable\s*to\s*get\s*local\s*issuer\s*certificate"
            self.assertRegex(ex.exception.args[0], expected_error_regex, msg="Raised SignatureValidationError but error did not indicate certificate failure")

    def test_should_raise_error_on_missing_signing_certificate(self):
        root_cert_path = os.path.join(self.tmp_dir, "missing_root_cert.pem")
        with patch("azurelinuxagent.ga.signature_validation.get_microsoft_signing_certificate_path", return_value=root_cert_path):
            with self.assertRaises(SignatureValidationError, msg="Signing certificate missing, should have raised error") as ex:
                validate_signature(self.null_ext_zip_path, self.null_ext_signature)
            self.assertIn("signing certificate was not found", ex.exception.args[0], msg="Error message did not indicate that certificate is missing.")

    def test_should_handle_and_report_error_raised_when_writing_signing_certificate(self):
        # If an error is raised when writing signing certificates, the error should be handled/swallowed but reported
        # via telemetry and log.
        with patch('azurelinuxagent.ga.signing_certificate_util.event.error') as report_err:
            open_target = "builtins.open" if sys.version_info[0] >= 3 else "__builtin__.open"
            with patch(open_target, side_effect=OSError):
                write_signing_certificates()
                signing_errors = [kw for _, kw in report_err.call_args_list if kw['op'] == WALAEventOperation.SignatureValidation]
                self.assertEqual(1, len(signing_errors), "Error writing signing certificates not logged or sent as telemetry")

    @skip_if_predicate_true(lambda: True, "Enable this test when timestamp validation has been implemented.")
    def test_should_raise_error_if_root_cert_was_expired_at_signing_time(self):
        # TODO: Test is skipped because it requires timestamp validation implementation. Write this test after
        # timestamp validation has been implemented.
        self.fail()

    @skip_if_predicate_true(lambda: True, "Enable this test when timestamp validation has been implemented.")
    def test_should_raise_error_if_intermediate_cert_was_expired_at_signing_time(self):
        # TODO: Test is skipped because it requires timestamp validation implementation. Write this test after
        # timestamp validation has been implemented.
        self.fail()

    @skip_if_predicate_true(lambda: True, "Enable this test when timestamp validation has been implemented.")
    def test_should_raise_error_if_leaf_cert_was_expired_at_signing_time(self):
        # TODO: Test is skipped because it requires timestamp validation implementation. Write this test after
        # timestamp validation has been implemented.
        self.fail()
