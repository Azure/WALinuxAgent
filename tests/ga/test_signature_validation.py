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
from azurelinuxagent.ga.signature_validation_util import validate_signature, SignatureValidationError, validate_handler_manifest_signing_info, \
    ManifestValidationError, _get_openssl_version, openssl_version_supported_for_signature_validation
from azurelinuxagent.ga.exthandlers import HandlerManifest
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.protocol.restapi import Extension
from azurelinuxagent.common.utils.shellutil import CommandError
from azurelinuxagent.common.logger import LogLevel


class TestSignatureValidation(AgentTestCase):
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

    def test_should_validate_signature_successfully(self):
        """
        Test that the signature can be validated successfully without raising an exception.

        Note: The test extension (VMAccess) was signed with a leaf certificate that expires in 2025. Even after the expiry
        date, validation should still succeed because the signature was generated when all certs were unexpired. While we
        could request newly signed versions, leaf certs expire fairly quickly (within a year) and we would
        need to frequently update the test with a new signature and package.
        """
        validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version, failure_log_level=LogLevel.WARNING)

    def test_should_raise_error_if_signature_does_not_match_package(self):
        # This signature is correctly formatted but belongs to a different extension (CSE),
        # signature validation should fail for VMAccess
        with open(os.path.join(data_dir, "signing/invalid_signature.txt"), 'r') as f:
            invalid_signature = f.read()
            with self.assertRaises(SignatureValidationError, msg="Signature is invalid, should have raised error"):
                validate_signature(self.vm_access_zip_path, invalid_signature, self.package_name_and_version, failure_log_level=LogLevel.WARNING)

    def test_should_raise_error_if_package_is_tampered_with(self):
        # This is the VMAccess test extension zip package with one byte modified, signature validation should fail
        modified_ext = os.path.join(data_dir, "signing/Modified_Microsoft.OSTCExtensions.Edp.VMAccessForLinux__1.7.0.zip")
        with self.assertRaises(SignatureValidationError, msg="Zip package does not match signature, should have raised error"):
            validate_signature(modified_ext, self.vm_access_signature, self.package_name_and_version, failure_log_level=LogLevel.WARNING)

    def test_should_raise_error_on_incorrect_signing_certificate(self):
        # The root certificate used here is valid (unexpired) and issued by the Microsoft CA, but it does not match the
        # one that signed the package - signature validation should fail.
        incorrect_root_cert_path = os.path.join(data_dir, "signing/incorrect_microsoft_root_cert.pem")
        with patch("azurelinuxagent.ga.signature_validation_util.get_microsoft_signing_certificate_path", return_value=incorrect_root_cert_path):
            with self.assertRaises(SignatureValidationError, msg="Signing certificate does not match, should have raised error") as ex:
                validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version, failure_log_level=LogLevel.WARNING)
            expected_error_regex = r"Verify\s*error\s*:\s*unable\s*to\s*get\s*local\s*issuer\s*certificate"
            self.assertRegex(ex.exception.args[0], expected_error_regex, msg="Raised SignatureValidationError but error did not indicate certificate failure")

    def test_should_raise_error_on_missing_signing_certificate(self):
        root_cert_path = os.path.join(self.tmp_dir, "missing_root_cert.pem")
        with patch("azurelinuxagent.ga.signature_validation_util.get_microsoft_signing_certificate_path", return_value=root_cert_path):
            with self.assertRaises(SignatureValidationError, msg="Signing certificate missing, should have raised error") as ex:
                validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version, failure_log_level=LogLevel.WARNING)
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

    def test_should_get_openssl_version(self):
        # Tests cases in format (<'openssl version' output>, <expected version string>)
        test_cases = [
            ("OpenSSL version: OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)", "3.0.13"),
            ("OpenSSL version: OpenSSL 1.1.1f  31 Mar 2020", "1.1.1"),
            ("OpenSSL version: OpenSSL 1.0.2zi-fips  1 Aug 2023", "1.0.2"),
            ("OpenSSL 1.1.1  1 Aug 2023", "1.1.1")
        ]
        for case in test_cases:
            with patch("azurelinuxagent.ga.signature_validation_util.run_command", return_value=case[0]):
                version = _get_openssl_version()
                self.assertEqual(version, case[1], "Returned incorrect openssl version")

    def test_should_not_support_signature_validation_if_fail_to_get_openssl_version(self):
        with patch("azurelinuxagent.ga.signature_validation_util.run_command", side_effect=CommandError("cmd", 1, "", "error")):
            self.assertFalse(openssl_version_supported_for_signature_validation())

        with patch("azurelinuxagent.ga.signature_validation_util.run_command", return_value=None):
            self.assertFalse(openssl_version_supported_for_signature_validation())

        with patch("azurelinuxagent.ga.signature_validation_util.run_command", return_value="some junk output"):
            self.assertFalse(openssl_version_supported_for_signature_validation())

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


class TestHandlerManifestValidation(AgentTestCase):

    def test_should_validate_manifest_successfully(self):

        data = {
            "handlerManifest": {},
            "signingInfo": {
                "type": "CustomScript",
                "publisher": "Microsoft.Azure.Extensions",
                "version": "2.1.13"
            }
        }

        ext_name = "Microsoft.Azure.Extensions.CustomScript"
        ext_version = "2.1.13"
        ext_signature = "nonemptysignature"
        manifest = HandlerManifest(data)
        ext_handler = Extension(name=ext_name)
        ext_handler.version = ext_version
        ext_handler.signature = ext_signature

        validate_handler_manifest_signing_info(manifest, ext_handler, failure_log_level=LogLevel.WARNING)

    def test_should_validate_manifest_successfully_for_case_mismatch(self):
        # Manifest validation should be case-insensitive for type and publisher.
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "type": "CustomScript",
                "publisher": "Microsoft.Azure.Extensions",
                "version": "2.1.13"
            }
        }

        ext_name = "microsoft.azure.extensions.customscript"    # Does not match case of handler manifest
        ext_version = "2.1.13"
        ext_signature = "nonemptysignature"
        manifest = HandlerManifest(data)
        ext_handler = Extension(name=ext_name)
        ext_handler.version = ext_version
        ext_handler.signature = ext_signature

        validate_handler_manifest_signing_info(manifest, ext_handler, failure_log_level=LogLevel.WARNING)

    def test_should_raise_error_if_manifest_type_does_not_match(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "type": "CustomScript",
                "publisher": "Microsoft.Azure.Extensions",
                "version": "2.1.13"
            }
        }

        ext_name = "Microsoft.Azure.Extensions.RunCommand"
        ext_version = "2.1.13"
        ext_signature = "nonemptysignature"
        manifest = HandlerManifest(data)
        ext_handler = Extension(name=ext_name)
        ext_handler.version = ext_version
        ext_handler.signature = ext_signature

        with self.assertRaises(ManifestValidationError, msg="HandlerManifest type does not match extension type, should have raised error") as ex:
            validate_handler_manifest_signing_info(manifest, ext_handler, failure_log_level=LogLevel.WARNING)
        expected_error_msg = "expected extension type 'RunCommand' does not match downloaded package type 'CustomScript'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                          msg="Raised ManifestValidationError but error did not indicate type mismatch")

    def test_should_raise_error_if_manifest_publisher_does_not_match(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "type": "CustomScript",
                "publisher": "Microsoft.Azure.Extensions",
                "version": "2.1.13"
            }
        }

        ext_name = "Microsoft.CPlat.Core.CustomScript"
        ext_version = "2.1.13"
        ext_signature = "nonemptysignature"
        manifest = HandlerManifest(data)
        ext_handler = Extension(name=ext_name)
        ext_handler.version = ext_version
        ext_handler.signature = ext_signature

        with self.assertRaises(ManifestValidationError, msg="HandlerManifest publisher does not match extension publisher, should have raised error") as ex:
            validate_handler_manifest_signing_info(manifest, ext_handler, failure_log_level=LogLevel.WARNING)
        expected_error_msg = "expected extension publisher 'Microsoft.CPlat.Core' does not match downloaded package publisher 'Microsoft.Azure.Extensions'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                          msg="Raised ManifestValidationError but error did not indicate publisher mismatch")

    def test_should_raise_error_if_manifest_version_does_not_match(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "type": "CustomScript",
                "publisher": "Microsoft.Azure.Extensions",
                "version": "2.1.13"
            }
        }

        ext_name = "Microsoft.Azure.Extensions.CustomScript"
        ext_version = "2.2.0"
        ext_signature = "nonemptysignature"
        manifest = HandlerManifest(data)
        ext_handler = Extension(name=ext_name)
        ext_handler.version = ext_version
        ext_handler.signature = ext_signature

        with self.assertRaises(ManifestValidationError, msg="HandlerManifest version does not match extension version, should have raised error") as ex:
            validate_handler_manifest_signing_info(manifest, ext_handler, failure_log_level=LogLevel.WARNING)
        expected_error_msg = "expected extension version '2.2.0' does not match downloaded package version '2.1.13'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                          msg="Raised ManifestValidationError but error did not indicate version mismatch")

    def test_should_raise_error_if_manifest_does_not_contain_signing_info(self):
        data = {
            "handlerManifest": {}
        }

        ext_name = "Microsoft.Azure.Extensions.CustomScript"
        ext_version = "2.1.13"
        ext_signature = "nonemptysignature"
        manifest = HandlerManifest(data)
        ext_handler = Extension(name=ext_name)
        ext_handler.version = ext_version
        ext_handler.signature = ext_signature

        with self.assertRaises(ManifestValidationError, msg="HandlerManifest does not contain signingInfo, should have raised error") as ex:
            validate_handler_manifest_signing_info(manifest, ext_handler, failure_log_level=LogLevel.WARNING)
        expected_error_msg = "HandlerManifest.json does not contain 'signingInfo'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                          msg="Raised ManifestValidationError but error did not indicate missing signingInfo")

    def test_should_raise_error_if_manifest_does_not_contain_signing_info_type(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "publisher": "Microsoft.Azure.Extensions",
                "version": "2.1.13"
            }
        }

        ext_name = "Microsoft.Azure.Extensions.CustomScript"
        ext_version = "2.1.13"
        ext_signature = "nonemptysignature"
        manifest = HandlerManifest(data)
        ext_handler = Extension(name=ext_name)
        ext_handler.version = ext_version
        ext_handler.signature = ext_signature

        with self.assertRaises(ManifestValidationError, msg="HandlerManifest does not contain signingInfo.type, should have raised error") as ex:
            validate_handler_manifest_signing_info(manifest, ext_handler, failure_log_level=LogLevel.WARNING)
        expected_error_msg = "HandlerManifest.json does not contain attribute 'signingInfo.type'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                          msg="Raised ManifestValidationError but error did not indicate missing signingInfo.type")

    def test_should_raise_error_if_manifest_does_not_contain_signing_info_publisher(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "type": "CustomScript",
                "version": "2.1.13"
            }
        }

        ext_name = "Microsoft.Azure.Extensions.CustomScript"
        ext_version = "2.1.13"
        ext_signature = "nonemptysignature"
        manifest = HandlerManifest(data)
        ext_handler = Extension(name=ext_name)
        ext_handler.version = ext_version
        ext_handler.signature = ext_signature

        with self.assertRaises(ManifestValidationError, msg="HandlerManifest does not contain signingInfo.publisher, should have raised error") as ex:
            validate_handler_manifest_signing_info(manifest, ext_handler, failure_log_level=LogLevel.WARNING)
        expected_error_msg = "HandlerManifest.json does not contain attribute 'signingInfo.publisher'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                          msg="Raised ManifestValidationError but error did not indicate missing signingInfo.publisher")

    def test_should_raise_error_if_manifest_does_not_contain_signing_info_version(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "type": "CustomScript",
                "publisher": "Microsoft.Azure.Extensions"
            }
        }

        ext_name = "Microsoft.Azure.Extensions.CustomScript"
        ext_version = "2.1.13"
        ext_signature = "nonemptysignature"
        manifest = HandlerManifest(data)
        ext_handler = Extension(name=ext_name)
        ext_handler.version = ext_version
        ext_handler.signature = ext_signature

        with self.assertRaises(ManifestValidationError, msg="HandlerManifest does not contain signingInfo.version, should have raised error") as ex:
            validate_handler_manifest_signing_info(manifest, ext_handler, failure_log_level=LogLevel.WARNING)
        expected_error_msg = "HandlerManifest.json does not contain attribute 'signingInfo.version'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                          msg="Raised ManifestValidationError but error did not indicate missing signingInfo.version")

