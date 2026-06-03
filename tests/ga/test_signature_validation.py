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
import datetime
import os
import sys

from tests.lib.tools import AgentTestCase, data_dir, patch, skip_if_predicate_true
from azurelinuxagent.common import conf
from azurelinuxagent.ga.signing_certificate_util import write_signing_certificates
from azurelinuxagent.ga.signature_validation_util import validate_signature, SignatureValidationError, \
    validate_extension_manifest_signing_info, validate_agent_manifest_signing_info, \
    ManifestValidationError, _get_openssl_version, openssl_version_supported_for_signature_validation, \
    ext_signature_validation_enabled, agent_signature_validation_enabled, agent_signature_goal_state_telemetry_enabled, \
    _is_signature_validation_telemetry_expired, _OpenSSLVersionCheck, _ExpiryCheckErrorReporter
from azurelinuxagent.ga.exthandlers import HandlerManifest
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.future import UTC
from azurelinuxagent.common.protocol.restapi import Extension
from azurelinuxagent.common.utils.shellutil import CommandError
from azurelinuxagent.common.version import AGENT_SIGNING_INFO_NAME


class TestSignatureValidation(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        write_signing_certificates()
        self.vm_access_zip_path = os.path.join(data_dir, "signing/Microsoft.OSTCExtensions.Edp.VMAccessForLinux__1.7.0.zip")
        vm_access_signature_path = os.path.join(data_dir, "signing/vm_access_signature.txt")
        with open(vm_access_signature_path, 'r') as f:
            self.vm_access_signature = f.read()
        self.package_name_and_version = "Microsoft.OSTCExtensions.Edp.VMAccessForLinux-1.5.0"
        # Reset cached OpenSSL version check result so each test starts with a clean state.
        _OpenSSLVersionCheck._version_supports_validation = None  # pylint: disable=protected-access
        # Reset the once-per-run guard for the expiry-check error reporter so each test starts with a clean state.
        _ExpiryCheckErrorReporter._reported = False  # pylint: disable=protected-access

    def test_should_validate_signature_successfully(self):
        """
        Test that the signature can be validated successfully without raising an exception.

        Note: The test extension (VMAccess) was signed with a leaf certificate that expires in 2025. Even after the expiry
        date, validation should still succeed because the signature was generated when all certs were unexpired. While we
        could request newly signed versions, leaf certs expire fairly quickly (within a year) and we would
        need to frequently update the test with a new signature and package.
        """
        validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)

    def test_should_raise_error_if_signature_does_not_match_package(self):
        # This signature is correctly formatted but belongs to a different extension (CSE),
        # signature validation should fail for VMAccess
        with open(os.path.join(data_dir, "signing/invalid_signature.txt"), 'r') as f:
            invalid_signature = f.read()
            with self.assertRaises(SignatureValidationError, msg="Signature is invalid, should have raised error"):
                validate_signature(self.vm_access_zip_path, invalid_signature, self.package_name_and_version)

    def test_should_raise_error_if_package_is_tampered_with(self):
        # This is the VMAccess test extension zip package with one byte modified, signature validation should fail
        modified_ext = os.path.join(data_dir, "signing/Modified_Microsoft.OSTCExtensions.Edp.VMAccessForLinux__1.7.0.zip")
        with self.assertRaises(SignatureValidationError, msg="Zip package does not match signature, should have raised error"):
            validate_signature(modified_ext, self.vm_access_signature, self.package_name_and_version)

    def test_should_raise_error_on_incorrect_signing_certificate(self):
        # The root certificate used here is valid (unexpired) and issued by the Microsoft CA, but it does not match the
        # one that signed the package - signature validation should fail.
        incorrect_root_cert_path = os.path.join(data_dir, "signing/incorrect_microsoft_root_cert.pem")
        with patch("azurelinuxagent.ga.signature_validation_util.get_microsoft_signing_certificate_path", return_value=incorrect_root_cert_path):
            with self.assertRaises(SignatureValidationError, msg="Signing certificate does not match, should have raised error") as ex:
                validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)
            expected_error_regex = r"Verify\s*error\s*:\s*unable\s*to\s*get\s*local\s*issuer\s*certificate"
            self.assertRegex(ex.exception.args[0], expected_error_regex, msg="Raised SignatureValidationError but error did not indicate certificate failure")

    def test_should_raise_error_on_missing_signing_certificate(self):
        root_cert_path = os.path.join(self.tmp_dir, "missing_root_cert.pem")
        with patch("azurelinuxagent.ga.signature_validation_util.get_microsoft_signing_certificate_path", return_value=root_cert_path):
            with self.assertRaises(SignatureValidationError, msg="Signing certificate missing, should have raised error") as ex:
                validate_signature(self.vm_access_zip_path, self.vm_access_signature, self.package_name_and_version)
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
        # The result of openssl_version_supported_for_signature_validation() is cached per agent execution,
        # so reset the cache between sub-cases to ensure each patched run_command is actually exercised.
        with patch("azurelinuxagent.ga.signature_validation_util.run_command", side_effect=CommandError("cmd", 1, "", "error")):
            self.assertFalse(openssl_version_supported_for_signature_validation())

        _OpenSSLVersionCheck._version_supports_validation = None  # pylint: disable=protected-access
        with patch("azurelinuxagent.ga.signature_validation_util.run_command", return_value=None):
            self.assertFalse(openssl_version_supported_for_signature_validation())

        _OpenSSLVersionCheck._version_supports_validation = None  # pylint: disable=protected-access
        with patch("azurelinuxagent.ga.signature_validation_util.run_command", return_value="some junk output"):
            self.assertFalse(openssl_version_supported_for_signature_validation())

    def test_should_cache_result_of_openssl_version_check_when_version_not_supported(self):
        # First call should invoke run_command and produce a log + telemetry event. Subsequent calls should return the
        # cached result without invoking run_command again, and without producing additional logs or telemetry.
        unsupported_output = "OpenSSL 1.0.2  1 Aug 2023"
        with patch("azurelinuxagent.ga.signature_validation_util.run_command", return_value=unsupported_output) as mock_run:
            with patch("azurelinuxagent.ga.signature_validation_util.logger.info") as mock_info:
                with patch("azurelinuxagent.ga.signature_validation_util.add_event") as mock_add_event:
                    for _ in range(5):
                        self.assertFalse(openssl_version_supported_for_signature_validation(),
                                         "Expected unsupported OpenSSL version to return False")
                    self.assertEqual(1, mock_run.call_count,
                                     "Expected run_command to be invoked exactly once across 5 calls (result should be cached)")
                    sig_val_events = [kw for _, kw in mock_add_event.call_args_list
                                      if kw.get('op') == WALAEventOperation.SignatureValidation]
                    self.assertEqual(1, len(sig_val_events),
                                     "Expected exactly one SignatureValidation telemetry event for unsupported OpenSSL version")
                    unsupported_logs = [args for args, _ in mock_info.call_args_list
                                        if args and "Signature validation requires OpenSSL" in args[0]]
                    self.assertEqual(1, len(unsupported_logs),
                                     "Expected the unsupported-OpenSSL-version log to be emitted exactly once")

        # Cache should also short-circuit the supported case (no further run_command invocations).
        _OpenSSLVersionCheck._version_supports_validation = None  # pylint: disable=protected-access
        supported_output = "OpenSSL 1.1.1f  31 Mar 2020"
        with patch("azurelinuxagent.ga.signature_validation_util.run_command", return_value=supported_output) as mock_run:
            for _ in range(5):
                self.assertTrue(openssl_version_supported_for_signature_validation(),
                                "Expected supported OpenSSL version to return True")
            self.assertEqual(1, mock_run.call_count,
                             "Expected run_command to be invoked exactly once for supported OpenSSL version (result should be cached)")

    def test_should_cache_result_of_openssl_version_check_when_exception_raised(self):
        # If determining the OpenSSL version raises an unexpected exception, the function should return False, emit
        # a single error log + telemetry event, and cache the result so the failure path is not re-executed.
        with patch("azurelinuxagent.ga.signature_validation_util._get_openssl_version", side_effect=Exception()) as mock_get:
            with patch("azurelinuxagent.ga.signature_validation_util.logger.warn") as mock_error:
                with patch("azurelinuxagent.ga.signature_validation_util.add_event") as mock_add_event:
                    for _ in range(5):
                        self.assertFalse(openssl_version_supported_for_signature_validation(),
                                         "Expected exception path to return False")
                    self.assertEqual(1, mock_get.call_count,
                                     "Expected _get_openssl_version to be invoked exactly once across 5 calls (result should be cached)")
                    sig_val_events = [kw for _, kw in mock_add_event.call_args_list
                                      if kw.get('op') == WALAEventOperation.SignatureValidation]
                    self.assertEqual(1, len(sig_val_events),
                                     "Expected exactly one SignatureValidation telemetry event for the exception path")
                    self.assertEqual(1, mock_error.call_count,
                                     "Expected the failure-to-determine-version error to be logged exactly once")

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

    def test_signature_validation_should_be_disabled_during_delay_period(self):
        """
        Test that signature validation (agent and extension) is disabled during the delay period after service start,
        and enabled after.
        """
        with patch("azurelinuxagent.ga.signature_validation_util.conf.get_ext_signature_validation_enabled", return_value=True):
            with patch("azurelinuxagent.ga.signature_validation_util.conf.get_agent_signature_validation_enabled", return_value=True):
                with patch("azurelinuxagent.ga.signature_validation_util.ConfidentialVMInfo.is_confidential_vm", return_value=True):

                    # Test 1: Within delay period - validation should be disabled
                    now = datetime.datetime.now(UTC)
                    with patch("azurelinuxagent.ga.signature_validation_util._agent_start_time", now):
                        self.assertFalse(ext_signature_validation_enabled(),
                                         "Extension signature validation should be disabled during delay period")
                        self.assertFalse(agent_signature_validation_enabled(),
                                         "Agent signature validation should be disabled during delay period")

                    # Test 2: After delay period - validation should be enabled
                    past_time = now - datetime.timedelta(seconds=conf.get_signature_validation_initial_delay() + 1)
                    with patch("azurelinuxagent.ga.signature_validation_util._agent_start_time", past_time):
                        self.assertTrue(ext_signature_validation_enabled(), "Extension signature validation should be enabled after delay period")
                        self.assertTrue(agent_signature_validation_enabled(), "Agent signature validation should be enabled after delay period")

    def test_is_agent_signature_validation_expired_should_return_true_if_feature_is_expired(self):
        """
        Test that _is_signature_validation_telemetry_expired returns True when current time is greater than the feature
        expiry time, or when the conf value is invalid
        """
        # When expiry time is in the future, _is_signature_validation_telemetry_expired should return False
        with patch("azurelinuxagent.ga.signature_validation_util.conf.get_signature_validation_telemetry_expiry_time", return_value="2099-12-01"):
            self.assertFalse(_is_signature_validation_telemetry_expired())

        # When expiry time is in the past, _is_signature_validation_telemetry_expired should return True
        with patch("azurelinuxagent.ga.signature_validation_util.conf.get_signature_validation_telemetry_expiry_time", return_value="2000-01-01"):
            self.assertTrue(_is_signature_validation_telemetry_expired())

        # When conf value of Debug.SignatureValidationTelemetryExpiryTime is invalid, _is_signature_validation_telemetry_expired should return True
        with patch("azurelinuxagent.ga.signature_validation_util.conf.get_signature_validation_telemetry_expiry_time", return_value="2026-31-12"):
            self.assertTrue(_is_signature_validation_telemetry_expired())

    def test_is_signature_validation_telemetry_expired_should_report_error_at_most_once_per_run(self):
        """
        When the configured expiry time cannot be parsed, _is_signature_validation_telemetry_expired() should log an
        error and emit a telemetry event exactly once per agent execution, regardless of how many times it is called.
        This avoids flooding the log/telemetry on each goal state processing.
        """
        with patch("azurelinuxagent.ga.signature_validation_util.conf.get_signature_validation_telemetry_expiry_time", return_value="2026-31-12"):
            with patch("azurelinuxagent.ga.signature_validation_util.logger.warn") as mock_warn:
                with patch("azurelinuxagent.ga.signature_validation_util.add_event") as mock_add_event:
                    for _ in range(5):
                        self.assertTrue(_is_signature_validation_telemetry_expired(),
                                        "Expected malformed expiry to be treated as expired")
                    self.assertEqual(1, mock_warn.call_count,
                                     "Expected expiry-check error to be logged exactly once across 5 calls")
                    self.assertEqual(1, len(mock_add_event.call_args_list),
                                     "Expected exactly one telemetry event for the malformed expiry")
                    _, kw = mock_add_event.call_args_list[0]
                    self.assertIn("Error while checking signature validation expiry time", kw.get('message'),
                                     "Expected telemetry event to indicate the malformed expiry")

    @contextlib.contextmanager
    def _patch_agent_signature_validation_dependencies(self, conf_enabled=True, validation_timeout_disabled=False,
                                                       should_delay=False, openssl_supported=True, is_cvm=True,
                                                       telemetry_expired=False):
        """
        Helper that patches all dependencies of agent_signature_validation_enabled() and
        agent_signature_goal_state_telemetry_enabled(). Defaults are set so that both functions return True;
        each test case overrides one parameter to exercise a single failure condition.
        """
        with patch("azurelinuxagent.ga.signature_validation_util.conf.get_agent_signature_validation_enabled", return_value=conf_enabled):
            with patch("azurelinuxagent.ga.signature_validation_util.SignatureValidationTimeout.is_agent_validation_disabled", return_value=validation_timeout_disabled):
                with patch("azurelinuxagent.ga.signature_validation_util._should_delay_signature_validation", return_value=should_delay):
                    with patch("azurelinuxagent.ga.signature_validation_util.openssl_version_supported_for_signature_validation", return_value=openssl_supported):
                        with patch("azurelinuxagent.ga.signature_validation_util.ConfidentialVMInfo.is_confidential_vm", return_value=is_cvm):
                            with patch("azurelinuxagent.ga.signature_validation_util._is_signature_validation_telemetry_expired", return_value=telemetry_expired):
                                yield

    def test_agent_signature_validation_enabled_should_return_expected_value(self):
        """
        Test that agent_signature_validation_enabled() returns True when conf flag is enabled, agent validation is not
        disabled, delay has passed, OpenSSL version is supported, VM is a CVM, and the agent signature validation
        feature is not expired. Returns False if any of these conditions is not met.
        """
        # (description, overrides applied on top of the all-conditions-met defaults, expected return value)
        cases = [
            ("all conditions met", {}, True),
            ("conf flag is disabled", {"conf_enabled": False}, False),
            ("validation timeout exceeded", {"validation_timeout_disabled": True}, False),
            ("validation is delayed", {"should_delay": True}, False),
            ("OpenSSL version is not supported", {"openssl_supported": False}, False),
            ("VM is not a CVM", {"is_cvm": False}, False),
            ("feature is expired", {"telemetry_expired": True}, False),
        ]
        for description, overrides, expected in cases:
            with self._patch_agent_signature_validation_dependencies(**overrides):
                self.assertEqual(expected, agent_signature_validation_enabled(),
                                 "agent_signature_validation_enabled() returned wrong value for case: {0}".format(description))

    def test_agent_signature_goal_state_telemetry_enabled_should_return_expected_value(self):
        """
        Test that agent_signature_goal_state_telemetry_enabled() returns True when conf flag is enabled, VM is a CVM,
        and the agent signature validation feature is not expired. Returns False if any of these conditions is not met.
        """
        # (description, overrides applied on top of the all-conditions-met defaults, expected return value)
        # Note: agent_signature_goal_state_telemetry_enabled() only depends on conf flag, CVM status, and expiry, so
        # only those overrides are exercised here. 
        cases = [
            ("all conditions met", {}, True),
            ("conf flag is disabled", {"conf_enabled": False}, False),
            ("VM is not a CVM", {"is_cvm": False}, False),
            ("feature is expired", {"telemetry_expired": True}, False),
        ]
        for description, overrides, expected in cases:
            with self._patch_agent_signature_validation_dependencies(**overrides):
                self.assertEqual(expected, agent_signature_goal_state_telemetry_enabled(),
                                 "agent_signature_goal_state_telemetry_enabled() returned wrong value for case: {0}".format(description))


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

        validate_extension_manifest_signing_info(manifest, ext_handler)

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

        validate_extension_manifest_signing_info(manifest, ext_handler)

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
            validate_extension_manifest_signing_info(manifest, ext_handler)
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
            validate_extension_manifest_signing_info(manifest, ext_handler)
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
            validate_extension_manifest_signing_info(manifest, ext_handler)
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
            validate_extension_manifest_signing_info(manifest, ext_handler)
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
            validate_extension_manifest_signing_info(manifest, ext_handler)
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
            validate_extension_manifest_signing_info(manifest, ext_handler)
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
            validate_extension_manifest_signing_info(manifest, ext_handler)
        expected_error_msg = "HandlerManifest.json does not contain attribute 'signingInfo.version'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                          msg="Raised ManifestValidationError but error did not indicate missing signingInfo.version")



class TestAgentHandlerManifestValidation(AgentTestCase):

    AGENT_VERSION = "9.9.9.9"

    def test_should_validate_agent_manifest_successfully(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "name": AGENT_SIGNING_INFO_NAME,
                "version": self.AGENT_VERSION
            }
        }

        validate_agent_manifest_signing_info(HandlerManifest(data), self.AGENT_VERSION)

    def test_should_raise_error_if_agent_manifest_name_does_not_match(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "name": "Microsoft.SomeOther.Agent",
                "version": self.AGENT_VERSION
            }
        }

        with self.assertRaises(ManifestValidationError) as ex:
            validate_agent_manifest_signing_info(HandlerManifest(data), self.AGENT_VERSION)
        expected_error_msg = "expected agent name 'Microsoft.OSTCLinuxAgent' does not match downloaded package name 'Microsoft.SomeOther.Agent'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                          msg="Raised ManifestValidationError but error did not indicate name mismatch")

    def test_should_raise_error_if_agent_manifest_name_case_does_not_match(self):
        # Unlike extensions, agent manifest comparison is case-sensitive.
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "name": AGENT_SIGNING_INFO_NAME.lower(),
                "version": self.AGENT_VERSION
            }
        }

        with self.assertRaises(ManifestValidationError) as ex:
            validate_agent_manifest_signing_info(HandlerManifest(data), self.AGENT_VERSION)
        expected_error_msg = "expected agent name 'Microsoft.OSTCLinuxAgent' does not match downloaded package name 'microsoft.ostclinuxagent'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                      msg="Raised ManifestValidationError but error did not indicate name case mismatch")

    def test_should_raise_error_if_agent_manifest_version_does_not_match(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "name": AGENT_SIGNING_INFO_NAME,
                "version": "1.2.3.4"
            }
        }

        with self.assertRaises(ManifestValidationError) as ex:
            validate_agent_manifest_signing_info(HandlerManifest(data), self.AGENT_VERSION)
        expected_error_msg = "expected agent version '9.9.9.9' does not match downloaded package version '1.2.3.4'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                      msg="Raised ManifestValidationError but error did not indicate version mismatch")

    def test_should_raise_error_if_agent_manifest_does_not_contain_signing_info(self):
        data = {
            "handlerManifest": {}
        }

        with self.assertRaises(ManifestValidationError) as ex:
            validate_agent_manifest_signing_info(HandlerManifest(data), self.AGENT_VERSION)
        expected_error_msg = "HandlerManifest.json does not contain 'signingInfo'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                      msg="Raised ManifestValidationError but error did not indicate missing signingInfo")

    def test_should_raise_error_if_agent_manifest_does_not_contain_signing_info_name(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "version": self.AGENT_VERSION
            }
        }

        with self.assertRaises(ManifestValidationError) as ex:
            validate_agent_manifest_signing_info(HandlerManifest(data), self.AGENT_VERSION)
        expected_error_msg = "HandlerManifest.json does not contain attribute 'signingInfo.name'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                      msg="Raised ManifestValidationError but error did not indicate missing signingInfo.name")

    def test_should_raise_error_if_agent_manifest_does_not_contain_signing_info_version(self):
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "name": AGENT_SIGNING_INFO_NAME
            }
        }

        with self.assertRaises(ManifestValidationError) as ex:
            validate_agent_manifest_signing_info(HandlerManifest(data), self.AGENT_VERSION)
        expected_error_msg = "HandlerManifest.json does not contain attribute 'signingInfo.version'"
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                      msg="Raised ManifestValidationError but error did not indicate missing signingInfo.version")

    def test_should_raise_reraise_exception_as_manifest_validation_error(self):
        # Any unexpected exception raised during agent manifest validation (e.g., not a ManifestValidationError)
        # should be caught and re-raised as a ManifestValidationError.
        data = {
            "handlerManifest": {},
            "signingInfo": {
                "name": AGENT_SIGNING_INFO_NAME,
                "version": self.AGENT_VERSION
            }
        }

        manifest = HandlerManifest(data)
        with patch.object(manifest, "get_signing_info", side_effect=Exception("unexpected failure")):
            with self.assertRaises(ManifestValidationError) as ex:
                validate_agent_manifest_signing_info(manifest, self.AGENT_VERSION)
        expected_error_msg = "Error during manifest 'signingInfo' validation for agent 'WALinuxAgent-{0}'. Error: unexpected failure".format(self.AGENT_VERSION)
        self.assertIn(expected_error_msg, str(ex.exception.args[0]),
                      msg="Unexpected exception should be re-raised as a ManifestValidationError")
