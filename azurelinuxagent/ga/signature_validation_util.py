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
import base64
import datetime
import os
import re
import uuid

from azurelinuxagent.common import conf
from azurelinuxagent.common.utils.shellutil import run_command, CommandError
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common import logger
from azurelinuxagent.ga.signing_certificate_util import get_microsoft_signing_certificate_path
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.future import ustr, UTC, datetime_min_utc
from azurelinuxagent.common.event import add_event, WALAEventOperation, elapsed_milliseconds
from azurelinuxagent.common.version import AGENT_VERSION, AGENT_NAME, AGENT_SIGNING_INFO_NAME
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator, PKG_SIGNATURE_VALIDATION_CPU_QUOTA, PKG_SIGNATURE_VALIDATION_SLICE_NAME, PKG_SIGNATURE_VALIDATION_CGROUPS_UNIT_NAME, DisableCgroups
from azurelinuxagent.common.osutil.systemd import is_systemd_run_failure
from azurelinuxagent.ga.confidential_vm_info import ConfidentialVMInfo


# Signature validation requires OpenSSL version 1.1.0 or later. The 'no_check_time' flag used for the 'openssl cms -verify'
# command is not supported on older versions.
_MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION = FlexibleVersion("1.1.0")

# Track the time when the agent module is first loaded. This is used to implement an initial delay period before validating signature.
# TODO: This is a temporary performance workaround for telemetry release; remove for production release.
_agent_start_time = datetime.datetime.now(UTC)


class SignatureValidationTimeout(object):
    """
    Tracks whether signature validation should be disabled due to a timeout. 
    
    A timeout during extension signature validation should not disable validation for agent signature validation, 
    and vice versa. This is because extension packages are typically larger than agent packages, and are more likely 
    to experience timeouts. 
    
    Disabling extension signature validation should only be done when the customer has not opted into enforcement
    of extension signature validation.

    TODO: This is a temporary workaround to prevent performance impact during telemetry release; remove for production release.
    """
    # Should only be set to True when customer has not opted into extension signature validation enforcement.
    _ext_validation_disabled = False

    _agent_validation_disabled = False

    @staticmethod
    def is_ext_validation_disabled():
        return SignatureValidationTimeout._ext_validation_disabled

    @staticmethod
    def disable_ext_validation():
        SignatureValidationTimeout._ext_validation_disabled = True

    @staticmethod
    def is_agent_validation_disabled():
        return SignatureValidationTimeout._agent_validation_disabled

    @staticmethod
    def disable_agent_validation():
        SignatureValidationTimeout._agent_validation_disabled = True


class PackageValidationError(AgentError):
    """
    Error raised when validation fails for a package.
    """
    def __init__(self, msg, operation, duration, inner=None, code=-1):
        super(PackageValidationError, self).__init__(msg, inner)
        self.code = code
        self.duration = duration
        self.operation = operation


class SignatureValidationError(PackageValidationError):
    """
    Error raised when signature validation fails for a package.
    """


class ManifestValidationError(PackageValidationError):
    """
    Error raised when handler manifest 'signingInfo' validation fails for a package.
    """


class SignatureValidationTimeoutError(SignatureValidationError):
    """
    Error raised when signature validation times out.
    """


def _get_openssl_version():
    """
    Calls 'openssl version' via subprocess and extracts the version from its output.
    Returns OpenSSL version string in major.minor.patch format. Any letter suffix is ignored (e.g., '1.1.1f' and '1.1.1wa-fips' will both return '1.1.1').
    If version cannot be found, returns '0.0.0'.
    """
    try:
        command = [conf.get_openssl_cmd(), 'version']
        output = run_command(command)
        if output is None:
            logger.error("Failed to get OpenSSL version. '{0}' returned no output.", ' '.join(command))
            return "0.0.0"

        match = re.search(r"OpenSSL (\d+\.\d+\.\d+)", output)
        if match is not None:
            return match.group(1)
        else:
            logger.error("Failed to get OpenSSL version. '{0}' returned output: {1}", ' '.join(command), output)
            return "0.0.0"

    except CommandError as ex:
        logger.error("Failed to get OpenSSL version. Error: {0}", ex.stderr)
        return "0.0.0"


class _OpenSSLVersionCheck(object):
    """
    Caches the result of the OpenSSL version capability check performed by
    openssl_version_supported_for_signature_validation(). Caching avoids repeated subprocess calls, 
    log noise, and repeated telemetry events.

    TODO: This is a temporary workaround while we collect telemetry on the signature validation feature; remove for
    production release once enforcement is in place.
    """
    # None until first check; True/False thereafter.
    _version_supports_validation = None

    @staticmethod
    def get_version_supports_validation():
        return _OpenSSLVersionCheck._version_supports_validation

    @staticmethod
    def set_version_supports_validation(supported):
        _OpenSSLVersionCheck._version_supports_validation = supported


def openssl_version_supported_for_signature_validation():
    # Signature validation currently requires OpenSSL >= 1.1.0 to support the 'no_check_time' flag
    # used with the 'openssl cms verify' command. This flag bypasses timestamp checks, and will be removed once
    # proper timestamp validation is implemented.
    #
    # For private preview release only, signature validation is only supported on distros with OpenSSL >= 1.1.0, and
    # users will be informed accordingly. If the OpenSSL version is too old, we log this and return False rather than
    # raising an error.
    #
    # The result is cached after the first call so the OpenSSL version check (and any associated log/telemetry) only
    # runs once per agent execution.
    version_supports_validation = _OpenSSLVersionCheck.get_version_supports_validation()
    if version_supports_validation is not None:
        return version_supports_validation

    try:
        openssl_version = _get_openssl_version()
        if FlexibleVersion(openssl_version) < _MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION:
            msg = ("Signature validation requires OpenSSL version {0}, but the current version is {1}. "
                   "To validate signature, please upgrade OpenSSL to version {0} or higher.").format(
                _MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION, openssl_version)
            logger.info(msg)
            add_event(op=WALAEventOperation.SignatureValidation, is_success=True,
                      message=msg, log_event=False)     # is_success=True to avoid polluting release monitoring queries while we collect telemetry on this feature
            _OpenSSLVersionCheck.set_version_supports_validation(False)
            return False
        _OpenSSLVersionCheck.set_version_supports_validation(True)
        return True
    except Exception as ex:
        msg = "Failed to determine if OpenSSL version supports signature validation. Error: {0}".format(ustr(ex))
        logger.warn(msg)
        add_event(op=WALAEventOperation.SignatureValidation, is_success=False, message=msg, log_event=False)
        _OpenSSLVersionCheck.set_version_supports_validation(False)
        return False


def _write_signature_to_file(sig_string, output_file):
    """
    Convert the base64-encoded signature string to binary, and write to the output file.
    """
    binary_signature = base64.b64decode(sig_string.strip())
    with open(output_file, "wb") as f:
        f.write(binary_signature)


def report_validation_event(op, level, message, name, version, duration):
    """
    Log signature validation event and emit telemetry with appropriate message based on log level.
    'level' is expected to be one of logger.LogLevel.INFO, WARNING, or ERROR. If level is WARNING, prefix with "[WARNING]"
    in telemetry, and append a message that failure can be ignored.

    Telemetry 'is_success' behavior based on log level:
        - ERROR: is_success=False, these should surface in release error monitoring queries.
        - WARNING: is_success=True. WARNING-level events should not surface in release error monitoring queries while
            we are collecting telemetry for this feature. TODO: is_success = False once we start enforcing signature validation
        - INFO: is_success=True.

    TODO: for extension signature validation, add '[Name-Version]' prefix to log messages
    """
    if level == logger.LogLevel.ERROR:
        logger.error(message)
        event_msg = message
        is_success = False
    elif level == logger.LogLevel.WARNING:
        message = "{0}\nThis failure can be safely ignored; will continue processing the package.".format(message)
        logger.warn(message)
        event_msg = "[WARNING] {0}".format(message)
        is_success = True
    else:
        # Log as INFO. If the level is invalid (i.e., not INFO, WARNING, or ERROR), treat it as INFO and prepend a warning to the message.
        if level != logger.LogLevel.INFO:
            message = "Invalid log level '{0}', reporting event at 'INFO' level instead. {1}".format(level, message)
        logger.info(message)
        event_msg = message
        is_success = True

    add_event(op=op, message=event_msg, name=name, version=version, is_success=is_success, duration=duration, log_event=False)


def validate_signature(package_path, signature, package_full_name):
    """
    Validates signature of provided package using OpenSSL CLI. The verification checks the signature against a trusted
    Microsoft root certificate but does not enforce certificate expiration.

    :param package_path: path to package file being validated
    :param signature: base64-encoded signature string
    :param package_full_name: string in the format "Name-Version", only used for telemetry purposes
    :raises SignatureValidationError: if signature validation fails
    """
    # Initialize variables that will be used in the except/finally blocks. These are assigned inside the try block,
    # but defining them here ensures safe access if an exception occurs before assignment.
    start_time = datetime_min_utc
    signature_path = ""
    name, version = "", ""

    try:
        start_time = datetime.datetime.now(UTC)
        # Extract package name and version from 'package_full_name' for telemetry. If format is not <name>-<version>, use
        # 'package_full_name' as the name and an empty string for version.
        name, version = package_full_name.rsplit('-', 1) if '-' in package_full_name else (package_full_name, "")
        signature_file_name = os.path.basename(package_path) + "_signature.pem"
        signature_path = os.path.join(conf.get_lib_dir(), str(signature_file_name))

        report_validation_event(op=WALAEventOperation.SignatureValidation, level=logger.LogLevel.INFO,
                                message="Validating signature for package '{0}'".format(package_full_name), name=name, version=version, duration=0)

        # Write signature to file and get signing certificate path
        _write_signature_to_file(signature, signature_path)
        microsoft_root_cert_file = get_microsoft_signing_certificate_path()
        if not os.path.isfile(microsoft_root_cert_file):
            msg = ("signing certificate was not found at expected location ('{0}'). Try restarting the agent, "
                   "or see log ('{1}') for additional details.").format(microsoft_root_cert_file, conf.get_agent_log_file())
            raise Exception(msg)

        # Use OpenSSL CLI to verify that the provided signature file correctly signs the package. The verification
        # process checks the certificate chain against the specified root certificate file, but the certificate's
        # expiration date is not enforced due to the `-no_check_time` flag. This allows the signature to be validated
        # regardless of the certificate's expiration status. However, bypassing expiration checking does not guarantee
        # that the signature is valid, as it could have been created with an expired/revoked certificate. This flag serves
        # as a temporary measure until a robust solution for handling expired/revoked certificates is implemented.
        #
        # TODO: implement timestamp token parsing and validate that certificate was valid at time of signing
        base_command = [
            conf.get_openssl_cmd(), 'cms', '-verify',
            '-binary', '-inform', 'der',  # Signature input format must be DER (binary encoding)
            '-in', signature_path,  # Path to the CMS signature file to be verified
            '-content', package_path,  # Path to the original package that was signed
            '-purpose', 'any',  # Allows verification for any purpose, not restricted to specific uses
            '-CAfile', microsoft_root_cert_file,  # Path to the trusted root certificate file used for verification
            '-no_check_time',  # Skips checking whether the certificate is expired
            '-out', os.devnull  # Command outputs the signed data, we don't need it so we suppress it
        ]

        # If cgroups are enabled, attempt to run the command in a dedicated systemd-run scope with a dedicated CPU quota.
        # This is because signature validation is CPU-intensive and may take excessive time if the agent's CPU quota is low.
        # If the systemd-run invocation fails, disable cgroups entirely and fall back to running the OpenSSL command directly.
        use_cgroups = CGroupConfigurator.get_instance().enabled()
        if use_cgroups:
            slice_name = PKG_SIGNATURE_VALIDATION_SLICE_NAME + ".slice"
            # Use a unique unit name per invocation to avoid collisions with prior transient units that systemd may
            # not have garbage-collected yet (e.g. if a previous invocation left the unit in a 'failed' state). This
            # mirrors the pattern used by start_extension_command() in cgroupapi.py.
            unit_name = "{0}_{1}".format(PKG_SIGNATURE_VALIDATION_CGROUPS_UNIT_NAME, ustr(uuid.uuid4()))
            systemd_cmd = ['systemd-run', '--unit={0}'.format(unit_name), '--slice={0}'.format(slice_name), '--scope',
                           '--property=CPUQuota={0}'.format(PKG_SIGNATURE_VALIDATION_CPU_QUOTA)]

            # Add accounting properties based on cgroup version
            accounting_props, accounting_vals = CGroupConfigurator.get_instance().get_cgroups_api().get_accounting_properties()
            for prop, val in zip(accounting_props, accounting_vals):
                systemd_cmd.append('--property={0}={1}'.format(prop, val))

            systemd_cmd.extend(base_command)
            try:
                # NOTE: The timeout parameter is ignored on Python 2, but this is acceptable because signature validation
                # is currently only performed on CVMs which should not be running Python 2, and the timeout is a temporary performance workaround.
                run_command(systemd_cmd, timeout=conf.get_signature_validation_timeout())
            except CommandError as ex:
                # If the systemd-run invocation itself failed, disable cgroups entirely and fall back to running openssl command directly.
                # If the openssl command failed, re-raise and do not retry.
                if is_systemd_run_failure(unit_name, ex.stderr):
                    error_msg = "'systemd-run' invocation failed for signature validation, disabling cgroups and falling back to direct execution. Error: '{0}'".format(ex.stderr)
                    report_validation_event(op=WALAEventOperation.SignatureValidation, level=logger.LogLevel.WARNING,
                        message=error_msg,
                        name=name, version=version, duration=0)
                    CGroupConfigurator.get_instance().disable(reason=error_msg, disable_cgroups=DisableCgroups.ALL)
                    run_command(base_command, timeout=conf.get_signature_validation_timeout())
                else:
                    raise
        else:
            # Run without systemd if cgroups disabled
            run_command(base_command, timeout=conf.get_signature_validation_timeout())

        report_validation_event(op=WALAEventOperation.PackageSignatureResult, level=logger.LogLevel.INFO,
                                message="Successfully validated signature for package '{0}'".format(package_full_name),
                                name=name, version=version, duration=elapsed_milliseconds(start_time))

    except CommandError as ex:
        # Handle command timeout - raise specific timeout error so caller can decide whether to disable future validations
        if "command timeout" in ex.stderr:
            msg = "Signature validation timed out after {0} seconds for package '{1}'.".format(
                conf.get_signature_validation_timeout(), package_full_name)
            raise SignatureValidationTimeoutError(msg=msg, operation=WALAEventOperation.PackageSignatureResult,
                                                  duration=elapsed_milliseconds(start_time))

        # For validation-related errors only, send the full signature string in telemetry for debugging purposes.
        add_event(op=WALAEventOperation.SignatureValidation, message="Package encoded signature: '{0}'".format(signature),
                  name=name, version=version, log_event=False)

        # If the signature validation command failed, raise a SignatureValidationError with event duration. Duration will be reported in telemetry by the caller.
        msg = "Signature validation failed for package '{0}'. \nReturn code: {1}\nError details:\n{2}".format(package_full_name, ex.returncode, ex.stderr)
        raise SignatureValidationError(msg=msg, operation=WALAEventOperation.PackageSignatureResult, duration=elapsed_milliseconds(start_time))

    except Exception as ex:
        # Catch all exceptions unrelated to OpenSSL signature verification (e.g., missing root certificate). Raise a SignatureValidationError with zero duration.
        msg = "Signature validation failed for package '{0}'. Error: {1}".format(package_full_name, ustr(ex))
        raise SignatureValidationError(msg=msg, operation=WALAEventOperation.SignatureValidation, duration=0)

    finally:
        # If signature file cleanup fails, log a warning and swallow the error
        try:
            if signature_path != "" and os.path.isfile(signature_path):
                os.remove(signature_path)
        except Exception as ex:
            report_validation_event(op=WALAEventOperation.SignatureValidation, level=logger.LogLevel.WARNING,
                                    message="Failed to cleanup signature file ('{0}'). Error: {1}".format(signature_path, ex),
                                    name=name, version=version, duration=0)


def validate_extension_manifest_signing_info(manifest, ext_handler):
    """
    For signed extensions, the handler manifest includes a "signingInfo" section that specifies
    the type, publisher, and version of the extension. During signature validation (after extracting zip package),
    we check these attributes against the expected values for the extension. If there is a mismatch, raise an error.

    :param manifest: HandlerManifest object
    :param ext_handler: Extension object
    :raises ManifestValidationError: if handler manifest validation fails
    """
    start_time = datetime_min_utc
    try:
        start_time = datetime.datetime.now(UTC)
        report_validation_event(op=WALAEventOperation.SignatureValidation, level=logger.LogLevel.INFO,
                                message="Validating handler manifest 'signingInfo' of extension '{0}'".format(ext_handler),
                                name=ext_handler.name, version=ext_handler.version, duration=0)

        # Check that 'signingInfo' exists in the manifest structure
        man_signing_info = manifest.get_signing_info()
        if man_signing_info is None:
            raise ManifestValidationError(msg="HandlerManifest.json does not contain 'signingInfo' for extension '{0}'".format(ext_handler),
                                          operation=WALAEventOperation.PackageSigningInfoResult, duration=elapsed_milliseconds(start_time))

        def validate_attribute(attribute, extension_value):
            # Validate that the specified 'attribute' exists in 'signingInfo', and that it matches the expected 'extension_value'.
            # If not, raise a ManifestValidationError.
            signing_info_value = man_signing_info.get(attribute)
            if signing_info_value is None:
                raise ManifestValidationError(msg="HandlerManifest.json does not contain attribute 'signingInfo.{0}' for extension '{1}'".format(attribute, ext_handler),
                                              operation=WALAEventOperation.PackageSigningInfoResult, duration=elapsed_milliseconds(start_time))

            # Comparison should be case-insensitive, because CRP ignores case for extension name.
            if extension_value.lower() != signing_info_value.lower():
                raise ManifestValidationError(msg="expected extension {0} '{1}' does not match downloaded package {0} '{2}' for extension '{3}'".format(attribute, extension_value, signing_info_value, ext_handler),
                                              operation=WALAEventOperation.PackageSigningInfoResult, duration=elapsed_milliseconds(start_time))

        # Compare extension attributes against the attributes specified in 'signingInfo'
        ext_publisher, ext_type = ext_handler.name.rsplit(".", 1)
        validate_attribute(attribute="type", extension_value=ext_type)
        validate_attribute(attribute="publisher", extension_value=ext_publisher)
        validate_attribute(attribute="version", extension_value=ext_handler.version)

        report_validation_event(op=WALAEventOperation.PackageSigningInfoResult, level=logger.LogLevel.INFO,
                                message="Successfully validated handler manifest 'signingInfo' for extension '{0}'".format(ext_handler),
                                name=ext_handler.name, version=ext_handler.version, duration=elapsed_milliseconds(start_time))

    except ManifestValidationError:
        # Should not be caught by the general Exception block
        raise

    except Exception as ex:
        # Catch any exceptions unrelated to 'signingInfo' validation (e.g. incorrectly formatted extension name) and raise as a ManifestValidationError with zero duration.
        raise ManifestValidationError(msg="Error during manifest 'signingInfo' validation for extension '{0}'. Error: {1}".format(ext_handler, ustr(ex)),
                                      operation=WALAEventOperation.PackageSigningInfoResult, duration=0)


def validate_agent_manifest_signing_info(manifest, expected_agent_version):
    """
    For signed agent packages, the handler manifest includes a "signingInfo" section that specifies
    the 'name' and 'version' of the agent.

    During agent package validation, we check the 'signingInfo' attributes against the
    expected values. If there is a mismatch, raise a ManifestValidationError.

    Unlike extensions, the agent's "signingInfo" does not include 'publisher' or 'type'. Those values are
    not delivered in the goal state for the agent, so there would be no value in checking those from the
    handler manifest. Instead the agent expects a 'name' attribute which should match the expected name.

    :param manifest: HandlerManifest object
    :param expected_agent_version: the expected agent version string (e.g., "9.9.9.9")
    :raises ManifestValidationError: if handler manifest validation fails
    """
    start_time = datetime_min_utc
    agent_full_name = "{0}-{1}".format(AGENT_NAME, expected_agent_version)
    try:
        start_time = datetime.datetime.now(UTC)
        report_validation_event(op=WALAEventOperation.SignatureValidation, level=logger.LogLevel.INFO,
                                message="Validating handler manifest 'signingInfo' of agent '{0}'".format(agent_full_name),
                                name=AGENT_NAME, version=expected_agent_version, duration=0)

        # Check that 'signingInfo' exists in the manifest structure
        man_signing_info = manifest.get_signing_info()
        if man_signing_info is None:
            raise ManifestValidationError(msg="HandlerManifest.json does not contain 'signingInfo' for agent '{0}'".format(agent_full_name),
                                          operation=WALAEventOperation.PackageSigningInfoResult, duration=elapsed_milliseconds(start_time))

        def validate_attribute(attribute, expected_value):
            # Validate that the specified 'attribute' exists in 'signingInfo', and that it matches the expected 'expected_value'.
            # If not, raise a ManifestValidationError.
            signing_info_value = man_signing_info.get(attribute)
            if signing_info_value is None:
                raise ManifestValidationError(msg="HandlerManifest.json does not contain attribute 'signingInfo.{0}' for agent '{1}'".format(attribute, agent_full_name),
                                              operation=WALAEventOperation.PackageSigningInfoResult, duration=elapsed_milliseconds(start_time))
            
            # Case-sensitive comparison, unlike the extensions signingInfo comparison which is case-insensitive.
            # AGENT_SIGNING_INFO_NAME is hardcoded and the manifest is generated from the same constant that we use for comparison and
            # version is numeric, so any case difference should be surfaced.
            if ustr(expected_value) != ustr(signing_info_value):
                raise ManifestValidationError(msg="expected agent {0} '{1}' does not match downloaded package {0} '{2}' for agent '{3}'".format(attribute, expected_value, signing_info_value, agent_full_name),
                                              operation=WALAEventOperation.PackageSigningInfoResult, duration=elapsed_milliseconds(start_time))

        # Compare agent attributes against the attributes specified in 'signingInfo'
        validate_attribute(attribute="name", expected_value=AGENT_SIGNING_INFO_NAME)
        validate_attribute(attribute="version", expected_value=expected_agent_version)

        report_validation_event(op=WALAEventOperation.PackageSigningInfoResult, level=logger.LogLevel.INFO,
                                message="Successfully validated handler manifest 'signingInfo' for agent '{0}'".format(agent_full_name),
                                name=AGENT_NAME, version=expected_agent_version, duration=elapsed_milliseconds(start_time))

    except ManifestValidationError:
        # Should not be caught by the general Exception block
        raise

    except Exception as ex:
        # Catch any exceptions unrelated to 'signingInfo' validation and raise as a ManifestValidationError with zero duration.
        raise ManifestValidationError(msg="Error during manifest 'signingInfo' validation for agent '{0}'. Error: {1}".format(agent_full_name, ustr(ex)),
                                      operation=WALAEventOperation.PackageSigningInfoResult, duration=0)


def _should_delay_signature_validation():
    """
    Signature validation is a CPU-intensive operation that may impact VM provisioning time. To avoid affecting TDPR
    for performance-sensitive users, we implement an initial delay period after agent startup (set via conf flag
    Debug.SignatureValidationInitialDelay), during which signature validation is skipped. This allows us to gather telemetry
    without impacting TDPR. This strategy will be used for both agent and extension signature validation while gathering
    telemetry.

    This function returns True if we are still within the delay period, False otherwise.

    TODO: This delay is a temporary workaround for telemetry release; remove for production release.
    """
    delay_seconds = conf.get_signature_validation_initial_delay()
    if delay_seconds <= 0:
        return False

    elapsed = datetime.datetime.now(UTC) - _agent_start_time
    return elapsed < datetime.timedelta(seconds=delay_seconds)


# Tracks whether we have already reported an error while checking the expiry time so we don't log/emit telemetry on every call.
# _is_signature_validation_telemetry_expired() can be called multiple times during a single goal state execution
class _ExpiryCheckErrorReporter(object):
    _reported = False

    @staticmethod
    def already_reported():
        return _ExpiryCheckErrorReporter._reported

    @staticmethod
    def mark_reported():
        _ExpiryCheckErrorReporter._reported = True


def _is_signature_validation_telemetry_expired():
    """
    We disable the agent signature validation feature after the expiry time. This is to prevent any long-term unintended
    behaviors in the agent if this version of the agent is baked-in to an image.
    """
    try:
        expiry_date = datetime.datetime.strptime(conf.get_signature_validation_telemetry_expiry_time(), "%Y-%m-%d").replace(tzinfo=UTC)
        return datetime.datetime.now(UTC) >= expiry_date
    except Exception as ex:
        # Catch any exception (e.g. ValueError from a malformed date string) and treat the feature as expired so we fail safe.
        # Only report the error once per agent execution to avoid flooding the log, since this function can be called
        # multiple times for a single goal state.
        if not _ExpiryCheckErrorReporter.already_reported():
            _ExpiryCheckErrorReporter.mark_reported()
            msg = ("Error while checking signature validation expiry time "
                   "(Debug.SignatureValidationTelemetryExpiryTime) from conf, will skip signature validation. "
                   "Error: {0}").format(ustr(ex))
            logger.warn(msg)
            add_event(op=WALAEventOperation.SignatureValidation, is_success=False, message=msg, log_event=False)
        return True


def ext_signature_validation_enabled():
    """
    Returns True if all conditions for extension signature validation are met:
    - Conf flag 'EnableExtSignatureValidation' is True
    - Agent is running on a Confidential VM (TODO: remove when all VMs are supported)
    - Extension signature validation timeout has not been exceeded (TODO: remove after telemetry release)
    - Initial delay period after agent start has passed (TODO: remove after telemetry release)
    - Signature validation feature is not expired according to Conf flag 'Debug.SignatureValidationTelemetryExpiryTime' (TODO: remove after telemetry release(s))
    - OpenSSL version supports required validation parameters (TODO: remove after timestamp validation implemented)
    """
    return conf.get_ext_signature_validation_enabled() and \
           ConfidentialVMInfo.is_confidential_vm() and \
           not SignatureValidationTimeout.is_ext_validation_disabled() and \
           not _should_delay_signature_validation() and \
           not _is_signature_validation_telemetry_expired() and \
           openssl_version_supported_for_signature_validation()


def agent_signature_validation_enabled():
    """
    Returns True if all conditions for agent signature validation are met:
        - Conf flag 'EnableAgentSignatureValidation' is True
        - Agent is running on a Confidential VM (TODO: remove when all VMs are supported)
        - Agent signature validation timeout has not been exceeded (TODO: remove after telemetry release(s))
        - Initial delay period after agent start has passed (TODO: remove after telemetry release(s))
        - Signature validation feature is not expired according to Conf flag 'Debug.SignatureValidationTelemetryExpiryTime' (TODO: remove after telemetry release(s))
        - OpenSSL version supports all validation parameters (TODO: remove after timestamp validation implemented)

    Agent package signature validation is currently limited to CVMs for telemetry/preview releases. It will be expanded to all VMs after we gain confidence in the feature.
    TODO: Remove the is_confidential_vm() check once signature validation is supported on all VMs.
    """
    return conf.get_agent_signature_validation_enabled() and \
           ConfidentialVMInfo.is_confidential_vm() and \
           not SignatureValidationTimeout.is_agent_validation_disabled() and \
           not _should_delay_signature_validation() and \
           not _is_signature_validation_telemetry_expired() and \
           openssl_version_supported_for_signature_validation()


def agent_signature_goal_state_telemetry_enabled():
    """
    Returns True if all conditions for agent signature goal state telemetry are met:
        - Conf flag 'EnableAgentSignatureValidation' is True
        - Agent is running on a Confidential VM (TODO: remove when all VMs are supported)
        - Agent signature validation feature is not expired according to Conf flag 'Debug.SignatureValidationTelemetryExpiryTime' (TODO: remove after telemetry release(s))

    We separate goal state telemetry enablement from signature validation enablement because validation enablement has
    performance concerns and openssl requirements, whereas sending telemetry on goal state signature contents has no
    performance concerns or dependencies on OpenSSL.

    Agent package signature validation is currently limited to CVMs for telemetry/preview releases. It will be expanded to all VMs after we gain confidence in the feature.
    TODO: Remove the is_confidential_vm() check once signature validation is supported on all VMs.
    """
    return conf.get_agent_signature_validation_enabled() and \
           ConfidentialVMInfo.is_confidential_vm() and \
           not _is_signature_validation_telemetry_expired()


def cleanup_package_with_invalid_signature(package_file):
    try:
        report_validation_event(op=WALAEventOperation.SignatureValidation, level=logger.LogLevel.INFO, name=AGENT_NAME, version=AGENT_VERSION,
                                message="Removing package {0} due to failed signature validation.".format(package_file), duration=0)
        os.remove(package_file)
    except Exception as cleanup_ex:
        report_validation_event(op=WALAEventOperation.ExtensionCleanup, level=logger.LogLevel.WARNING, name=AGENT_NAME, version=AGENT_VERSION,
                                message="Failed to delete package {0}: {1}".format(package_file, ustr(cleanup_ex)), duration=0)
