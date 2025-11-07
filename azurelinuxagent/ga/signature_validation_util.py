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

from azurelinuxagent.common import conf
from azurelinuxagent.common.utils.shellutil import run_command, CommandError
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common import logger
from azurelinuxagent.ga.signing_certificate_util import get_microsoft_signing_certificate_path
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.future import ustr, UTC, datetime_min_utc
from azurelinuxagent.common.event import add_event, WALAEventOperation, elapsed_milliseconds
from azurelinuxagent.common.version import AGENT_VERSION, AGENT_NAME
from azurelinuxagent.ga.confidential_vm_info import ConfidentialVMInfo


# Signature validation requires OpenSSL version 1.1.0 or later. The 'no_check_time' flag used for the 'openssl cms -verify'
# command is not supported on older versions.
_MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION = FlexibleVersion("1.1.0")


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


def openssl_version_supported_for_signature_validation():
    # Signature validation currently requires OpenSSL >= 1.1.0 to support the 'no_check_time' flag
    # used with the 'openssl cms verify' command. This flag bypasses timestamp checks, and will be removed once
    # proper timestamp validation is implemented.
    #
    # For private preview release only, signature validation is only supported on distros with OpenSSL >= 1.1.0, and
    # users will be informed accordingly. If the OpenSSL version is too old, we log this and return False rather than
    # raising an error.
    openssl_version = _get_openssl_version()
    if FlexibleVersion(openssl_version) < _MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION:
        msg = ("Signature validation requires OpenSSL version {0}, but the current version is {1}. "
               "To validate signature, please upgrade OpenSSL to version {0} or higher.").format(
            _MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION, openssl_version)
        logger.info(msg)
        return False
    return True


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
        is_success = False
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
        command = [
            conf.get_openssl_cmd(), 'cms', '-verify',
            '-binary', '-inform', 'der',  # Signature input format must be DER (binary encoding)
            '-in', signature_path,  # Path to the CMS signature file to be verified
            '-content', package_path,  # Path to the original package that was signed
            '-purpose', 'any',  # Allows verification for any purpose, not restricted to specific uses
            '-CAfile', microsoft_root_cert_file,  # Path to the trusted root certificate file used for verification
            '-no_check_time'  # Skips checking whether the certificate is expired
        ]
        run_command(command, encode_output=False)

        report_validation_event(op=WALAEventOperation.PackageSignatureResult, level=logger.LogLevel.INFO,
                                message="Successfully validated signature for package '{0}'".format(package_full_name),
                                name=name, version=version, duration=elapsed_milliseconds(start_time))

    except CommandError as ex:
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


def validate_handler_manifest_signing_info(manifest, ext_handler):
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
        man_signing_info = manifest.data.get("signingInfo")
        if man_signing_info is None:
            raise ManifestValidationError(msg="HandlerManifest.json does not contain 'signingInfo'",
                                          operation=WALAEventOperation.PackageSigningInfoResult, duration=elapsed_milliseconds(start_time))

        def validate_attribute(attribute, extension_value):
            # Validate that the specified 'attribute' exists in 'signingInfo', and that it matches the expected 'extension_value'.
            # If not, raise a ManifestValidationError.
            signing_info_value = man_signing_info.get(attribute)
            if signing_info_value is None:
                raise ManifestValidationError(msg="HandlerManifest.json does not contain attribute 'signingInfo.{0}'".format(attribute),
                                              operation=WALAEventOperation.PackageSigningInfoResult, duration=elapsed_milliseconds(start_time))

            # Comparison should be case-insensitive, because CRP ignores case for extension name.
            if extension_value.lower() != signing_info_value.lower():
                raise ManifestValidationError(msg="expected extension {0} '{1}' does not match downloaded package {0} '{2}'".format(attribute, extension_value, signing_info_value),
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
                                      operation=WALAEventOperation.SignatureValidation, duration=0)


def signature_validation_enabled():
    """
    Returns True if signature validation is enabled in conf file, OpenSSL version supports all validation parameters, and agent is running on a Confidential VM.

    Extension signature validation is currently limited to CVMs for telemetry/preview releases. It will be expanded to all VMs after we gain confidence in the feature.
    TODO: Remove the is_confidential_vm() check once signature validation is supported on all VMs.
    """
    return conf.get_signature_validation_enabled() and openssl_version_supported_for_signature_validation() and ConfidentialVMInfo.is_confidential_vm()


def cleanup_package_with_invalid_signature(package_file):
    try:
        report_validation_event(op=WALAEventOperation.SignatureValidation, level=logger.LogLevel.INFO, name=AGENT_NAME, version=AGENT_VERSION,
                                message="Removing package {0} due to failed signature validation.".format(package_file), duration=0)
        os.remove(package_file)
    except Exception as cleanup_ex:
        report_validation_event(op=WALAEventOperation.SignatureValidation, level=logger.LogLevel.WARNING, name=AGENT_NAME, version=AGENT_VERSION,
                                message="Failed to delete package {0}: {1}".format(package_file, ustr(cleanup_ex)), duration=0)
