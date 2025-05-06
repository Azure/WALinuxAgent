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
from azurelinuxagent.common.future import ustr, UTC
from azurelinuxagent.common.event import add_event, WALAEventOperation, elapsed_milliseconds


# This file tracks the state of signature and manifest validation for the package. If the file exists, signature and
# manifest have both been successfully validated.
_PACKAGE_VALIDATION_STATE_FILE = "package_validated"

# Signature validation requires OpenSSL version 1.1.0 or later. The 'no_check_time' flag used for the 'openssl cms -verify'
# command is not supported on older versions.
_MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION = FlexibleVersion("1.1.0")

# The 'encodedSignature' property is only supported on newer versions of HGAP. Before sending telemetry that signature
# is missing in fast track goal states, check that HGAP version supports signature.
_MIN_HGAP_VERSION_FOR_EXT_SIGNATURE_VALIDATION = FlexibleVersion("1.0.8.159")


class PackageValidationError(AgentError):
    """
    Error raised when validation fails for a package.
    """
    def __init__(self, msg=None, inner=None, code=-1):
        super(PackageValidationError, self).__init__(msg, inner)
        self.code = code


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


def validate_signature(package_path, signature, package_full_name):
    """
    Validates signature of provided package using OpenSSL CLI. The verification checks the signature against a trusted
    Microsoft root certificate but does not enforce certificate expiration.
    :param package_path: path to package file being validated
    :param signature: base64-encoded signature string
    :param package_full_name: string in the format "Name-Version", only used for telemetry purposes
    :raises SignatureValidationError: if signature validation fails
    """

    start_time = datetime.datetime.now(UTC)
    signature_file_name = os.path.basename(package_path) + "_signature.pem"
    signature_path = os.path.join(conf.get_lib_dir(), str(signature_file_name))
    name, version = package_full_name.split('-')

    try:
        add_event(op=WALAEventOperation.SignatureValidation, message="Validating signature for package '{0}'".format(package_full_name),
                  name=name, version=version, is_success=True, log_event=False)
        _write_signature_to_file(signature, signature_path)
        microsoft_root_cert_file = get_microsoft_signing_certificate_path()

        if not os.path.isfile(microsoft_root_cert_file):
            raise Exception(
                "signing certificate was not found at expected location ('{0}'). Try restarting the agent, or see log ('{1}') for additional details."
                .format(microsoft_root_cert_file, conf.get_agent_log_file())
            )

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
        add_event(op=WALAEventOperation.PackageSignatureResult, message="Successfully validated signature for package '{0}'".format(package_full_name),
                  name=name, version=version, is_success=True, duration=elapsed_milliseconds(start_time), log_event=False)

    except CommandError as ex:
        msg = "Signature validation failed for package '{0}'. \nReturn code: {1}\nError details:\n{2}".format(package_full_name, ex.returncode, ex.stderr)
        add_event(op=WALAEventOperation.PackageSignatureResult, message="[WARNING] " + msg, name=name, version=version,
                  is_success=False, duration=elapsed_milliseconds(start_time), log_event=False)
        raise SignatureValidationError(msg)

    except Exception as ex:
        msg = "Signature validation failed for package '{0}'. Error: {1}".format(package_full_name, ustr(ex))
        add_event(op=WALAEventOperation.PackageSignatureResult, message="[WARNING] " + msg, name=name, version=version,
                  is_success=False, duration=elapsed_milliseconds(start_time), log_event=False)
        raise SignatureValidationError(msg)

    finally:
        if os.path.isfile(signature_path):
            os.remove(signature_path)


def validate_handler_manifest_signing_info(manifest, ext_handler):
    """
    For signed extensions, the handler manifest includes a "signingInfo" section that specifies
    the type, publisher, and version of the extension. During signature validation (after extracting zip package),
    we check these attributes against the expected values for the extension. If there is a mismatch, raise an error.

    :param manifest: HandlerManifest object
    :param ext_handler: Extension object
    :raises ManifestValidationError: if handler manifest validation fails
    """
    add_event(op=WALAEventOperation.SignatureValidation, message="Validating handler manifest 'signingInfo' of extension '{0}'".format(ext_handler), name=ext_handler.name, version=ext_handler.version, is_success=True, log_event=False)
    start_time = datetime.datetime.now(UTC)

    # Check that 'signingInfo' exists in the manifest structure
    man_signing_info = manifest.data.get("signingInfo")
    if man_signing_info is None:
        msg = "HandlerManifest.json does not contain 'signingInfo'"
        add_event(op=WALAEventOperation.PackageSigningInfoResult, message=msg, name=ext_handler.name, version=ext_handler.version, is_success=False, duration=elapsed_milliseconds(start_time), log_event=False)
        raise ManifestValidationError(msg=msg)

    def validate_attribute(attribute, extension_value):
        # Validate that the specified 'attribute' exists in 'signingInfo', and that it matches the expected 'extension_value'.
        # If not, report telemetry with is_success=False and raise a ManifestValidationError.
        signing_info_value = man_signing_info.get(attribute)
        if signing_info_value is None:
            message = "HandlerManifest.json does not contain attribute 'signingInfo.{0}'".format(attribute)
            add_event(op=WALAEventOperation.PackageSigningInfoResult, message=message, name=ext_handler.name, version=ext_handler.version, is_success=False, duration=elapsed_milliseconds(start_time), log_event=False)
            raise ManifestValidationError(msg=message)

        # Comparison should be case-insensitive, because CRP ignores case for extension name.
        if extension_value.lower() != signing_info_value.lower():
            message = "expected extension {0} '{1}' does not match downloaded package {0} '{2}'".format(attribute, extension_value, signing_info_value)
            add_event(op=WALAEventOperation.PackageSigningInfoResult, message=message, name=ext_handler.name, version=ext_handler.version, is_success=False, duration=elapsed_milliseconds(start_time), log_event=False)
            raise ManifestValidationError(msg=message)

    # Compare extension attributes against the attributes specified in 'signingInfo'
    ext_publisher, ext_type = ext_handler.name.rsplit(".", 1)
    validate_attribute(attribute="type", extension_value=ext_type)
    validate_attribute(attribute="publisher", extension_value=ext_publisher)
    validate_attribute(attribute="version", extension_value=ext_handler.version)

    add_event(op=WALAEventOperation.PackageSigningInfoResult, message="Successfully validated handler manifest 'signingInfo' for extension '{0}'".format(ext_handler),
              name=ext_handler.name, version=ext_handler.version, is_success=True, duration=elapsed_milliseconds(start_time), log_event=False)


def save_signature_validation_state(target_dir):
    """
    Create signature validation state file in the target directory. Existence of file indicates that signature and manifest
    were successfully validated for the package.
    """
    validation_state_file = os.path.join(target_dir, _PACKAGE_VALIDATION_STATE_FILE)
    try:
        with open(validation_state_file, 'w'):
            pass
    except Exception as e:
        msg = "Error saving signature validation state file ({0}): {1}".format(validation_state_file, e)
        raise PackageValidationError(msg=msg)


def signature_has_been_validated(target_dir):
    """
    Returns True if signature validation state file exists in the specified directory.
    Presence of the file indicates that the package signature was successfully validated.
    """
    validation_state_file = os.path.join(target_dir, _PACKAGE_VALIDATION_STATE_FILE)
    return os.path.exists(validation_state_file)


def should_validate_signature():
    """
    Returns True if signature validation is enabled in conf file and OpenSSL version supports all validation parameters.
    """
    return conf.get_signature_validation_enabled() and openssl_version_supported_for_signature_validation()
