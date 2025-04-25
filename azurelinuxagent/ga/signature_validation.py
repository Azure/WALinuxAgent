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
import os
import re

from azurelinuxagent.common import conf
from azurelinuxagent.common.utils.shellutil import run_command, CommandError
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common import logger
from azurelinuxagent.ga.signing_certificate_util import get_microsoft_signing_certificate_path
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.future import ustr


# This file tracks the state of signature validation for the package. If the file exists, signature has been validated.
_PACKAGE_VALIDATION_STATE_FILE = "package_validated"

# Signature validation requires OpenSSL version 1.1.0 or later. The 'no_check_time' flag used for the 'openssl cms -verify'
# command is not supported on older versions.
_MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION = FlexibleVersion("1.1.0")


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


def validate_signature(package_path, signature):
    """
    Validates signature of provided package using OpenSSL CLI. The verification checks the signature against a trusted
    Microsoft root certificate but does not enforce certificate expiration.
    :param package_path: path to package file being validated
    :param signature: base64-encoded signature string
    :raises SignatureValidationError: if signature validation fails
    """
    signature_file_name = os.path.basename(package_path) + "_signature.pem"
    signature_path = os.path.join(conf.get_lib_dir(), str(signature_file_name))

    try:
        _write_signature_to_file(signature, signature_path)
        microsoft_root_cert_file = get_microsoft_signing_certificate_path()

        if not os.path.isfile(microsoft_root_cert_file):
            msg = (
                "Signature validation failed for package '{0}': "
                "signing certificate was not found at expected location ('{1}'). "
                "Try restarting the agent, or see log ('{2}') for additional details."
            ).format(package_path, microsoft_root_cert_file, conf.get_agent_log_file())
            raise SignatureValidationError(msg=msg)

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

    except CommandError as ex:
        msg = "Signature validation failed for package '{0}'. \nReturn code: {1}\nError details:\n{2}".format(package_path, ex.returncode, ex.stderr)
        raise SignatureValidationError(msg=msg)

    except Exception as ex:
        msg = "Signature validation failed for package '{0}'. Error: {1}".format(package_path, ustr(ex))
        raise SignatureValidationError(msg=msg)

    finally:
        if os.path.isfile(signature_path):
            os.remove(signature_path)


def validate_handler_manifest_signing_info(manifest, ext_handler):
    """
    For signed extensions, the handler manifest includes a "signingInfo" section that specifies
    the type, publisher, and version of the extension. During signature validation (after extracting zip package),
    we check these attributes against the values in the goal state. If there is a mismatch, raise an error.

    :param manifest: HandlerManifest object
    :param ext_handler: Extension object
    :raises ManifestValidationError: if handler manifest validation fails
    """
    man_signing_info = manifest.data.get("signingInfo")
    if man_signing_info is None:
        msg = "HandlerManifest.json does not contain 'signingInfo'"
        raise ManifestValidationError(msg=msg)

    # Validate extension name (publisher + type). This comparison should be case-insensitive, because CRP ignores case for extension name.
    ext_publisher, ext_type = ext_handler.name.rsplit(".", 1)

    signing_info_type = man_signing_info.get("type")
    if signing_info_type is None:
        msg = "HandlerManifest.json does not contain attribute 'signingInfo.type'"
        raise ManifestValidationError(msg=msg)

    if signing_info_type.lower() != ext_type.lower():
        msg = "expected extension type '{0}' does not match downloaded package type '{1}'".format(ext_type, signing_info_type)
        raise ManifestValidationError(msg=msg)

    signing_info_publisher = man_signing_info.get("publisher")
    if signing_info_publisher is None:
        msg = "HandlerManifest.json does not contain attribute 'signingInfo.publisher'"
        raise ManifestValidationError(msg=msg)

    if signing_info_publisher.lower() != ext_publisher.lower():
        msg = "expected extension publisher '{0}' does not match downloaded package publisher '{1}' (specified in HandlerManifest.json)".format(
            ext_publisher, signing_info_publisher)
        raise ManifestValidationError(msg=msg)

    # Validate extension version
    signing_info_version = man_signing_info.get("version")
    if signing_info_version is None:
        msg = "HandlerManifest.json does not contain attribute 'signingInfo.version'"
        raise ManifestValidationError(msg=msg)

    if signing_info_version != ext_handler.version:
        msg = "expected extension version '{0}' does not match downloaded package version '{1}' (specified in HandlerManifest.json)".format(
            ext_handler.version, signing_info_version)
        raise ManifestValidationError(msg=msg)


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
