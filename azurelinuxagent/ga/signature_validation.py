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
from azurelinuxagent.common import event
from azurelinuxagent.common import logger
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import ExtensionErrorCodes
from azurelinuxagent.ga.signing_certificate_util import get_microsoft_signing_certificate_path
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion


# This file tracks the state of signature validation for the package. If the file exists, signature has been validated.
_SIGNATURE_VALIDATION_STATE_FILE = "signature_validated"

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
    Error raised when signature validation fails for an extension.
    """


class ManifestValidationError(PackageValidationError):
    """
    Error raised when handler manifest 'signingInfo' validation fails for an extension.
    """


def _get_openssl_version():
    """
    Calls 'openssl version' via subprocess and extracts the version from its output.
    Raises SignatureValidationError if the version cannot be found, extracted, or if the command fails.
    Returns OpenSSL version string in major.minor.patch format. Any letter suffix is ignored (e.g., '1.1.1f' and '1.1.1wa-fips' will both return '1.1.1').
    """
    try:
        command = [conf.get_openssl_cmd(), 'version']
        output = run_command(command)
        if output is None:
            msg = "Failed to get OpenSSL version. '{0}' returned no output.".format(command)
            event.error(op=WALAEventOperation.SignatureValidation, fmt=msg)
            raise PackageValidationError(msg=msg)

        match = re.search(r"OpenSSL (\d+\.\d+\.\d+)", output)
        if match is not None:
            return match.group(1)
        else:
            msg = "Failed to get OpenSSL version. '{0}' returned output: {1}".format(command, output)
            event.error(op=WALAEventOperation.SignatureValidation, fmt=msg)
            raise PackageValidationError(msg=msg)

    except CommandError as ex:
        msg = "Failed to get OpenSSL version. Error: {0}".format(ex.stderr)
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg)
        raise PackageValidationError(msg=msg)


def openssl_version_supported_for_signature_validation():
    openssl_version = _get_openssl_version()
    if FlexibleVersion(openssl_version) < _MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION:
        msg = ("Signature validation requires OpenSSL version {0}, but the current version is {1}. "
               "To validate signature, please upgrade OpenSSL to version {0} or higher.").format(
            _MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION, openssl_version)
        logger.warn(msg)
        return False
    return True


def _write_signature_to_file(sig_string, output_file):
    """
    Convert the base64-encoded signature string to binary, and write to the output file.
    """
    binary_signature = base64.b64decode(sig_string.strip())
    with open(output_file, "wb") as f:
        f.write(binary_signature)


def validate_signature(package_path, signature, package_name=None, package_version=None):
    """
    Validates signature of provided package using OpenSSL CLI. The verification checks the signature against a trusted
    Microsoft root certificate but does not enforce certificate expiration.
    :param package_path: path to package file being validated
    :param signature: base64-encoded signature string
    :param package_name: name of package used only for telemetry
    :param package_version: package version only used for telemetry
    :raises SignatureValidationError: if signature validation fails
    """
    event.info(op=WALAEventOperation.SignatureValidation, fmt="Validating signature of package '{0}'".format(package_path),
               name=package_name, version=package_version)
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
            event.error(op=WALAEventOperation.SignatureValidation, fmt=msg, name=package_name, version=package_version)
            raise SignatureValidationError(msg=msg, code=ExtensionErrorCodes.PluginPackageExtractionFailed)

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
        event.info(op=WALAEventOperation.SignatureValidation, fmt="Successfully validated signature for package '{0}'.".format(package_path),
                   name=package_name, version=package_version)

    except CommandError as ex:
        msg = "Signature validation failed for package '{0}'. \nReturn code: {1}\nError details:\n{2}".format(package_path, ex.returncode, ex.stderr)
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg, name=package_name, version=package_version)
        raise SignatureValidationError(msg=msg, code=ExtensionErrorCodes.PluginPackageExtractionFailed)

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
    :raises SignatureValidationError: if handler manifest validation fails
    """
    event.info(op=WALAEventOperation.SignatureValidation, fmt="Validating handler manifest 'signingInfo' of package '{0}'".format(ext_handler.name),
               name=ext_handler.name, version=ext_handler.version)

    man_signing_info = manifest.data.get("signingInfo")
    if man_signing_info is None:
        msg = "HandlerManifest.json does not contain 'signingInfo'"
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg, name=ext_handler.name, version=ext_handler.version)
        raise ManifestValidationError(msg=msg, code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    # Validate extension name (publisher + type). This comparison should be case-insensitive, because CRP ignores case for extension name.
    gs_publisher, gs_type = ext_handler.name.rsplit(".", 1)

    signing_info_type = man_signing_info.get("type")
    if signing_info_type is None:
        msg = "HandlerManifest.json does not contain attribute 'signingInfo.type'"
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg, name=ext_handler.name, version=ext_handler.version)
        raise ManifestValidationError(msg=msg, code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    if signing_info_type.lower() != gs_type.lower():
        msg = "expected extension type '{0}' does not match downloaded package type '{1}'".format(gs_type, signing_info_type)
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg, name=ext_handler.name, version=ext_handler.version)
        raise ManifestValidationError(msg=msg, code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    signing_info_publisher = man_signing_info.get("publisher")
    if signing_info_publisher is None:
        msg = "HandlerManifest.json does not contain attribute 'signingInfo.publisher'"
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg, name=ext_handler.name, version=ext_handler.version)
        raise ManifestValidationError(msg=msg, code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    if signing_info_publisher.lower() != gs_publisher.lower():
        msg = "expected extension publisher '{0}' does not match downloaded package publisher '{1}' (specified in HandlerManifest.json)".format(
            gs_publisher, signing_info_publisher)
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg, name=ext_handler.name, version=ext_handler.version)
        raise ManifestValidationError(msg=msg, code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    # Validate extension version
    signing_info_version = man_signing_info.get("version")
    if signing_info_version is None:
        msg = "HandlerManifest.json does not contain attribute 'signingInfo.version'"
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg, name=ext_handler.name, version=ext_handler.version)
        raise ManifestValidationError(msg=msg, code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    if signing_info_version != ext_handler.version:
        msg = "expected extension version '{0}' does not match downloaded package version '{1}' (specified in HandlerManifest.json)".format(
            ext_handler.version, signing_info_version)
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg, name=ext_handler.name, version=ext_handler.version)
        raise ManifestValidationError(msg=msg, code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    event.info(op=WALAEventOperation.SignatureValidation, fmt="Successfully validated handler manifest 'signingInfo' for extension '{0}'".format(ext_handler),
               name=ext_handler.name, version=ext_handler.version)


def save_signature_validation_state(target_dir):
    """
    Create signature validation state file in the target directory. Existence of file indicates that signature and manifest
    were successfully validated for the package.
    """
    validation_state_file = os.path.join(target_dir, _SIGNATURE_VALIDATION_STATE_FILE)
    try:
        with open(validation_state_file, 'w'):
            pass
    except Exception as e:
        msg = "Error saving signature validation state file ({0}): {1}".format(validation_state_file, e)
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg)


def signature_has_been_validated(target_dir):
    """
    Returns True if signature validation state file exists in the specified directory.
    Presence of the file indicates that the package signature was successfully validated.
    """
    validation_state_file = os.path.join(target_dir, _SIGNATURE_VALIDATION_STATE_FILE)
    return os.path.exists(validation_state_file)