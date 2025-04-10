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
from azurelinuxagent.common.exception import ExtensionError, AgentError
from azurelinuxagent.common import event
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import ExtensionErrorCodes
from azurelinuxagent.ga.signing_certificate_util import get_microsoft_signing_certificate_path
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion


# Signature validation requires OpenSSL version 1.1.0 or later. The 'no_check_time' flag used for the 'openssl cms -verify'
# command is not supported on older versions.
_MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION = FlexibleVersion("1.1.0")


class SignatureValidationError(ExtensionError):
    """
    Error raised when signature validation fails for an extension.
    """


class HandlerManifestError(ExtensionError):
    """
    Error raised when handler manifest 'signingInfo' validation fails for an extension.
    """


class OpenSSLVersionError(AgentError):
    """
    Error raised when OpenSSL version is less than the supported version.
    """


def _get_openssl_version():
    try:
        command = [conf.get_openssl_cmd(), 'version']
        output = run_command(command)
        if output is None:
            raise SignatureValidationError(msg="Failed to get OpenSSL version. '{0}' returned no output.".format(command))

        match = re.match(r"OpenSSL (\d+\.\d+\.\d+)", output)
        if match is not None:
            return match.group(1)
        else:
            raise SignatureValidationError(msg="Failed to get OpenSSL version. '{0}' returned output: {1}".format(command, output))

    except CommandError as ex:
        raise SignatureValidationError(msg="Failed to get OpenSSL version. Error: {0}".format(ex.stderr))


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

    # Validate that OpenSSL meets minimum version requirement
    openssl_version = _get_openssl_version()
    if FlexibleVersion(openssl_version) < _MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION:
        msg = ("Signature validation requires OpenSSL version {0}, but the current version is {1}. "
               "To validate signature, please upgrade OpenSSL to version {0} or higher.").format(
            _MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION, openssl_version)
        raise OpenSSLVersionError(msg=msg)

    event.info(op=WALAEventOperation.SignatureValidation, fmt="Validating signature of package '{0}'".format(package_path))
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

    except CommandError as ex:
        msg = "Signature validation failed for package '{0}'. \nReturn code: {1}\nError details:\n{2}".format(package_path, ex.returncode, ex.stderr)
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
    event.info(op=WALAEventOperation.SignatureValidation, fmt="Validating handler manifest 'signingInfo' of package '{0}'".format(ext_handler.name))

    man_signing_info = manifest.data.get("signingInfo")
    if man_signing_info is None:
        raise HandlerManifestError(msg="HandlerManifest.json does not contain 'signingInfo'", code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    # Validate extension name (publisher + type). This comparison should be case-insensitive.
    gs_publisher, gs_type = ext_handler.name.rsplit(".", 1)

    signing_info_type = man_signing_info.get("type")
    if signing_info_type is None:
        raise HandlerManifestError(msg="HandlerManifest.json does not contain attribute 'signingInfo.type'", code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    if signing_info_type.lower() != gs_type.lower():
        raise HandlerManifestError(msg="expected extension type '{0}' does not match downloaded package type '{1}' (specified in HandlerManifest.json)".format(
                                   gs_type, signing_info_type), code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    signing_info_publisher = man_signing_info.get("publisher")
    if signing_info_publisher is None:
        raise HandlerManifestError(msg="HandlerManifest.json does not contain attribute 'signingInfo.publisher'", code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    if signing_info_publisher.lower() != gs_publisher.lower():
        raise HandlerManifestError(msg="expected extension publisher '{0}' does not match downloaded package publisher '{1}' (specified in HandlerManifest.json)".format(
                                   gs_publisher, signing_info_publisher), code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    # Validate extension version
    signing_info_version = man_signing_info.get("version")
    if signing_info_version is None:
        raise HandlerManifestError(msg="HandlerManifest.json does not contain attribute 'signingInfo.version'", code=ExtensionErrorCodes.PluginInstallProcessingFailed)

    if signing_info_version != ext_handler.version:
        raise HandlerManifestError(msg="expected extension version '{0}' does not match downloaded package version '{1}' (specified in HandlerManifest.json)".format(ext_handler.version, signing_info_version),
                                   code=ExtensionErrorCodes.PluginInstallProcessingFailed)