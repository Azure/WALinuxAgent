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

from azurelinuxagent.common import conf
from azurelinuxagent.common.utils.shellutil import run_command, CommandError
from azurelinuxagent.common.exception import ExtensionError
from azurelinuxagent.common import event
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import ExtensionErrorCodes
from azurelinuxagent.ga.signing_certificate_util import get_microsoft_signing_certificate_path


class SignatureValidationError(ExtensionError):
    """
    Error raised when signature validation fails for an extension.
    """


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

    event.info(WALAEventOperation.SignatureValidation, "Validating signature of package '{0}'".format(package_path))
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
