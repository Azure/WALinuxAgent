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
from azurelinuxagent.common.utils.shellutil import run_command
from azurelinuxagent.common.exception import ExtensionDisallowedError
from azurelinuxagent.common import event
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import ExtensionErrorCodes


def _write_signature_to_file(sig_string, output_file):
    """
    Convert the signature string to a binary, and write to the output file.
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
    :return: True if signature valid, else raise 'ExtensionDisallowedError'
    """

    event.info(WALAEventOperation.SignatureValidation, "Validating signature of package '{0}'".format(package_path))
    signature_file_name = os.path.basename(package_path).rstrip(".zip") + "_signature.pem"
    signature_path = os.path.join(conf.get_lib_dir(), str(signature_file_name))

    try:
        _write_signature_to_file(signature, signature_path)
        microsoft_root_cert_file = conf.get_microsoft_root_certificate_path()

        # Use OpenSSL CLI to verify that the provided signature file correctly signs the package. The verification
        # process checks the certificate chain against the specified root certificate file but does not enforce
        # certificate expiration due to the `-no_check_time` flag. This ensures the signature is valid and originates from a
        # trusted source, regardless of the certificate's expiration status.
        #
        # TODO: implement timestamp token parsing and validate that certificate was valid at time of signing
        command = [
            'openssl', 'cms', '-verify',
            '-binary', '-inform', 'der',  # Signature input format must be DER (binary encoding)
            '-in', signature_path,  # Path to the CMS signature file to be verified
            '-content', package_path,  # Path to the original package that was signed
            '-purpose', 'any',  # Allows verification for any purpose, not restricted to specific uses
            '-CAfile', microsoft_root_cert_file,  # Path to the trusted root certificate file used for verification
            '-no_check_time'  # Skips checking whether the certificate is expired
        ]
        run_command(command, encode_output=False)
        os.remove(signature_path)
        return True

    except Exception as ex:
        ex_info = getattr(ex, 'stderr', ex)
        msg = "Failed to validate signature of package '{0}'. Error details:\n{1}".format(package_path, ex_info)
        raise ExtensionDisallowedError(msg=msg, code=ExtensionErrorCodes.PluginPackageExtractionFailed)