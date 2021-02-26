# Microsoft Azure Linux Agent
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
import errno
import struct
import os.path
import subprocess

from azurelinuxagent.common.future import ustr, bytebuffer
from azurelinuxagent.common.exception import CryptError

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil


DECRYPT_SECRET_CMD = "{0} cms -decrypt -inform DER -inkey {1} -in /dev/stdin"


class CryptUtil(object):
    def __init__(self, openssl_cmd):
        self.openssl_cmd = openssl_cmd

    def gen_transport_cert(self, prv_file, crt_file):
        """
        Create ssl certificate for https communication with endpoint server.
        """
        cmd = [self.openssl_cmd, "req", "-x509", "-nodes", "-subj", "/CN=LinuxTransport", 
            "-days", "730", "-newkey", "rsa:2048", "-keyout", prv_file, "-out", crt_file]
        try:
            shellutil.run_command(cmd)
        except shellutil.CommandError as cmd_err:
            msg = "Failed to create {0} and {1} certificates.\n[stdout]\n{2}\n\n[stderr]\n{3}\n"\
                .format(prv_file, crt_file, cmd_err.stdout, cmd_err.stderr)
            logger.error(msg)

    def get_pubkey_from_prv(self, file_name):
        if not os.path.exists(file_name):
            raise IOError(errno.ENOENT, "File not found", file_name)
        else:
            cmd = [self.openssl_cmd, "rsa", "-in", file_name, "-pubout"]
            pub = shellutil.run_command(cmd, log_error=True)
            return pub

    def get_pubkey_from_crt(self, file_name):
        if not os.path.exists(file_name):
            raise IOError(errno.ENOENT, "File not found", file_name)
        else:
            cmd = [self.openssl_cmd, "x509", "-in", file_name, "-pubkey", "-noout"]
            pub = shellutil.run_command(cmd, log_error=True)
            return pub

    def get_thumbprint_from_crt(self, file_name):
        if not os.path.exists(file_name):
            raise IOError(errno.ENOENT, "File not found", file_name)
        else:
            cmd = [self.openssl_cmd, "x509", "-in", file_name, "-fingerprint", "-noout"]
            thumbprint = shellutil.run_command(cmd)
            thumbprint = thumbprint.rstrip().split('=')[1].replace(':', '').upper()
            return thumbprint

    def decrypt_p7m(self, p7m_file, trans_prv_file, trans_cert_file, pem_file):
        if not os.path.exists(p7m_file):
            raise IOError(errno.ENOENT, "File not found", p7m_file)
        elif not os.path.exists(trans_prv_file):
            raise IOError(errno.ENOENT, "File not found", trans_prv_file)
        else:
            try:
                shellutil.run_pipe([
                    [self.openssl_cmd, "cms", "-decrypt", "-in", p7m_file, "-inkey", trans_prv_file, "-recip", trans_cert_file],
                    [self.openssl_cmd, "pkcs12", "-nodes", "-password", "pass:", "-out", pem_file]])
            except shellutil.CommandError as command_error:
                logger.error("Failed to decrypt {0} (return code: {1})\n[stdout]\n{2}\n[stderr]\n{3}",
                    p7m_file, command_error.returncode, command_error.stdout, command_error.stderr)

    def crt_to_ssh(self, input_file, output_file):
        with open(output_file, "ab") as file_out:
            cmd = ["ssh-keygen", "-i", "-m", "PKCS8", "-f", input_file]

            try:
                shellutil.run_command(cmd, stdout=file_out, log_error=True)
            except shellutil.CommandError:
                pass  # nothing to do; the error is already logged

    def asn1_to_ssh(self, pubkey):
        lines = pubkey.split("\n")
        lines = [x for x in lines if not x.startswith("----")]
        base64_encoded = "".join(lines)
        try:
            #TODO remove pyasn1 dependency
            from pyasn1.codec.der import decoder as der_decoder
            der_encoded = base64.b64decode(base64_encoded)
            der_encoded = der_decoder.decode(der_encoded)[0][1]  # pylint: disable=unsubscriptable-object
            key = der_decoder.decode(self.bits_to_bytes(der_encoded))[0]
            n=key[0]  # pylint: disable=unsubscriptable-object
            e=key[1]  # pylint: disable=unsubscriptable-object
            keydata = bytearray()
            keydata.extend(struct.pack('>I', len("ssh-rsa")))
            keydata.extend(b"ssh-rsa")
            keydata.extend(struct.pack('>I', len(self.num_to_bytes(e))))
            keydata.extend(self.num_to_bytes(e))
            keydata.extend(struct.pack('>I', len(self.num_to_bytes(n)) + 1))
            keydata.extend(b"\0")
            keydata.extend(self.num_to_bytes(n))
            keydata_base64 = base64.b64encode(bytebuffer(keydata))
            return ustr(b"ssh-rsa " +  keydata_base64 + b"\n",
                        encoding='utf-8')
        except ImportError as e:
            raise CryptError("Failed to load pyasn1.codec.der")

    def num_to_bytes(self, num):
        """
        Pack number into bytes.  Retun as string.
        """
        result = bytearray()
        while num:
            result.append(num & 0xFF)
            num >>= 8
        result.reverse()
        return result

    def bits_to_bytes(self, bits):
        """
        Convert an array contains bits, [0,1] to a byte array
        """
        index = 7
        byte_array = bytearray()
        curr = 0
        for bit in bits:
            curr = curr | (bit << index)
            index = index - 1
            if index == -1:
                byte_array.append(curr)
                curr = 0
                index = 7
        return bytes(byte_array)

    def decrypt_secret(self, encrypted_password, private_key):
        try:
            decoded = base64.b64decode(encrypted_password)
            args = DECRYPT_SECRET_CMD.format(self.openssl_cmd, private_key).split(' ')
            output = shellutil.run_command(args, input=decoded, stderr=subprocess.STDOUT, encode_input=False, encode_output=False)
            return output.decode('utf-16')
        except shellutil.CommandError as command_error:
            raise subprocess.CalledProcessError(command_error.returncode, "openssl cms -decrypt", output=command_error.stdout)
        except Exception as e:
            raise CryptError("Error decoding secret", e)
