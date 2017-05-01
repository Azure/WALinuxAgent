# Microsoft Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#

import base64
import struct
from azurelinuxagent.common.future import ustr, bytebuffer
from azurelinuxagent.common.exception import CryptError
import azurelinuxagent.common.utils.shellutil as shellutil

class CryptUtil(object):
    def __init__(self, openssl_cmd):
        self.openssl_cmd = openssl_cmd

    def gen_transport_cert(self, prv_file, crt_file):
        """
        Create ssl certificate for https communication with endpoint server.
        """
        cmd = ("{0} req -x509 -nodes -subj /CN=LinuxTransport -days 730 "
               "-newkey rsa:2048 -keyout {1} "
               "-out {2}").format(self.openssl_cmd, prv_file, crt_file)
        shellutil.run(cmd)

    def get_pubkey_from_prv(self, file_name):
        cmd = "{0} rsa -in {1} -pubout 2>/dev/null".format(self.openssl_cmd, 
                                                           file_name)
        pub = shellutil.run_get_output(cmd)[1]
        return pub

    def get_pubkey_from_crt(self, file_name):
        cmd = "{0} x509 -in {1} -pubkey -noout".format(self.openssl_cmd, 
                                                       file_name)
        pub = shellutil.run_get_output(cmd)[1]
        return pub

    def get_thumbprint_from_crt(self, file_name):
        cmd="{0} x509 -in {1} -fingerprint -noout".format(self.openssl_cmd, 
                                                          file_name)
        thumbprint = shellutil.run_get_output(cmd)[1]
        thumbprint = thumbprint.rstrip().split('=')[1].replace(':', '').upper()
        return thumbprint

    def decrypt_p7m(self, p7m_file, trans_prv_file, trans_cert_file, pem_file):
        cmd = ("{0} cms -decrypt -in {1} -inkey {2} -recip {3} "
               "| {4} pkcs12 -nodes -password pass: -out {5}"
               "").format(self.openssl_cmd, p7m_file, trans_prv_file, 
                          trans_cert_file, self.openssl_cmd, pem_file)
        shellutil.run(cmd)

    def crt_to_ssh(self, input_file, output_file):
        shellutil.run("ssh-keygen -i -m PKCS8 -f {0} >> {1}".format(input_file,
                                                                    output_file))

    def asn1_to_ssh(self, pubkey):
        lines = pubkey.split("\n")
        lines = [x for x in lines if not x.startswith("----")]
        base64_encoded = "".join(lines)
        try:
            #TODO remove pyasn1 dependency
            from pyasn1.codec.der import decoder as der_decoder
            der_encoded = base64.b64decode(base64_encoded)
            der_encoded = der_decoder.decode(der_encoded)[0][1]
            key = der_decoder.decode(self.bits_to_bytes(der_encoded))[0]
            n=key[0]
            e=key[1]
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

