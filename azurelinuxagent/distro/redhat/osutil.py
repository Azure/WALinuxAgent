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

import os
import re
import pwd
import shutil
import socket
import array
import struct
import fcntl
import time
import base64
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text, bytebuffer
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.textutil as textutil
from azurelinuxagent.distro.default.osutil import DefaultOSUtil, OSUtilError

class Redhat6xOSUtil(DefaultOSUtil):
    def __init__(self):
        super(Redhat6xOSUtil, self).__init__()
        self.sshd_conf_file_path = '/etc/ssh/sshd_config'
        self.openssl_cmd = '/usr/bin/openssl'
        self.conf_file_path = '/etc/waagent.conf'
        self.selinux=None

    def start_network(self):
        return shellutil.run("/sbin/service networking start", chk_err=False)

    def restart_ssh_service(self):
        return shellutil.run("/sbin/service sshd condrestart", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("/sbin/service waagent stop", chk_err=False)

    def start_agent_service(self):
        return shellutil.run("/sbin/service waagent start", chk_err=False)

    def register_agent_service(self):
        return shellutil.run("chkconfig --add waagent", chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("chkconfig --del waagent", chk_err=False)

    def asn1_to_ssh_rsa(self, pubkey):
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
            return text(b"ssh-rsa " +  keydata_base64 + b"\n", 
                        encoding='utf-8')
        except ImportError as e:
            raise OSUtilError("Failed to load pyasn1.codec.der")

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

    def openssl_to_openssh(self, input_file, output_file):
        pubkey = fileutil.read_file(input_file)
        ssh_rsa_pubkey = self.asn1_to_ssh_rsa(pubkey)
        fileutil.write_file(output_file, ssh_rsa_pubkey)

    #Override
    def get_dhcp_pid(self):
        ret= shellutil.run_get_output("pidof dhclient")
        return ret[1] if ret[0] == 0 else None

    def set_hostname(self, hostname):
        """
        Set /etc/sysconfig/network
        """
        fileutil.update_conf_file('/etc/sysconfig/network',
                                  'HOSTNAME',
                                  'HOSTNAME={0}'.format(hostname))
        shellutil.run("hostname {0}".format(hostname), chk_err=False)

    def set_dhcp_hostname(self, hostname):
        ifname = self.get_if_name()
        filepath = "/etc/sysconfig/network-scripts/ifcfg-{0}".format(ifname)
        fileutil.update_conf_file(filepath,
                                  'DHCP_HOSTNAME',
                                  'DHCP_HOSTNAME={0}'.format(hostname))

class RedhatOSUtil(Redhat6xOSUtil):
    def __init__(self):
        super(RedhatOSUtil, self).__init__()

    def set_hostname(self, hostname):
        """
        Set /etc/hostname
        Unlike redhat 6.x, redhat 7.x will set hostname to /etc/hostname
        """
        DefaultOSUtil.set_hostname(self, hostname)

    def publish_hostname(self, hostname):
        """
        Restart NetworkManager first before publishing hostname
        """
        shellutil.run("service NetworkManager restart")
        super(RedhatOSUtil, self).publish_hostname(hostname)

    def register_agent_service(self):
        return shellutil.run("systemctl enable waagent", chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("systemctl disable waagent", chk_err=False)


