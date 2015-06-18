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
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.textutil as textutil
from azurelinuxagent.distro.default.osutil import OSUtil, OSUtilError

class Redhat6xOSUtil(OSUtil):
    def __init__(self):
        super(Redhat6xOSUtil, self).__init__()
        self.sshdConfigPath = '/etc/ssh/sshd_config'
        self.opensslCmd = '/usr/bin/openssl'
        self.configPath = '/etc/waagent.conf'
        self.selinux=None

    def StartNetwork(self):
        return shellutil.Run("/sbin/service networking start", chk_err=False)

    def RestartSshService(self):
        return shellutil.Run("/sbin/service sshd condrestart", chk_err=False)

    def StopAgentService(self):
        return shellutil.Run("/sbin/service waagent stop", chk_err=False)

    def StartAgentService(self):
        return shellutil.Run("/sbin/service waagent start", chk_err=False)

    def RsaPublicKeyToSshRsa(self, publicKey):
        lines = publicKey.split("\n")
        lines = filter(lambda x : not x.startswith("----"), lines)
        base64Encoded = "".join(lines)
        try:
            #TODO remove pyasn1 dependency
            from pyasn1.codec.der import decoder as der_decoder
            derEncoded = base64.b64decode(base64Encoded)
            derEncoded = der_decoder.decode(derEncoded)[0][1]
            k = der_decoder.decode(textutil.BitsToString(derEncoded))[0]
            n=k[0]
            e=k[1]
            keydata=""
            keydata += struct.pack('>I',len("ssh-rsa"))
            keydata += "ssh-rsa"
            keydata += struct.pack('>I',len(textutil.NumberToBytes(e)))
            keydata += textutil.NumberToBytes(e)
            keydata += struct.pack('>I',len(textutil.NumberToBytes(n)) + 1)
            keydata += "\0"
            keydata += textutil.NumberToBytes(n)
            return "ssh-rsa " + base64.b64encode(keydata) + "\n"
        except ImportError as e:
            raise OSUtilError("Failed to load pyasn1.codec.der")
        except Exception as e:
            raise OSUtilError(("Failed to convert public key: {0} {1}"
                               "").format(type(e).__name__, e))

    def OpenSslToOpenSsh(self, inputFile, outputFile):
        publicKey = fileutil.GetFileContents(inputFile)
        sshRsaPublicKey = self.RsaPublicKeyToSshRsa(publicKey)
        fileutil.SetFileContents(outputFile, sshRsaPublicKey)

    #Override
    def GetDhcpProcessId(self):
        ret= shellutil.RunGetOutput("pidof dhclient")
        return ret[1] if ret[0] == 0 else None

class RedhatOSUtil(Redhat6xOSUtil):
    def __init__(self):
        super(RedhatOSUtil, self).__init__()

    def SetHostname(self, hostname):
        super(RedhatOSUtil, self).SetHostname(hostname)
        fileutil.UpdateConfigFile('/etc/sysconfig/network', 
                                  'HOSTNAME',
                                  'HOSTNAME={0}'.format(hostname))
    
    def SetDhcpHostname(self, hostname):
        ifname = self.GetInterfaceName()
        filepath = "/etc/sysconfig/network-scripts/ifcfg-{0}".format(ifname)
        fileutil.UpdateConfigFile(filepath,
                                  'DHCP_HOSTNAME',
                                  'DHCP_HOSTNAME={0}'.format(hostname))


