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

from azurelinuxagent.distro.default.osutil import DefaultOSUtil


class FreeBSDOSUtil(DefaultOSUtil):
    def __init__(self):
        super(FreeBSDOSUtil, self).__init__()

    def get_mac_addr(self):
        
        return 1

    @staticmethod
    def _get_net_info():
        """
        There is no SIOCGIFCONF
        on freeBSD - just parse ifconfig.
        Returns strings: iface, inet4_addr, and mac
        or 'None,None,None' if unable to parse.
        We will sleep and retry as the network must be up.
        """
        code,output=RunGetOutput("ifconfig",chk_err=False)
        Log(output)
        retries=10
        cmd='ifconfig | grep -A2 -B2 ether | grep -B3 inet | grep -A4 UP '
        code=1

        while code > 0 :
            if code > 0 and retries == 0:
                Error("GetFreeBSDEthernetInfo - Failed to detect ethernet interface")
                return None, None, None
            code,output=RunGetOutput(cmd,chk_err=False)
            retries-=1
            if code > 0 and retries > 0 :
                Log("GetFreeBSDEthernetInfo - Error: retry ethernet detection " + str(retries))
                if retries == 9 :
                    c,o=RunGetOutput("ifconfig | grep -A1 -B2 ether",chk_err=False)
                    if c == 0:
                        t=o.replace('\n',' ')
                        t=t.split()
                        i=t[0][:-1]
                        Log(RunGetOutput('id')[1])
                        Run('dhclient '+i)
                time.sleep(10)

        j=output.replace('\n',' ')
        j=j.split()
        iface=j[0][:-1]

        for i in range(len(j)):
            if j[i] == 'inet' :
                inet=j[i+1]
            elif j[i] == 'ether' :
                mac=j[i+1]

        return iface, inet, mac

