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

import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.logger as logger
from azurelinuxagent.distro.default.osutil import DefaultOSUtil
from azurelinuxagent.exception import OSUtilError


class FreeBSDOSUtil(DefaultOSUtil):
    def __init__(self):
        super(FreeBSDOSUtil, self).__init__()

    def get_if_mac(self, ifname):
        data = self._get_net_info()
        if data[0] == ifname:
            return data[2].replace(':', '').upper()
        return None

    def get_first_if(self):
        return self._get_net_info()[:2]

    def route_add(self, net, mask, gateway):
        cmd = 'route add {0} {1} {2}'.format(net, gateway, mask)
        return shellutil.run(cmd, chk_err=False)

    def is_missing_default_route(self):
        routes = shellutil.run_get_output("netstat -rn4")[1]
        for route in routes.split("\n"):
            if route.startswith("0.0.0.0 ") or route.startswith("default "):
                return False
        return True

    def set_route_for_dhcp_broadcast(self, ifname):
        return shellutil.run("route add 255.255.255.255 0.0.0.0 -ifp {0}".format(ifname), chk_err=False)

    def remove_route_for_dhcp_broadcast(self, ifname):
        shellutil.run("route delete 255.255.255.255", chk_err=False)

    @staticmethod
    def _get_net_info():
        """
        There is no SIOCGIFCONF
        on freeBSD - just parse ifconfig.
        Returns strings: iface, inet4_addr, and mac
        or 'None,None,None' if unable to parse.
        We will sleep and retry as the network must be up.
        """
        iface = ''
        inet = ''
        mac = ''

        err, output = shellutil.run_get_output('ifconfig -l ether', chk_err=False)
        if err:
            raise OSUtilError("Can't find ether interface:{0}".format(output))
        ifaces = output.split()
        if not ifaces:
            raise OSUtilError("Can't find ether interface.")
        iface = ifaces[0]

        err, output = shellutil.run_get_output('ifconfig ' + iface, chk_err=False)
        if err:
            raise OSUtilError("Can't get info for interface:{0}".format(iface))

        for line in output.split('\n'):
            if line.find('inet ') != -1:
                inet = line.split()[1]
            elif line.find('ether ') != -1:
                mac = line.split()[1]
        logger.verb("Interface info: ({0},{1},{2})", iface, inet, mac)

        return iface, inet, mac
