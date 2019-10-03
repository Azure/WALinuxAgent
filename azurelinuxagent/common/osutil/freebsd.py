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

import socket
import struct
import binascii
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.utils.networkutil import RouteEntry
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.future import ustr

class FreeBSDOSUtil(DefaultOSUtil):

    def __init__(self):
        super(FreeBSDOSUtil, self).__init__()
        self._scsi_disks_timeout_set = False
        self.jit_enabled = True

    def set_hostname(self, hostname):
        rc_file_path = '/etc/rc.conf'
        conf_file = fileutil.read_file(rc_file_path).split("\n")
        textutil.set_ini_config(conf_file, "hostname", hostname)
        fileutil.write_file(rc_file_path, "\n".join(conf_file))
        shellutil.run("hostname {0}".format(hostname), chk_err=False)

    def restart_ssh_service(self):
        return shellutil.run('service sshd restart', chk_err=False)

    def useradd(self, username, expiration=None, comment=None):
        """
        Create user account with 'username'
        """
        userentry = self.get_userentry(username)
        if userentry is not None:
            logger.warn("User {0} already exists, skip useradd", username)
            return
        if expiration is not None:
            cmd = "pw useradd {0} -e {1} -m".format(username, expiration)
        else:
            cmd = "pw useradd {0} -m".format(username)
        if comment is not None:
            cmd += " -c {0}".format(comment)
        retcode, out = shellutil.run_get_output(cmd)
        if retcode != 0:
            raise OSUtilError(("Failed to create user account:{0}, "
                               "retcode:{1}, "
                               "output:{2}").format(username, retcode, out))

    def del_account(self, username):
        if self.is_sys_user(username):
            logger.error("{0} is a system user. Will not delete it.", username)
        shellutil.run('> /var/run/utx.active')
        shellutil.run('rmuser -y ' + username)
        self.conf_sudoer(username, remove=True)

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        if self.is_sys_user(username):
            raise OSUtilError(("User {0} is a system user, "
                               "will not set password.").format(username))
        passwd_hash = textutil.gen_password_hash(password, crypt_id, salt_len)
        cmd = "echo '{0}'|pw usermod {1} -H 0 ".format(passwd_hash, username)
        ret, output = shellutil.run_get_output(cmd, log_cmd=False)
        if ret != 0:
            raise OSUtilError(("Failed to set password for {0}: {1}"
                               "").format(username, output))

    def del_root_password(self):
        err = shellutil.run('pw usermod root -h -')
        if err:
            raise OSUtilError("Failed to delete root password: Failed to update password database.")

    def get_if_mac(self, ifname):
        data = self._get_net_info()
        if data[0] == ifname:
            return data[2].replace(':', '').upper()
        return None

    def get_first_if(self):
        return self._get_net_info()[:2]

    @staticmethod
    def read_route_table():
        """
        Return a list of strings comprising the route table, including column headers. Each line is stripped of leading
        or trailing whitespace but is otherwise unmolested.

        :return: Entries in the route priority table from `netstat -rn`
        :rtype: list(str)
        """
        linux_style_route_file = [ "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT" ]

        cmd = "netstat -rn"
        ret, netstat_output = shellutil.run_get_output(cmd)
        if ret:
            raise OSUtilError("Cannot read route table [{0}]".format(netstat_output))
        netstat_output = netstat_output.split("\n")
        if len(netstat_output) < 3:
            return linux_style_route_file
        netstat_output = netstat_output[3:]
        # Parse the Netstat -RN header line
        n_columns = 0
        column_index = {}
        header_line = netstat_output[0]
        for header in [h for h in header_line.split() if len(h) > 0]:
            column_index[header] = n_columns
            n_columns += 1
        try:
            column_iface = column_index["Netif"]
            column_dest = column_index["Destination"]
            column_gw = column_index["Gateway"]
            column_flags = column_index["Flags"]
        except KeyError:
            msg = "netstat -rn is missing key information; headers are [{0}]".format(header_line)
            logger.error(msg)
            return linux_style_route_file
        # Parse the Routes
        n_routes = len(netstat_output)
        for i in range(1, n_routes-1):
            route = netstat_output[i].split()
            n_columns = len(route)
            if n_columns == 0:
                # End of IPv4 Routes
                break
            elif n_columns < 4:
                # Skip, Invalid/Incomplete Route
                continue
            # Network Interface
            netif = route[column_iface]
            # Destination IP (in HEX)
            if route[column_dest] == "default":
                route[column_dest] = "0.0.0.0/32"
            elif route[column_dest] == "localhost":
                route[column_dest] = "127.0.0.1/32"
            _dest = route[column_dest].split("/")
            dest = ""
            try:
                # IPv4
                dest = "%08X" % int(binascii.hexlify(struct.pack("!I", struct.unpack("=I", socket.inet_pton(socket.AF_INET, _dest[0]))[0])), 16)
            except socket.error:
                dest = ""
            if dest == "":
                # Not an IPv4 or v6 address, skip
                continue
            # Route Gateway (IN HEX)
            if route[column_gw] == "default":
                route[column_gw] = "0.0.0.0"
            elif route[column_gw] == "localhost":
                route[column_gw] = "127.0.0.1"
            gw = ""
            try:
                # IPv4
                gw = "%08X" % int(binascii.hexlify(struct.pack("!I", struct.unpack("=I", socket.inet_pton(socket.AF_INET, route[column_gw]))[0])), 16)
            except socket.error:
                gw = ""
            if gw == "":
                gw = "0.0.0.0"
            # Route Flags
            flags = 0
            RTF_UP = 0x0001
            RTF_GATEWAY = 0x0002
            RTF_HOST = 0x0004
            RTF_DYNAMIC = 0x0010
            if "U" in route[column_flags]:
                flags |= RTF_UP
            if "G" in route[column_flags]:
                flags |= RTF_GATEWAY
            if "H" in route[column_flags]:
                flags |= RTF_HOST
            if "S" not in route[column_flags]:
                flags |= RTF_DYNAMIC
            # Reference Count
            refcount = 0
            # Use
            use = 0
            # Route Metric (priority list ordering is metric)
            metric = n_routes - i
            # Subnet Mask
            mask = 32
            if len(_dest) > 1:
                mask = int(_dest[1])
            mask = "{0:08x}".format(struct.pack(">I", (0xffffffff << (32 - prefix)) & 0xffffffff)).upper()
            # MTU
            mtu = 0
            # Window
            window = 0
            # Initial Round Trip Time
            irtt = 0
            # Add the route
            linux_style_route_file.append("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\t{8}\t{9}\t{10}".format(
                    netif, dest, gw, flags, refcount, use, metric, mask, mtu, window, irtt))
        return linux_style_route_file

    @staticmethod
    def get_list_of_routes(route_table):
        """
        Construct a list of all network routes known to this system.

        :param list(str) route_table: List of text entries from route table, including headers
        :return: a list of network routes
        :rtype: list(RouteEntry)
        """
        route_list = []
        count = len(route_table)

        if count < 1:
            logger.error("netstat -rn is missing headers")
        elif count == 1:
            logger.error("netstat -rn contains no routes")
        else:
            route_list = DefaultOSUtil._build_route_list(route_table)
        return route_list

    def get_primary_interface(self):
        """
        Get the name of the primary interface, which is the one with the
        default route attached to it; if there are multiple default routes,
        the primary has the lowest Metric.
        :return: the interface which has the default route
        """
        RTF_GATEWAY = 0x0002
        DEFAULT_DEST = "00000000"
        
        primary_interface = None

        if not self.disable_route_warning:
            logger.info("Examine netstat -rn for primary interface")

        route_table = self.read_route_table()

        def is_default(route):
            return (route.destination == DEFAULT_DEST) and (RTF_GATEWAY & route.flags)

        candidates = list(filter(is_default, self.get_list_of_routes(route_table)))

        if len(candidates) > 0:
            def get_metric(route):
                return int(route.metric)
            primary_route = min(candidates, key=get_metric)
            primary_interface = primary_route.interface

        if primary_interface is None:
            primary_interface = ''
            if not self.disable_route_warning:
                logger.warn('Could not determine primary interface, '
                            'please ensure routes are correct')
                logger.warn('Primary interface examination will retry silently')
                self.disable_route_warning = True
        else:
            logger.info('Primary interface is [{0}]'.format(primary_interface))
            self.disable_route_warning = False
        return primary_interface

    def is_primary_interface(self, ifname):
        """
        Indicate whether the specified interface is the primary.
        :param ifname: the name of the interface - eth0, lo, etc.
        :return: True if this interface binds the default route
        """
        return self.get_primary_interface() == ifname

    def is_loopback(self, ifname):
        """
        Determine if a named interface is loopback.
        """
        return ifname.startswith("lo")

    def route_add(self, net, mask, gateway):
        cmd = 'route add {0} {1} {2}'.format(net, gateway, mask)
        return shellutil.run(cmd, chk_err=False)

    def is_missing_default_route(self):
        """
        For FreeBSD, the default broadcast goes to current default gw, not a all-ones broadcast address, need to
        specify the route manually to get it work in a VNET environment.
        SEE ALSO: man ip(4) IP_ONESBCAST,
        """
        RTF_GATEWAY = 0x0002
        DEFAULT_DEST = "00000000"

        route_table = self.read_route_table()
        routes = self.get_list_of_routes(route_table)
        for route in routes:
            if (route.destination == DEFAULT_DEST) and (RTF_GATEWAY & route.flags):
               return False
        return True

    def is_dhcp_enabled(self):
        return True

    def start_dhcp_service(self):
        shellutil.run("/etc/rc.d/dhclient start {0}".format(self.get_if_name()), chk_err=False)

    def allow_dhcp_broadcast(self):
        pass

    def set_route_for_dhcp_broadcast(self, ifname):
        return shellutil.run("route add 255.255.255.255 -iface {0}".format(ifname), chk_err=False)

    def remove_route_for_dhcp_broadcast(self, ifname):
        shellutil.run("route delete 255.255.255.255 -iface {0}".format(ifname), chk_err=False)

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pgrep", "-n", "dhclient"])

    def eject_dvd(self, chk_err=True):
        dvd = self.get_dvd_device()
        retcode = shellutil.run("cdcontrol -f {0} eject".format(dvd))
        if chk_err and retcode != 0:
            raise OSUtilError("Failed to eject dvd: ret={0}".format(retcode))

    def restart_if(self, ifname):
        # Restart dhclient only to publish hostname
        shellutil.run("/etc/rc.d/dhclient restart {0}".format(ifname), chk_err=False)

    def get_total_mem(self):
        cmd = "sysctl hw.physmem |awk '{print $2}'"
        ret, output = shellutil.run_get_output(cmd)
        if ret:
            raise OSUtilError("Failed to get total memory: {0}".format(output))
        try:
            return int(output)/1024/1024
        except ValueError:
            raise OSUtilError("Failed to get total memory: {0}".format(output))

    def get_processor_cores(self):
        ret, output = shellutil.run_get_output("sysctl hw.ncpu |awk '{print $2}'")
        if ret:
            raise OSUtilError("Failed to get processor cores.")

        try:
            return int(output)
        except ValueError:
            raise OSUtilError("Failed to get total memory: {0}".format(output))

    def set_scsi_disks_timeout(self, timeout):
        if self._scsi_disks_timeout_set:
            return

        ret, output = shellutil.run_get_output('sysctl kern.cam.da.default_timeout={0}'.format(timeout))
        if ret:
            raise OSUtilError("Failed set SCSI disks timeout: {0}".format(output))
        self._scsi_disks_timeout_set = True

    def check_pid_alive(self, pid):
        return shellutil.run('ps -p {0}'.format(pid), chk_err=False) == 0

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
        logger.verbose("Interface info: ({0},{1},{2})", iface, inet, mac)

        return iface, inet, mac

    def device_for_ide_port(self, port_id):
        """
        Return device name attached to ide port 'n'.
        """
        if port_id > 3:
            return None
        g0 = "00000000"
        if port_id > 1:
            g0 = "00000001"
            port_id = port_id - 2
        err, output = shellutil.run_get_output('sysctl dev.storvsc | grep pnpinfo | grep deviceid=')
        if err:
            return None
        g1 = "000" + ustr(port_id)
        g0g1 = "{0}-{1}".format(g0, g1)
        """
        search 'X' from 'dev.storvsc.X.%pnpinfo: classid=32412632-86cb-44a2-9b5c-50d1417354f5 deviceid=00000000-0001-8899-0000-000000000000'
        """
        cmd_search_ide = "sysctl dev.storvsc | grep pnpinfo | grep deviceid={0}".format(g0g1)
        err, output = shellutil.run_get_output(cmd_search_ide)
        if err:
            return None
        cmd_extract_id = cmd_search_ide + "|awk -F . '{print $3}'"
        err, output = shellutil.run_get_output(cmd_extract_id)
        """
        try to search 'blkvscX' and 'storvscX' to find device name
        """
        output = output.rstrip()
        cmd_search_blkvsc = "camcontrol devlist -b | grep blkvsc{0} | awk '{{print $1}}'".format(output)
        err, output = shellutil.run_get_output(cmd_search_blkvsc)
        if err == 0:
            output = output.rstrip()
            cmd_search_dev="camcontrol devlist | grep {0} | awk -F \( '{{print $2}}'|sed -e 's/.*(//'| sed -e 's/).*//'".format(output)
            err, output = shellutil.run_get_output(cmd_search_dev)
            if err == 0:
                for possible in output.rstrip().split(','):
                    if not possible.startswith('pass'):
                        return possible

        cmd_search_storvsc = "camcontrol devlist -b | grep storvsc{0} | awk '{{print $1}}'".format(output)
        err, output = shellutil.run_get_output(cmd_search_storvsc)
        if err == 0:
            output = output.rstrip()
            cmd_search_dev="camcontrol devlist | grep {0} | awk -F \( '{{print $2}}'|sed -e 's/.*(//'| sed -e 's/).*//'".format(output)
            err, output = shellutil.run_get_output(cmd_search_dev)
            if err == 0:
                for possible in output.rstrip().split(','):
                    if not possible.startswith('pass'):
                        return possible
        return None

    @staticmethod
    def get_total_cpu_ticks_since_boot():
        return 0
