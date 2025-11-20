# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
# Copyright 2017 Reyk Floeter <reyk@openbsd.org>
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
# Requires Python 2.6+ and OpenSSL 1.0+

import os
import re
import time
import glob
import datetime
import socket
import struct
import binascii

from azurelinuxagent.common.future import UTC
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.conf as conf

from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.osutil.default import DefaultOSUtil

UUID_PATTERN = re.compile(
    r'^\s*[A-F0-9]{8}(?:\-[A-F0-9]{4}){3}\-[A-F0-9]{12}\s*$',
    re.IGNORECASE)


class OpenBSDOSUtil(DefaultOSUtil):

    def __init__(self):
        super(OpenBSDOSUtil, self).__init__()
        self.jit_enabled = True
        self._scsi_disks_timeout_set = False

    @staticmethod
    def get_agent_bin_path():
        return "/usr/local/sbin"

    def get_instance_id(self):
        ret, output = shellutil.run_get_output("sysctl -n hw.uuid")
        if ret != 0 or UUID_PATTERN.match(output) is None:
            return ""
        return output.strip()

    def set_hostname(self, hostname):
        fileutil.write_file("/etc/myname", "{}\n".format(hostname))
        self._run_command_without_raising(["hostname", hostname], log_error=False)

    def restart_ssh_service(self):
        return shellutil.run('rcctl restart sshd', chk_err=False)

    def start_agent_service(self):
        return shellutil.run('rcctl start {0}'.format(self.service_name), chk_err=False)

    def stop_agent_service(self):
        return shellutil.run('rcctl stop {0}'.format(self.service_name), chk_err=False)

    def register_agent_service(self):
        shellutil.run('chmod 0555 /etc/rc.d/{0}'.format(self.service_name), chk_err=False)
        return shellutil.run('rcctl enable {0}'.format(self.service_name), chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run('rcctl disable {0}'.format(self.service_name), chk_err=False)

    def del_account(self, username):
        if self.is_sys_user(username):
            logger.error("{0} is a system user. Will not delete it.", username)
        self._run_command_without_raising(["touch", "/var/run/utmp"])
        self._run_command_without_raising(["userdel", "-r", username])
        self.conf_sudoer(username, remove=True)

    def conf_sudoer(self, username, nopasswd=False, remove=False):
        doas_conf = "/etc/doas.conf"
        doas = None
        if not remove:
            if not os.path.isfile(doas_conf):
                # always allow root to become root
                doas = "permit keepenv nopass root\n"
                fileutil.append_file(doas_conf, doas)
            if nopasswd:
                doas = "permit keepenv nopass {0}\n".format(username)
            else:
                doas = "permit keepenv persist {0}\n".format(username)
            fileutil.append_file(doas_conf, doas)
            fileutil.chmod(doas_conf, 0o644)
        else:
            # Remove user from doas.conf
            if os.path.isfile(doas_conf):
                try:
                    content = fileutil.read_file(doas_conf)
                    doas = content.split("\n")
                    doas = [x for x in doas if username not in x]
                    fileutil.write_file(doas_conf, "\n".join(doas))
                except IOError as err:
                    raise OSUtilError("Failed to remove sudoer: "
                                      "{0}".format(err))

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        if self.is_sys_user(username):
            raise OSUtilError(("User {0} is a system user. "
                               "Will not set passwd.").format(username))
        output = self._run_command_raising_OSUtilError(['encrypt'], cmd_input=password,
                                                       err_msg="Failed to encrypt password for {0}".format(username))
        passwd_hash = output.strip()
        self._run_command_raising_OSUtilError(['usermod', '-p', passwd_hash, username],
                                              err_msg="Failed to set password for {0}".format(username))

    def del_root_password(self):
        ret, output = shellutil.run_get_output('usermod -p "*" root')
        if ret:
            raise OSUtilError("Failed to delete root password: "
                              "{0}".format(output))

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
        Return a list of strings comprising the route table as in the Linux /proc/net/route format. The input taken is from OpenBSDs
        `netstat -rn -f inet` command. Here is what the function does in detail:

        1. Runs `netstat -rn -f inet` which outputs a column formatted list of ipv4 routes in priority order like so:

            > Routing tables
            > 
            > Internet:
            > Destination        Gateway            Flags   Refs      Use   Mtu  Prio Iface
            > default            10.0.0.1           UGS       10      183     -     8 hvn0
            > 224/4              127.0.0.1          URS        0        0 32768     8 lo0
            > 10.0.0/24          10.0.0.6           UCn        1        0     -     4 hvn0
            > 10.0.0.1           12:34:56:78:9a:bc  UHLch      3        8     -     3 hvn0
            > 10.0.0.6           7c:1e:52:19:02:8d  UHLl       0       48     -     1 hvn0
            > 10.0.0.255         10.0.0.6           UHb        0        0     -     1 hvn0
            > 127/8              127.0.0.1          UGRS       0        0 32768     8 lo0
            > 127.0.0.1          127.0.0.1          UHhl       1        2 32768     1 lo0
            > 168.63.129.16/32   10.0.0.1           UGS        0       11     -     8 hvn0
            > 169.254.169.254/32 10.0.0.1           UGS        0        0     -     8 hvn0

        2. Convert it to an array of lines that resemble an equivalent /proc/net/route content on a Linux system like so:

            > Iface   Destination Gateway     Flags   RefCnt  Use Metric  Mask        MTU Window  IRTT
            > gre828  00000000    00000000    0001    0   0   0   000000F8    0   0   0
            > ens160  00000000    FE04700A    0003    0   0   100 00000000    0   0   0
            > gre828  00000008    00000000    0001    0   0   0   000000FE    0   0   0
            > ens160  0004700A    00000000    0001    0   0   100 00FFFFFF    0   0   0
            > gre828  2504700A    00000000    0005    0   0   0   FFFFFFFF    0   0   0
            > gre828  3704700A    00000000    0005    0   0   0   FFFFFFFF    0   0   0
            > gre828  4104700A    00000000    0005    0   0   0   FFFFFFFF    0   0   0

        :return: Entries in the ipv4 route priority list from `netstat -rn -f inet` in the linux `/proc/net/route` style
        :rtype: list(str)
        """

        def _get_netstat_rn_ipv4_routes():
            """
            Runs `netstat -rn -f inet` and parses its output and returns a list of routes where the key is the column name
            and the value is the value in the column, stripped of leading and trailing whitespace.

            :return: List of dictionaries representing routes in the ipv4 route priority list from `netstat -rn -f inet`
            :rtype: list(dict)
            """
            cmd = ["netstat", "-rn", "-f", "inet"]
            output = shellutil.run_command(cmd, log_error=True)
            output_lines = output.split("\n")
            if len(output_lines) < 3:
                raise OSUtilError("`netstat -rn -f inet` output seems to be empty")
            output_lines = [line.strip() for line in output_lines if line]
            if "Internet:" not in output_lines:
                raise OSUtilError("`netstat -rn -f inet` output seems to contain no ipv4 routes")
            route_header_line = output_lines.index("Internet:") + 1
            # Parse the file structure and left justify the routes
            route_start_line = route_header_line + 1
            route_line_length = max([len(line) for line in output_lines[route_header_line:]])
            netstat_route_list = [line.ljust(route_line_length) for line in output_lines[route_start_line:]]
            # Parse the headers
            _route_headers = output_lines[route_header_line].split()
            n_route_headers = len(_route_headers)
            route_columns = {}
            for i in range(0, n_route_headers - 1):
                route_columns[_route_headers[i]] = (
                    output_lines[route_header_line].index(_route_headers[i]),
                    (output_lines[route_header_line].index(_route_headers[i + 1]) - 1)
                )
            route_columns[_route_headers[n_route_headers - 1]] = (
                output_lines[route_header_line].index(_route_headers[n_route_headers - 1]),
                None
            )
            # Parse the routes
            netstat_routes = []
            n_netstat_routes = len(netstat_route_list)
            for i in range(0, n_netstat_routes):
                netstat_route = {}
                for column in route_columns:
                    netstat_route[column] = netstat_route_list[i][
                                            route_columns[column][0]:route_columns[column][1]].strip()
                netstat_route["Metric"] = n_netstat_routes - i
                netstat_routes.append(netstat_route)
            # Return the Sections
            return netstat_routes

        def _ipv4_ascii_address_to_hex(ipv4_ascii_address):
            """
            Converts an IPv4 32bit address from its ASCII notation (ie. 127.0.0.1) to an 8 digit padded hex notation
            (ie. "0100007F") string.

            :return: 8 character long hex string representation of the IP
            :rtype: string
            """
            # Raises socket.error if the IP is not a valid IPv4
            return "%08X" % int(binascii.hexlify(
                struct.pack("!I", struct.unpack("=I", socket.inet_pton(socket.AF_INET, ipv4_ascii_address))[0])), 16)

        def _ipv4_cidr_mask_to_hex(ipv4_cidr_mask):
            """
            Converts an subnet mask from its CIDR integer notation (ie. 32) to an 8 digit padded hex notation
            (ie. "FFFFFFFF") string representing its bitmask form.

            :return: 8 character long hex string representation of the IP
            :rtype: string
            """
            return "{0:08x}".format(
                struct.unpack("=I", struct.pack("!I", (0xffffffff << (32 - ipv4_cidr_mask)) & 0xffffffff))[0]).upper()

        def _ipv4_cidr_destination_to_hex(destination):
            """
            Converts an destination address from its CIDR notation (ie. 127.0.0.1/32 or default or localhost) to an 8
            digit padded hex notation (ie. "0100007F" or "00000000" or "0100007F") string and its subnet bitmask
            also in hex (FFFFFFFF).

            :return: tuple of 8 character long hex string representation of the IP and 8 character long hex string representation of the subnet mask
            :rtype: tuple(string, int)
            """
            destination_ip = "0.0.0.0"
            destination_subnetmask = 32
            if destination != "default":
                if destination == "localhost":
                    destination_ip = "127.0.0.1"
                else:
                    destination_ip = destination.split("/")
                    if len(destination_ip) > 1:
                        destination_subnetmask = int(destination_ip[1])
                    destination_ip = destination_ip[0]
            hex_destination_ip = _ipv4_ascii_address_to_hex(destination_ip)
            hex_destination_subnetmask = _ipv4_cidr_mask_to_hex(destination_subnetmask)
            return hex_destination_ip, hex_destination_subnetmask

        def _try_ipv4_gateway_to_hex(gateway):
            """
            If the gateway is an IPv4 address, return its IP in hex, else, return "00000000"

            :return: 8 character long hex string representation of the IP of the gateway
            :rtype: string
            """
            try:
                return _ipv4_ascii_address_to_hex(gateway)
            except socket.error:
                return "00000000"

        def _ascii_route_flags_to_bitmask(ascii_route_flags):
            """
            Converts route flags to a bitmask of their equivalent linux/route.h values.

            :return: integer representation of a 16 bit mask
            :rtype: int
            """
            bitmask_flags = 0
            RTF_UP = 0x0001
            RTF_GATEWAY = 0x0002
            RTF_HOST = 0x0004
            RTF_DYNAMIC = 0x0010
            if "U" in ascii_route_flags:
                bitmask_flags |= RTF_UP
            if "G" in ascii_route_flags:
                bitmask_flags |= RTF_GATEWAY
            if "H" in ascii_route_flags:
                bitmask_flags |= RTF_HOST
            if "S" not in ascii_route_flags:
                bitmask_flags |= RTF_DYNAMIC
            return bitmask_flags

        def _openbsd_netstat_rn_route_to_linux_proc_net_route(netstat_route):
            """
            Converts a single OpenBSD `netstat -rn -f inet` route to its equivalent /proc/net/route line. ie:
            > default            10.0.0.1           UGS       10      183     -     8 hvn0
            to
            > em1  00000000    00000000    0003    0   0   0   FFFFFFFF    0   0   0

            :return: string representation of the equivalent /proc/net/route line
            :rtype: string
            """
            network_interface = netstat_route["Iface"]
            hex_destination_ip, hex_destination_subnetmask = _ipv4_cidr_destination_to_hex(netstat_route["Destination"])
            hex_gateway = _try_ipv4_gateway_to_hex(netstat_route["Gateway"])
            bitmask_flags = _ascii_route_flags_to_bitmask(netstat_route["Flags"])
            dummy_refcount = 0
            dummy_use = 0
            route_metric = netstat_route["Metric"]
            dummy_mtu = netstat_route["Mtu"]
            dummy_window = 0
            dummy_irtt = 0
            return "{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\t{8}\t{9}\t{10}".format(
                network_interface,
                hex_destination_ip,
                hex_gateway,
                bitmask_flags,
                dummy_refcount,
                dummy_use,
                route_metric,
                hex_destination_subnetmask,
                dummy_mtu,
                dummy_window,
                dummy_irtt
            )

        linux_style_route_file = ["Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT"]

        try:
            netstat_routes = _get_netstat_rn_ipv4_routes()
            # Make sure the `netstat -rn -f inet` contains columns for Iface, Destination, Gateway and Flags which are needed to convert
            # to the Linux Format
            if len(netstat_routes) > 0:
                missing_headers = []
                if "Iface" not in netstat_routes[0]:
                    missing_headers.append("Iface")
                if "Destination" not in netstat_routes[0]:
                    missing_headers.append("Destination")
                if "Gateway" not in netstat_routes[0]:
                    missing_headers.append("Gateway")
                if "Flags" not in netstat_routes[0]:
                    missing_headers.append("Flags")
                if missing_headers:
                    raise KeyError(
                        "`netstat -rn -f inet` output is missing columns required to convert to the Linux /proc/net/route format; columns are [{0}]".format(
                            missing_headers))
                # Parse the Netstat IPv4 Routes
                for netstat_route in netstat_routes:
                    try:
                        linux_style_route = _openbsd_netstat_rn_route_to_linux_proc_net_route(netstat_route)
                        linux_style_route_file.append(linux_style_route)
                    except Exception:
                        # Skip the route
                        continue
        except Exception as e:
            logger.error("Cannot read route table [{0}]", ustr(e))
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
            logger.error("netstat -rn -f inet is missing headers")
        elif count == 1:
            logger.error("netstat -rn -f inet contains no routes")
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
            logger.info("Examine `netstat -rn -f inet` for primary interface")

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
        ret = shellutil.run("route -n get default", chk_err=False)
        if ret == 0:
            return False
        return True

    def is_dhcp_enabled(self):
        pass

    def start_dhcp_service(self):
        pass

    def stop_dhcp_service(self):
        pass

    def get_dhcp_lease_endpoint(self):
        """
        OpenBSD has a sligthly different lease file format.
        """
        endpoint = None
        pathglob = '/var/db/dhclient.leases.{}'.format(self.get_first_if()[0])

        HEADER_LEASE = "lease"
        HEADER_OPTION = "option option-245"
        HEADER_EXPIRE = "expire"
        FOOTER_LEASE = "}"
        FORMAT_DATETIME = "%Y/%m/%d %H:%M:%S %Z"

        logger.info("looking for leases in path [{0}]".format(pathglob))
        for lease_file in glob.glob(pathglob):
            leases = open(lease_file).read()
            if HEADER_OPTION in leases:
                cached_endpoint = None
                has_option_245 = False
                expired = True  # assume expired
                for line in leases.splitlines():
                    if line.startswith(HEADER_LEASE):
                        cached_endpoint = None
                        has_option_245 = False
                        expired = True
                    elif HEADER_OPTION in line:
                        try:
                            ipaddr = line.split(" ")[-1].strip(";").split(":")
                            cached_endpoint = \
                               ".".join(str(int(d, 16)) for d in ipaddr)
                            has_option_245 = True
                        except ValueError:
                            logger.error("could not parse '{0}'".format(line))
                    elif HEADER_EXPIRE in line:
                        if "never" in line:
                            expired = False
                        else:
                            try:
                                expire_string = line.split(
                                    " ", 4)[-1].strip(";")
                                expire_date = datetime.datetime.strptime(expire_string, FORMAT_DATETIME).replace(tzinfo=UTC)
                                if expire_date > datetime.datetime.now(UTC):
                                    expired = False
                            except ValueError:
                                logger.error("could not parse expiry token "
                                             "'{0}'".format(line))
                    elif FOOTER_LEASE in line:
                        logger.info("dhcp entry:{0}, 245:{1}, expired: {2}"
                                    .format(cached_endpoint, has_option_245, expired))
                        if not expired and cached_endpoint is not None and has_option_245:
                            endpoint = cached_endpoint
                            logger.info("found endpoint [{0}]".format(endpoint))
                            # we want to return the last valid entry, so
                            # keep searching
        if endpoint is not None:
            logger.info("cached endpoint found [{0}]".format(endpoint))
        else:
            logger.info("cached endpoint not found")
        return endpoint

    def allow_dhcp_broadcast(self):
        pass

    def set_route_for_dhcp_broadcast(self, ifname):
        return shellutil.run("route add 255.255.255.255 -iface "
                             "{0}".format(ifname), chk_err=False)

    def remove_route_for_dhcp_broadcast(self, ifname):
        shellutil.run("route delete 255.255.255.255 -iface "
                      "{0}".format(ifname), chk_err=False)

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pgrep", "-n", "dhclient"])

    def get_dvd_device(self, dev_dir='/dev'):
        pattern = r'cd[0-9]c'
        for dvd in [re.match(pattern, dev) for dev in os.listdir(dev_dir)]:
            if dvd is not None:
                return "/dev/{0}".format(dvd.group(0))
        raise OSUtilError("Failed to get DVD device")

    def mount_dvd(self,
                  max_retry=6,
                  chk_err=True,
                  dvd_device=None,
                  mount_point=None,
                  sleep_time=5):
        if dvd_device is None:
            dvd_device = self.get_dvd_device()
        if mount_point is None:
            mount_point = conf.get_dvd_mount_point()
        if not os.path.isdir(mount_point):
            os.makedirs(mount_point)

        for retry in range(0, max_retry):
            retcode = self.mount(dvd_device,
                                mount_point, 
                                option=["-o", "ro", "-t", "udf"], 
                                chk_err=False) 
            if retcode == 0:
                logger.info("Successfully mounted DVD")
                return
            if retry < max_retry - 1:
                mountlist = shellutil.run_get_output("/sbin/mount")[1]
                existing = self.get_mount_point(mountlist, dvd_device)
                if existing is not None:
                    logger.info("{0} is mounted at {1}", dvd_device, existing)
                    return
                logger.warn("Mount DVD failed: retry={0}, ret={1}", retry,
                            retcode)
                time.sleep(sleep_time)
        if chk_err:
            raise OSUtilError("Failed to mount DVD.")

    def eject_dvd(self, chk_err=True):
        dvd = self.get_dvd_device()
        retcode = shellutil.run("cdio eject {0}".format(dvd))
        if chk_err and retcode != 0:
            raise OSUtilError("Failed to eject DVD: ret={0}".format(retcode))

    def restart_if(self, ifname, retries=3, wait=5):
        # Restart dhclient only to publish hostname
        shellutil.run("/sbin/dhclient {0}".format(ifname), chk_err=False)

    def get_total_mem(self):
        ret, output = shellutil.run_get_output("sysctl -n hw.physmem")
        if ret:
            raise OSUtilError("Failed to get total memory: {0}".format(output))
        try:
            return int(output)/1024/1024
        except ValueError:
            raise OSUtilError("Failed to get total memory: {0}".format(output))

    def get_processor_cores(self):
        ret, output = shellutil.run_get_output("sysctl -n hw.ncpu")
        if ret:
            raise OSUtilError("Failed to get processor cores.")

        try:
            return int(output)
        except ValueError:
            raise OSUtilError("Failed to get total memory: {0}".format(output))

    def set_scsi_disks_timeout(self, timeout):
        pass

    def check_pid_alive(self, pid):  # pylint: disable=R1710
        if not pid:
            return
        return shellutil.run('ps -p {0}'.format(pid), chk_err=False) == 0

    @staticmethod
    def _get_net_info():
        """
        There is no SIOCGIFCONF
        on OpenBSD - just parse ifconfig.
        Returns strings: iface, inet4_addr, and mac
        or 'None,None,None' if unable to parse.
        We will sleep and retry as the network must be up.
        """
        iface = ''
        inet = ''
        mac = ''

        ret, output = shellutil.run_get_output(
            'ifconfig hvn | grep -E "^hvn.:" | sed "s/:.*//g"', chk_err=False)
        if ret:
            raise OSUtilError("Can't find ether interface:{0}".format(output))
        ifaces = output.split()
        if not ifaces:
            raise OSUtilError("Can't find ether interface.")
        iface = ifaces[0]

        ret, output = shellutil.run_get_output(
            'ifconfig ' + iface, chk_err=False)
        if ret:
            raise OSUtilError("Can't get info for interface:{0}".format(iface))

        for line in output.split('\n'):
            if line.find('inet ') != -1:
                inet = line.split()[1]
            elif line.find('lladdr ') != -1:
                mac = line.split()[1]
        logger.verbose("Interface info: ({0},{1},{2})", iface, inet, mac)

        return iface, inet, mac

    def device_for_ide_port(self, port_id):
        """
        Return device name attached to ide port 'n'.
        """
        return "wd{0}".format(port_id)

    @staticmethod
    def get_total_cpu_ticks_since_boot():
        return 0
