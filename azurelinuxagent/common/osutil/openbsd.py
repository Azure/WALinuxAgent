# Microsoft Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and OpenSSL 1.0+

import os
import re
import time
import glob
import datetime

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
        self._scsi_disks_timeout_set = False

    def get_instance_id(self):
        ret, output = shellutil.run_get_output("sysctl -n hw.uuid")
        if ret != 0 or UUID_PATTERN.match(output) is None:
            return ""
        return output.strip()

    def set_hostname(self, hostname):
        fileutil.write_file("/etc/myname", "{}\n".format(hostname))
        shellutil.run("hostname {0}".format(hostname), chk_err=False)

    def restart_ssh_service(self):
        return shellutil.run('rcctl restart sshd', chk_err=False)

    def start_agent_service(self):
        return shellutil.run('rcctl start waagent', chk_err=False)

    def stop_agent_service(self):
        return shellutil.run('rcctl stop waagent', chk_err=False)

    def register_agent_service(self):
        shellutil.run('chmod 0555 /etc/rc.d/waagent', chk_err=False)
        return shellutil.run('rcctl enable waagent', chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run('rcctl disable waagent', chk_err=False)

    def del_account(self, username):
        if self.is_sys_user(username):
            logger.error("{0} is a system user. Will not delete it.",
                         username)
        shellutil.run("> /var/run/utmp")
        shellutil.run("userdel -r " + username)
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
        cmd = "echo -n {0}|encrypt".format(password)
        ret, output = shellutil.run_get_output(cmd, log_cmd=False)
        if ret != 0:
            raise OSUtilError(("Failed to encrypt password for {0}: {1}"
                               "").format(username, output))
        passwd_hash = output.strip()
        cmd = "usermod -p '{0}' {1}".format(passwd_hash, username)
        ret, output = shellutil.run_get_output(cmd, log_cmd=False)
        if ret != 0:
            raise OSUtilError(("Failed to set password for {0}: {1}"
                               "").format(username, output))

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
                                expire_date = datetime.datetime.strptime(
                                    expire_string, FORMAT_DATETIME)
                                if expire_date > datetime.datetime.utcnow():
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
        ret, output = shellutil.run_get_output("pgrep -n dhclient",
                                               chk_err=False)
        return output if ret == 0 else None

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
            retcode = self.mount(dvd_device, mount_point, option="-o ro -t udf",
                                 chk_err=chk_err)
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

    def check_pid_alive(self, pid):
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
