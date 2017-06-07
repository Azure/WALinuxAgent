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

import multiprocessing
import os
import platform
import re
import shutil
import socket
import array
import struct
import time
import pwd
import fcntl
import base64
import glob
import datetime

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil

from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.cryptutil import CryptUtil

__RULES_FILES__ = [ "/lib/udev/rules.d/75-persistent-net-generator.rules",
                    "/etc/udev/rules.d/70-persistent-net.rules" ]

"""
Define distro specific behavior. OSUtil class defines default behavior
for all distros. Each concrete distro classes could overwrite default behavior
if needed.
"""

DMIDECODE_CMD = 'dmidecode --string system-uuid'
PRODUCT_ID_FILE = '/sys/class/dmi/id/product_uuid'
UUID_PATTERN = re.compile(
    '^\s*[A-F0-9]{8}(?:\-[A-F0-9]{4}){3}\-[A-F0-9]{12}\s*$',
    re.IGNORECASE)

class DefaultOSUtil(object):

    def __init__(self):
        self.agent_conf_file_path = '/etc/waagent.conf'
        self.selinux = None
        self.disable_route_warning = False

    def get_agent_conf_file_path(self):
        return self.agent_conf_file_path

    def get_instance_id(self):
        '''
        Azure records a UUID as the instance ID
        First check /sys/class/dmi/id/product_uuid.
        If that is missing, then extracts from dmidecode
        If nothing works (for old VMs), return the empty string
        '''
        if os.path.isfile(PRODUCT_ID_FILE):
            return fileutil.read_file(PRODUCT_ID_FILE).strip()

        rc, s = shellutil.run_get_output(DMIDECODE_CMD)
        if rc != 0 or UUID_PATTERN.match(s) is None:
            return ""

        return s.strip()

    def get_userentry(self, username):
        try:
            return pwd.getpwnam(username)
        except KeyError:
            return None

    def is_sys_user(self, username):
        """
        Check whether use is a system user. 
        If reset sys user is allowed in conf, return False
        Otherwise, check whether UID is less than UID_MIN
        """
        if conf.get_allow_reset_sys_user():
            return False

        userentry = self.get_userentry(username)
        uidmin = None
        try:
            uidmin_def = fileutil.get_line_startingwith("UID_MIN",
                                                        "/etc/login.defs")
            if uidmin_def is not None:
                uidmin = int(uidmin_def.split()[1])
        except IOError as e:
            pass
        if uidmin == None:
            uidmin = 100
        if userentry != None and userentry[2] < uidmin:
            return True
        else:
            return False

    def useradd(self, username, expiration=None):
        """
        Create user account with 'username'
        """
        userentry = self.get_userentry(username)
        if userentry is not None:
            logger.info("User {0} already exists, skip useradd", username)
            return

        if expiration is not None:
            cmd = "useradd -m {0} -e {1}".format(username, expiration)
        else:
            cmd = "useradd -m {0}".format(username)
        retcode, out = shellutil.run_get_output(cmd)
        if retcode != 0:
            raise OSUtilError(("Failed to create user account:{0}, "
                               "retcode:{1}, "
                               "output:{2}").format(username, retcode, out))

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        if self.is_sys_user(username):
            raise OSUtilError(("User {0} is a system user, "
                               "will not set password.").format(username))
        passwd_hash = textutil.gen_password_hash(password, crypt_id, salt_len)
        cmd = "usermod -p '{0}' {1}".format(passwd_hash, username)
        ret, output = shellutil.run_get_output(cmd, log_cmd=False)
        if ret != 0:
            raise OSUtilError(("Failed to set password for {0}: {1}"
                               "").format(username, output))

    def conf_sudoer(self, username, nopasswd=False, remove=False):
        sudoers_dir = conf.get_sudoers_dir()
        sudoers_wagent = os.path.join(sudoers_dir, 'waagent')

        if not remove:
            # for older distros create sudoers.d
            if not os.path.isdir(sudoers_dir):
                sudoers_file = os.path.join(sudoers_dir, '../sudoers')
                # create the sudoers.d directory
                os.mkdir(sudoers_dir)
                # add the include of sudoers.d to the /etc/sudoers
                sudoers = '\n#includedir ' + sudoers_dir + '\n'
                fileutil.append_file(sudoers_file, sudoers)
            sudoer = None
            if nopasswd:
                sudoer = "{0} ALL=(ALL) NOPASSWD: ALL\n".format(username)
            else:
                sudoer = "{0} ALL=(ALL) ALL\n".format(username)
            fileutil.append_file(sudoers_wagent, sudoer)
            fileutil.chmod(sudoers_wagent, 0o440)
        else:
            #Remove user from sudoers
            if os.path.isfile(sudoers_wagent):
                try:
                    content = fileutil.read_file(sudoers_wagent)
                    sudoers = content.split("\n")
                    sudoers = [x for x in sudoers if username not in x]
                    fileutil.write_file(sudoers_wagent, "\n".join(sudoers))
                except IOError as e:
                    raise OSUtilError("Failed to remove sudoer: {0}".format(e))

    def del_root_password(self):
        try:
            passwd_file_path = conf.get_passwd_file_path()
            passwd_content = fileutil.read_file(passwd_file_path)
            passwd = passwd_content.split('\n')
            new_passwd = [x for x in passwd if not x.startswith("root:")]
            new_passwd.insert(0, "root:*LOCK*:14600::::::")
            fileutil.write_file(passwd_file_path, "\n".join(new_passwd))
        except IOError as e:
            raise OSUtilError("Failed to delete root password:{0}".format(e))

    def _norm_path(self, filepath):
        home = conf.get_home_dir()
        # Expand HOME variable if present in path
        path = os.path.normpath(filepath.replace("$HOME", home))
        return path

    def deploy_ssh_keypair(self, username, keypair):
        """
        Deploy id_rsa and id_rsa.pub
        """
        path, thumbprint = keypair
        path = self._norm_path(path)
        dir_path = os.path.dirname(path)
        fileutil.mkdir(dir_path, mode=0o700, owner=username)
        lib_dir = conf.get_lib_dir()
        prv_path = os.path.join(lib_dir, thumbprint + '.prv')
        if not os.path.isfile(prv_path):
            raise OSUtilError("Can't find {0}.prv".format(thumbprint))
        shutil.copyfile(prv_path, path)
        pub_path = path + '.pub'
        crytputil = CryptUtil(conf.get_openssl_cmd())
        pub = crytputil.get_pubkey_from_prv(prv_path)
        fileutil.write_file(pub_path, pub)
        self.set_selinux_context(pub_path, 'unconfined_u:object_r:ssh_home_t:s0')
        self.set_selinux_context(path, 'unconfined_u:object_r:ssh_home_t:s0')
        os.chmod(path, 0o644)
        os.chmod(pub_path, 0o600)

    def openssl_to_openssh(self, input_file, output_file):
        cryptutil = CryptUtil(conf.get_openssl_cmd())
        cryptutil.crt_to_ssh(input_file, output_file)

    def deploy_ssh_pubkey(self, username, pubkey):
        """
        Deploy authorized_key
        """
        path, thumbprint, value = pubkey
        if path is None:
            raise OSUtilError("Public key path is None")

        crytputil = CryptUtil(conf.get_openssl_cmd())

        path = self._norm_path(path)
        dir_path = os.path.dirname(path)
        fileutil.mkdir(dir_path, mode=0o700, owner=username)
        if value is not None:
            if not value.startswith("ssh-"):
                raise OSUtilError("Bad public key: {0}".format(value))
            fileutil.write_file(path, value)
        elif thumbprint is not None:
            lib_dir = conf.get_lib_dir()
            crt_path = os.path.join(lib_dir, thumbprint + '.crt')
            if not os.path.isfile(crt_path):
                raise OSUtilError("Can't find {0}.crt".format(thumbprint))
            pub_path = os.path.join(lib_dir, thumbprint + '.pub')
            pub = crytputil.get_pubkey_from_crt(crt_path)
            fileutil.write_file(pub_path, pub)
            self.set_selinux_context(pub_path,
                                     'unconfined_u:object_r:ssh_home_t:s0')
            self.openssl_to_openssh(pub_path, path)
            fileutil.chmod(pub_path, 0o600)
        else:
            raise OSUtilError("SSH public key Fingerprint and Value are None")

        self.set_selinux_context(path, 'unconfined_u:object_r:ssh_home_t:s0')
        fileutil.chowner(path, username)
        fileutil.chmod(path, 0o644)

    def is_selinux_system(self):
        """
        Checks and sets self.selinux = True if SELinux is available on system.
        """
        if self.selinux == None:
            if shellutil.run("which getenforce", chk_err=False) == 0:
                self.selinux = True
            else:
                self.selinux = False
        return self.selinux

    def is_selinux_enforcing(self):
        """
        Calls shell command 'getenforce' and returns True if 'Enforcing'.
        """
        if self.is_selinux_system():
            output = shellutil.run_get_output("getenforce")[1]
            return output.startswith("Enforcing")
        else:
            return False

    def set_selinux_context(self, path, con):
        """
        Calls shell 'chcon' with 'path' and 'con' context.
        Returns exit result.
        """
        if self.is_selinux_system():
            if not os.path.exists(path):
                logger.error("Path does not exist: {0}".format(path))
                return 1
            return shellutil.run('chcon ' + con + ' ' + path)

    def conf_sshd(self, disable_password):
        option = "no" if disable_password else "yes"
        conf_file_path = conf.get_sshd_conf_file_path()
        conf_file = fileutil.read_file(conf_file_path).split("\n")
        textutil.set_ssh_config(conf_file, "PasswordAuthentication", option)
        textutil.set_ssh_config(conf_file, "ChallengeResponseAuthentication", option)
        textutil.set_ssh_config(conf_file, "ClientAliveInterval", "180")
        fileutil.write_file(conf_file_path, "\n".join(conf_file))
        logger.info("{0} SSH password-based authentication methods."
                    .format("Disabled" if disable_password else "Enabled"))
        logger.info("Configured SSH client probing to keep connections alive.")

    def get_dvd_device(self, dev_dir='/dev'):
        pattern = r'(sr[0-9]|hd[c-z]|cdrom[0-9]|cd[0-9])'
        device_list = os.listdir(dev_dir)
        for dvd in [re.match(pattern, dev) for dev in device_list]:
            if dvd is not None:
                return "/dev/{0}".format(dvd.group(0))
        inner_detail = "The following devices were found, but none matched " \
                       "the pattern [{0}]: {1}\n".format(pattern, device_list)
        raise OSUtilError(msg="Failed to get dvd device from {0}".format(dev_dir),
                          inner=inner_detail)

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
        mount_list = shellutil.run_get_output("mount")[1]
        existing = self.get_mount_point(mount_list, dvd_device)

        if existing is not None:
            # already mounted
            logger.info("{0} is already mounted at {1}", dvd_device, existing)
            return

        if not os.path.isdir(mount_point):
            os.makedirs(mount_point)

        err = ''
        for retry in range(1, max_retry):
            return_code, err = self.mount(dvd_device,
                                          mount_point,
                                          option="-o ro -t udf,iso9660",
                                          chk_err=chk_err)
            if return_code == 0:
                logger.info("Successfully mounted dvd")
                return
            else:
                logger.warn(
                    "Mounting dvd failed [retry {0}/{1}, sleeping {2} sec]",
                    retry,
                    max_retry - 1,
                    sleep_time)
                if retry < max_retry:
                    time.sleep(sleep_time)
        if chk_err:
            raise OSUtilError("Failed to mount dvd device", inner=err)

    def umount_dvd(self, chk_err=True, mount_point=None):
        if mount_point is None:
            mount_point = conf.get_dvd_mount_point()
        return_code = self.umount(mount_point, chk_err=chk_err)
        if chk_err and return_code != 0:
            raise OSUtilError("Failed to unmount dvd device at {0}",
                              mount_point)

    def eject_dvd(self, chk_err=True):
        dvd = self.get_dvd_device()
        retcode = shellutil.run("eject {0}".format(dvd))
        if chk_err and retcode != 0:
            raise OSUtilError("Failed to eject dvd: ret={0}".format(retcode))

    def try_load_atapiix_mod(self):
        try:
            self.load_atapiix_mod()
        except Exception as e:
            logger.warn("Could not load ATAPI driver: {0}".format(e))

    def load_atapiix_mod(self):
        if self.is_atapiix_mod_loaded():
            return
        ret, kern_version = shellutil.run_get_output("uname -r")
        if ret != 0:
            raise Exception("Failed to call uname -r")
        mod_path = os.path.join('/lib/modules',
                                kern_version.strip('\n'),
                                'kernel/drivers/ata/ata_piix.ko')
        if not os.path.isfile(mod_path):
            raise Exception("Can't find module file:{0}".format(mod_path))

        ret, output = shellutil.run_get_output("insmod " + mod_path)
        if ret != 0:
            raise Exception("Error calling insmod for ATAPI CD-ROM driver")
        if not self.is_atapiix_mod_loaded(max_retry=3):
            raise Exception("Failed to load ATAPI CD-ROM driver")

    def is_atapiix_mod_loaded(self, max_retry=1):
        for retry in range(0, max_retry):
            ret = shellutil.run("lsmod | grep ata_piix", chk_err=False)
            if ret == 0:
                logger.info("Module driver for ATAPI CD-ROM is already present.")
                return True
            if retry < max_retry - 1:
                time.sleep(1)
        return False

    def mount(self, dvd, mount_point, option="", chk_err=True):
        cmd = "mount {0} {1} {2}".format(option, dvd, mount_point)
        retcode, err = shellutil.run_get_output(cmd, chk_err)
        if retcode != 0:
            detail = "[{0}] returned {1}: {2}".format(cmd, retcode, err)
            err = detail
        return retcode, err

    def umount(self, mount_point, chk_err=True):
        return shellutil.run("umount {0}".format(mount_point), chk_err=chk_err)

    def allow_dhcp_broadcast(self):
        #Open DHCP port if iptables is enabled.
        # We supress error logging on error.
        shellutil.run("iptables -D INPUT -p udp --dport 68 -j ACCEPT",
                      chk_err=False)
        shellutil.run("iptables -I INPUT -p udp --dport 68 -j ACCEPT",
                      chk_err=False)


    def remove_rules_files(self, rules_files=__RULES_FILES__):
        lib_dir = conf.get_lib_dir()
        for src in rules_files:
            file_name = fileutil.base_name(src)
            dest = os.path.join(lib_dir, file_name)
            if os.path.isfile(dest):
                os.remove(dest)
            if os.path.isfile(src):
                logger.warn("Move rules file {0} to {1}", file_name, dest)
                shutil.move(src, dest)

    def restore_rules_files(self, rules_files=__RULES_FILES__):
        lib_dir = conf.get_lib_dir()
        for dest in rules_files:
            filename = fileutil.base_name(dest)
            src = os.path.join(lib_dir, filename)
            if os.path.isfile(dest):
                continue
            if os.path.isfile(src):
                logger.warn("Move rules file {0} to {1}", filename, dest)
                shutil.move(src, dest)

    def get_mac_addr(self):
        """
        Convienience function, returns mac addr bound to
        first non-loopback interface.
        """
        ifname=''
        while len(ifname) < 2 :
            ifname=self.get_first_if()[0]
        addr = self.get_if_mac(ifname)
        return textutil.hexstr_to_bytearray(addr)

    def get_if_mac(self, ifname):
        """
        Return the mac-address bound to the socket.
        """
        sock = socket.socket(socket.AF_INET,
                             socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        param = struct.pack('256s', (ifname[:15]+('\0'*241)).encode('latin-1'))
        info = fcntl.ioctl(sock.fileno(), 0x8927, param)
        return ''.join(['%02X' % textutil.str_to_ord(char) for char in info[18:24]])

    def get_first_if(self):
        """
        Return the interface name, and ip addr of the
        first active non-loopback interface.
        """
        iface=''
        expected=16 # how many devices should I expect...

        # for 64bit the size is 40 bytes
        # for 32bit the size is 32 bytes
        python_arc = platform.architecture()[0]
        struct_size = 32 if python_arc == '32bit' else 40

        sock = socket.socket(socket.AF_INET,
                             socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        buff=array.array('B', b'\0' * (expected * struct_size))
        param = struct.pack('iL',
                            expected*struct_size,
                            buff.buffer_info()[0])
        ret = fcntl.ioctl(sock.fileno(), 0x8912, param)
        retsize=(struct.unpack('iL', ret)[0])
        if retsize == (expected * struct_size):
            logger.warn(('SIOCGIFCONF returned more than {0} up '
                         'network interfaces.'), expected)
        sock = buff.tostring()
        primary = bytearray(self.get_primary_interface(), encoding='utf-8')
        for i in range(0, struct_size * expected, struct_size):
            iface=sock[i:i+16].split(b'\0', 1)[0]
            if len(iface) == 0 or self.is_loopback(iface) or iface != primary:
                # test the next one
                if len(iface) != 0 and not self.disable_route_warning:
                    logger.info('Interface [{0}] skipped'.format(iface))
                continue
            else:
                # use this one
                logger.info('Interface [{0}] selected'.format(iface))
                break

        return iface.decode('latin-1'), socket.inet_ntoa(sock[i+20:i+24])

    def get_primary_interface(self):
        """
        Get the name of the primary interface, which is the one with the
        default route attached to it; if there are multiple default routes,
        the primary has the lowest Metric.
        :return: the interface which has the default route
        """
        # from linux/route.h
        RTF_GATEWAY = 0x02
        DEFAULT_DEST = "00000000"

        hdr_iface = "Iface"
        hdr_dest = "Destination"
        hdr_flags = "Flags"
        hdr_metric = "Metric"

        idx_iface = -1
        idx_dest = -1
        idx_flags = -1
        idx_metric = -1
        primary = None
        primary_metric = None

        if not self.disable_route_warning:
            logger.info("Examine /proc/net/route for primary interface")
        with open('/proc/net/route') as routing_table:
            idx = 0
            for header in filter(lambda h: len(h) > 0, routing_table.readline().strip(" \n").split("\t")):
                if header == hdr_iface:
                    idx_iface = idx
                elif header == hdr_dest:
                    idx_dest = idx
                elif header == hdr_flags:
                    idx_flags = idx
                elif header == hdr_metric:
                    idx_metric = idx
                idx = idx + 1
            for entry in routing_table.readlines():
                route = entry.strip(" \n").split("\t")
                if route[idx_dest] == DEFAULT_DEST and int(route[idx_flags]) & RTF_GATEWAY == RTF_GATEWAY:
                    metric = int(route[idx_metric])
                    iface = route[idx_iface]
                    if primary is None or metric < primary_metric:
                        primary = iface
                        primary_metric = metric

        if primary is None:
            primary = ''
            if not self.disable_route_warning:
                with open('/proc/net/route') as routing_table_fh:
                    routing_table_text = routing_table_fh.read()
                    logger.warn('Could not determine primary interface, '
                                'please ensure /proc/net/route is correct')
                    logger.warn('Contents of /proc/net/route:\n{0}'.format(routing_table_text))
                    logger.warn('Primary interface examination will retry silently')
                    self.disable_route_warning = True
        else:
            logger.info('Primary interface is [{0}]'.format(primary))
            self.disable_route_warning = False
        return primary

    def is_primary_interface(self, ifname):
        """
        Indicate whether the specified interface is the primary.
        :param ifname: the name of the interface - eth0, lo, etc.
        :return: True if this interface binds the default route
        """
        return self.get_primary_interface() == ifname

    def is_loopback(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        result = fcntl.ioctl(s.fileno(), 0x8913, struct.pack('256s', ifname[:15]))
        flags, = struct.unpack('H', result[16:18])
        isloopback = flags & 8 == 8
        if not self.disable_route_warning:
            logger.info('interface [{0}] has flags [{1}], '
                        'is loopback [{2}]'.format(ifname, flags, isloopback))
        return isloopback

    def get_dhcp_lease_endpoint(self):
        """
        OS specific, this should return the decoded endpoint of
        the wireserver from option 245 in the dhcp leases file
        if it exists on disk.
        :return: The endpoint if available, or None
        """
        return None

    @staticmethod
    def get_endpoint_from_leases_path(pathglob):
        """
        Try to discover and decode the wireserver endpoint in the
        specified dhcp leases path.
        :param pathglob: The path containing dhcp lease files
        :return: The endpoint if available, otherwise None
        """
        endpoint = None

        HEADER_LEASE = "lease"
        HEADER_OPTION = "option unknown-245"
        HEADER_DNS = "option domain-name-servers"
        HEADER_EXPIRE = "expire"
        FOOTER_LEASE = "}"
        FORMAT_DATETIME = "%Y/%m/%d %H:%M:%S"

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
                    elif HEADER_DNS in line:
                        cached_endpoint = line.replace(HEADER_DNS, '').strip(" ;")
                    elif HEADER_OPTION in line:
                        has_option_245 = True
                    elif HEADER_EXPIRE in line:
                        if "never" in line:
                            expired = False
                        else:
                            try:
                                expire_string = line.split(" ", 4)[-1].strip(";")
                                expire_date = datetime.datetime.strptime(expire_string, FORMAT_DATETIME)
                                if expire_date > datetime.datetime.utcnow():
                                    expired = False
                            except:
                                logger.error("could not parse expiry token '{0}'".format(line))
                    elif FOOTER_LEASE in line:
                        logger.info("dhcp entry:{0}, 245:{1}, expired:{2}".format(
                            cached_endpoint, has_option_245, expired))
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

    def is_missing_default_route(self):
        routes = shellutil.run_get_output("route -n")[1]
        for route in routes.split("\n"):
            if route.startswith("0.0.0.0 ") or route.startswith("default "):
               return False
        return True

    def get_if_name(self):
        return self.get_first_if()[0]

    def get_ip4_addr(self):
        return self.get_first_if()[1]

    def set_route_for_dhcp_broadcast(self, ifname):
        return shellutil.run("route add 255.255.255.255 dev {0}".format(ifname),
                             chk_err=False)

    def remove_route_for_dhcp_broadcast(self, ifname):
        shellutil.run("route del 255.255.255.255 dev {0}".format(ifname),
                      chk_err=False)

    def is_dhcp_enabled(self):
        return False

    def stop_dhcp_service(self):
        pass

    def start_dhcp_service(self):
        pass

    def start_network(self):
        pass

    def start_agent_service(self):
        pass

    def stop_agent_service(self):
        pass

    def register_agent_service(self):
        pass

    def unregister_agent_service(self):
        pass

    def restart_ssh_service(self):
        pass

    def route_add(self, net, mask, gateway):
        """
        Add specified route using /sbin/route add -net.
        """
        cmd = ("/sbin/route add -net "
               "{0} netmask {1} gw {2}").format(net, mask, gateway)
        return shellutil.run(cmd, chk_err=False)

    def get_dhcp_pid(self):
        ret = shellutil.run_get_output("pidof dhclient", chk_err=False)
        return ret[1] if ret[0] == 0 else None

    def set_hostname(self, hostname):
        fileutil.write_file('/etc/hostname', hostname)
        shellutil.run("hostname {0}".format(hostname), chk_err=False)

    def set_dhcp_hostname(self, hostname):
        autosend = r'^[^#]*?send\s*host-name.*?(<hostname>|gethostname[(,)])'
        dhclient_files = ['/etc/dhcp/dhclient.conf', '/etc/dhcp3/dhclient.conf', '/etc/dhclient.conf']
        for conf_file in dhclient_files:
            if not os.path.isfile(conf_file):
                continue
            if fileutil.findstr_in_file(conf_file, autosend):
                #Return if auto send host-name is configured
                return
            fileutil.update_conf_file(conf_file,
                                      'send host-name',
                                      'send host-name "{0}";'.format(hostname))

    def restart_if(self, ifname, retries=3, wait=5):
        retry_limit=retries+1
        for attempt in range(1, retry_limit):
            return_code=shellutil.run("ifdown {0} && ifup {0}".format(ifname))
            if return_code == 0:
                return
            logger.warn("failed to restart {0}: return code {1}".format(ifname, return_code))
            if attempt < retry_limit:
                logger.info("retrying in {0} seconds".format(wait))
                time.sleep(wait)
            else:
                logger.warn("exceeded restart retries")

    def publish_hostname(self, hostname):
        self.set_dhcp_hostname(hostname)
        self.set_hostname_record(hostname)
        ifname = self.get_if_name()
        self.restart_if(ifname)

    def set_scsi_disks_timeout(self, timeout):
        for dev in os.listdir("/sys/block"):
            if dev.startswith('sd'):
                self.set_block_device_timeout(dev, timeout)

    def set_block_device_timeout(self, dev, timeout):
        if dev is not None and timeout is not None:
            file_path = "/sys/block/{0}/device/timeout".format(dev)
            content = fileutil.read_file(file_path)
            original = content.splitlines()[0].rstrip()
            if original != timeout:
                fileutil.write_file(file_path, timeout)
                logger.info("Set block dev timeout: {0} with timeout: {1}",
                            dev, timeout)

    def get_mount_point(self, mountlist, device):
        """
        Example of mountlist:
            /dev/sda1 on / type ext4 (rw)
            proc on /proc type proc (rw)
            sysfs on /sys type sysfs (rw)
            devpts on /dev/pts type devpts (rw,gid=5,mode=620)
            tmpfs on /dev/shm type tmpfs
            (rw,rootcontext="system_u:object_r:tmpfs_t:s0")
            none on /proc/sys/fs/binfmt_misc type binfmt_misc (rw)
            /dev/sdb1 on /mnt/resource type ext4 (rw)
        """
        if (mountlist and device):
            for entry in mountlist.split('\n'):
                if(re.search(device, entry)):
                    tokens = entry.split()
                    #Return the 3rd column of this line
                    return tokens[2] if len(tokens) > 2 else None
        return None

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
        device = None
        path = "/sys/bus/vmbus/devices/"
        if os.path.exists(path):
            for vmbus in os.listdir(path):
                deviceid = fileutil.read_file(os.path.join(path, vmbus, "device_id"))
                guid = deviceid.lstrip('{').split('-')
                if guid[0] == g0 and guid[1] == "000" + ustr(port_id):
                    for root, dirs, files in os.walk(path + vmbus):
                        if root.endswith("/block"):
                            device = dirs[0]
                            break
                        else : #older distros
                            for d in dirs:
                                if ':' in d and "block" == d.split(':')[0]:
                                    device = d.split(':')[1]
                                    break
                    break
        return device

    def set_hostname_record(self, hostname):
        fileutil.write_file(conf.get_published_hostname(), contents=hostname)

    def get_hostname_record(self):
        hostname_record = conf.get_published_hostname()
        if not os.path.exists(hostname_record):
            # this file is created at provisioning time with agents >= 2.2.3
            hostname = socket.gethostname()
            logger.warn('Hostname record does not exist, '
                        'creating [{0}] with hostname [{1}]',
                        hostname_record,
                        hostname)
            self.set_hostname_record(hostname)
        record = fileutil.read_file(hostname_record)
        return record

    def del_account(self, username):
        if self.is_sys_user(username):
            logger.error("{0} is a system user. Will not delete it.", username)
        shellutil.run("> /var/run/utmp")
        shellutil.run("userdel -f -r " + username)
        self.conf_sudoer(username, remove=True)

    def decode_customdata(self, data):
        return base64.b64decode(data).decode('utf-8')

    def get_total_mem(self):
        # Get total memory in bytes and divide by 1024**2 to get the value in MB.
        return os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024**2)

    def get_processor_cores(self):
        return multiprocessing.cpu_count()

    def check_pid_alive(self, pid):
        return pid is not None and os.path.isdir(os.path.join('/proc', pid))
