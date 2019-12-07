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
import datetime
import errno
import fcntl
import glob
import multiprocessing
import os
import platform
import pwd
import re
import shutil
import socket
import struct
import sys
import time
from pwd import getpwall

import array

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.networkutil import RouteEntry, NetworkInterfaceCard
from azurelinuxagent.common.utils.shellutil import CommandError

__RULES_FILES__ = [ "/lib/udev/rules.d/75-persistent-net-generator.rules",
                    "/etc/udev/rules.d/70-persistent-net.rules" ]

"""
Define distro specific behavior. OSUtil class defines default behavior
for all distros. Each concrete distro classes could overwrite default behavior
if needed.
"""

IPTABLES_VERSION_PATTERN = re.compile("^[^\d\.]*([\d\.]+).*$")
IPTABLES_VERSION = "iptables --version"
IPTABLES_LOCKING_VERSION = FlexibleVersion('1.4.21')

FIREWALL_ACCEPT = "iptables {0} -t security -{1} OUTPUT -d {2} -p tcp -m owner --uid-owner {3} -j ACCEPT"
# Note:
# -- Initially "flight" the change to ACCEPT packets and develop a metric baseline
#    A subsequent release will convert the ACCEPT to DROP
# FIREWALL_DROP = "iptables {0} -t security -{1} OUTPUT -d {2} -p tcp -m conntrack --ctstate INVALID,NEW -j ACCEPT"
FIREWALL_DROP = "iptables {0} -t security -{1} OUTPUT -d {2} -p tcp -m conntrack --ctstate INVALID,NEW -j DROP"
FIREWALL_LIST = "iptables {0} -t security -L -nxv"
FIREWALL_PACKETS = "iptables {0} -t security -L OUTPUT --zero OUTPUT -nxv"
FIREWALL_FLUSH = "iptables {0} -t security --flush"

# Precisely delete the rules created by the agent.
# this rule was used <= 2.2.25.  This rule helped to validate our change, and determine impact.
FIREWALL_DELETE_CONNTRACK_ACCEPT = "iptables {0} -t security -D OUTPUT -d {1} -p tcp -m conntrack --ctstate INVALID,NEW -j ACCEPT"
FIREWALL_DELETE_OWNER_ACCEPT = "iptables {0} -t security -D OUTPUT -d {1} -p tcp -m owner --uid-owner {2} -j ACCEPT"
FIREWALL_DELETE_CONNTRACK_DROP = "iptables {0} -t security -D OUTPUT -d {1} -p tcp -m conntrack --ctstate INVALID,NEW -j DROP"

PACKET_PATTERN = "^\s*(\d+)\s+(\d+)\s+DROP\s+.*{0}[^\d]*$"
ALL_CPUS_REGEX = re.compile('^cpu .*')


_enable_firewall = True

DMIDECODE_CMD = 'dmidecode --string system-uuid'
PRODUCT_ID_FILE = '/sys/class/dmi/id/product_uuid'
UUID_PATTERN = re.compile(
    r'^\s*[A-F0-9]{8}(?:\-[A-F0-9]{4}){3}\-[A-F0-9]{12}\s*$',
    re.IGNORECASE)

IOCTL_SIOCGIFCONF = 0x8912
IOCTL_SIOCGIFFLAGS = 0x8913
IOCTL_SIOCGIFHWADDR = 0x8927
IFNAMSIZ = 16

IP_COMMAND_OUTPUT = re.compile('^\d+:\s+(\w+):\s+(.*)$')

BASE_CGROUPS = '/sys/fs/cgroup'

STORAGE_DEVICE_PATH = '/sys/bus/vmbus/devices/'
GEN2_DEVICE_ID = 'f8b3781a-1e82-4818-a1c3-63d806ec15bb'

class DefaultOSUtil(object):
    def __init__(self):
        self.agent_conf_file_path = '/etc/waagent.conf'
        self.selinux = None
        self.disable_route_warning = False
        self.jit_enabled = False
        self.service_name = self.get_service_name()

    @staticmethod
    def get_service_name():
        return "waagent"

    def get_firewall_dropped_packets(self, dst_ip=None):
        # If a previous attempt failed, do not retry
        global _enable_firewall
        if not _enable_firewall:
            return 0

        try:
            wait = self.get_firewall_will_wait()

            rc, output = shellutil.run_get_output(FIREWALL_PACKETS.format(wait), log_cmd=False, expected_errors=[3])
            if rc == 3:
                # Transient error  that we ignore.  This code fires every loop
                # of the daemon (60m), so we will get the value eventually.
                return 0

            if rc != 0:
                return -1

            pattern = re.compile(PACKET_PATTERN.format(dst_ip))
            for line in output.split('\n'):
                m = pattern.match(line)
                if m is not None:
                    return int(m.group(1))
            
            return 0

        except Exception as e:
            _enable_firewall = False
            logger.warn("Unable to retrieve firewall packets dropped"
                        "{0}".format(ustr(e)))
            return -1

    def get_firewall_will_wait(self):
        # Determine if iptables will serialize access
        rc, output = shellutil.run_get_output(IPTABLES_VERSION)
        if rc != 0:
            msg = "Unable to determine version of iptables"
            logger.warn(msg)
            raise Exception(msg)

        m = IPTABLES_VERSION_PATTERN.match(output)
        if m is None:
            msg = "iptables did not return version information"
            logger.warn(msg)
            raise Exception(msg)

        wait = "-w" \
                if FlexibleVersion(m.group(1)) >= IPTABLES_LOCKING_VERSION \
                else ""
        return wait

    def _delete_rule(self, rule):
        """
        Continually execute the delete operation until the return
        code is non-zero or the limit has been reached.
        """
        for i in range(1, 100):
            rc = shellutil.run(rule, chk_err=False)
            if rc == 1:
                return
            elif rc == 2:
                raise Exception("invalid firewall deletion rule '{0}'".format(rule))

    def remove_firewall(self, dst_ip=None, uid=None):
        # If a previous attempt failed, do not retry
        global _enable_firewall
        if not _enable_firewall:
            return False

        try:
            if dst_ip is None or uid is None:
                msg = "Missing arguments to enable_firewall"
                logger.warn(msg)
                raise Exception(msg)

            wait = self.get_firewall_will_wait()

            # This rule was <= 2.2.25 only, and may still exist on some VMs.  Until 2.2.25
            # has aged out, keep this cleanup in place.
            self._delete_rule(FIREWALL_DELETE_CONNTRACK_ACCEPT.format(wait, dst_ip))

            self._delete_rule(FIREWALL_DELETE_OWNER_ACCEPT.format(wait, dst_ip, uid))
            self._delete_rule(FIREWALL_DELETE_CONNTRACK_DROP.format(wait, dst_ip))

            return True

        except Exception as e:
            _enable_firewall = False
            logger.info("Unable to remove firewall -- "
                        "no further attempts will be made: "
                        "{0}".format(ustr(e)))
            return False

    def enable_firewall(self, dst_ip=None, uid=None):
        # If a previous attempt failed, do not retry
        global _enable_firewall
        if not _enable_firewall:
            return False

        try:
            if dst_ip is None or uid is None:
                msg = "Missing arguments to enable_firewall"
                logger.warn(msg)
                raise Exception(msg)

            wait = self.get_firewall_will_wait()

            # If the DROP rule exists, make no changes
            drop_rule = FIREWALL_DROP.format(wait, "C", dst_ip)
            rc = shellutil.run(drop_rule, chk_err=False)
            if rc == 0:
                logger.verbose("Firewall appears established")
                return True
            elif rc == 2:
                self.remove_firewall(dst_ip, uid)
                msg = "please upgrade iptables to a version that supports the -C option"
                logger.warn(msg)
                raise Exception(msg)

            # Otherwise, append both rules
            accept_rule = FIREWALL_ACCEPT.format(wait, "A", dst_ip, uid)
            drop_rule = FIREWALL_DROP.format(wait, "A", dst_ip)

            if shellutil.run(accept_rule) != 0:
                msg = "Unable to add ACCEPT firewall rule '{0}'".format(
                    accept_rule)
                logger.warn(msg)
                raise Exception(msg)

            if shellutil.run(drop_rule) != 0:
                msg = "Unable to add DROP firewall rule '{0}'".format(
                    drop_rule)
                logger.warn(msg)
                raise Exception(msg)

            logger.info("Successfully added Azure fabric firewall rules")

            rc, output = shellutil.run_get_output(FIREWALL_LIST.format(wait))
            if rc == 0:
                logger.info("Firewall rules:\n{0}".format(output))
            else:
                logger.warn("Listing firewall rules failed: {0}".format(output))

            return True

        except Exception as e:
            _enable_firewall = False
            logger.info("Unable to establish firewall -- "
                        "no further attempts will be made: "
                        "{0}".format(ustr(e)))
            return False

    @staticmethod
    def _correct_instance_id(id):
        '''
        Azure stores the instance ID with an incorrect byte ordering for the
        first parts. For example, the ID returned by the metadata service:

            D0DF4C54-4ECB-4A4B-9954-5BDF3ED5C3B8

        will be found as:

            544CDFD0-CB4E-4B4A-9954-5BDF3ED5C3B8

        This code corrects the byte order such that it is consistent with
        that returned by the metadata service.
        '''

        if not UUID_PATTERN.match(id):
            return id

        parts = id.split('-')
        return '-'.join([
                textutil.swap_hexstring(parts[0], width=2),
                textutil.swap_hexstring(parts[1], width=2),
                textutil.swap_hexstring(parts[2], width=2),
                parts[3],
                parts[4]
            ])

    def is_current_instance_id(self, id_that):
        '''
        Compare two instance IDs for equality, but allow that some IDs
        may have been persisted using the incorrect byte ordering.
        '''
        id_this = self.get_instance_id()
        logger.verbose("current instance id: {0}".format(id_this))
        logger.verbose(" former instance id: {0}".format(id_that))
        return id_this.lower() == id_that.lower() or \
            id_this.lower() == self._correct_instance_id(id_that).lower()

    @staticmethod
    def is_cgroups_supported():
        """
        Enabled by default; disabled if the base path of cgroups doesn't exist.
        """
        return os.path.exists(BASE_CGROUPS)

    @staticmethod
    def _cgroup_path(tail=""):
        return os.path.join(BASE_CGROUPS, tail).rstrip(os.path.sep)

    def mount_cgroups(self):
        try:
            path = self._cgroup_path()
            if not os.path.exists(path):
                fileutil.mkdir(path)
                self.mount(device='cgroup_root',
                           mount_point=path,
                           option="-t tmpfs",
                           chk_err=False)
            elif not os.path.isdir(self._cgroup_path()):
                logger.error("Could not mount cgroups: ordinary file at {0}", path)
                return

            controllers_to_mount = ['cpu,cpuacct', 'memory']
            errors = 0
            cpu_mounted = False
            for controller in controllers_to_mount:
                try:
                    target_path = self._cgroup_path(controller)
                    if not os.path.exists(target_path):
                        fileutil.mkdir(target_path)
                        self.mount(device=controller,
                                   mount_point=target_path,
                                   option="-t cgroup -o {0}".format(controller),
                                   chk_err=False)
                        if controller == 'cpu,cpuacct':
                            cpu_mounted = True
                except Exception as exception:
                    errors += 1
                    if errors == len(controllers_to_mount):
                        raise
                    logger.warn("Could not mount cgroup controller {0}: {1}", controller, ustr(exception))

            if cpu_mounted:
                for controller in ['cpu', 'cpuacct']:
                    target_path = self._cgroup_path(controller)
                    if not os.path.exists(target_path):
                        os.symlink(self._cgroup_path('cpu,cpuacct'), target_path)

        except OSError as oe:
            # log a warning for read-only file systems
            logger.warn("Could not mount cgroups: {0}", ustr(oe))
            raise
        except Exception as e:
            logger.error("Could not mount cgroups: {0}", ustr(e))
            raise

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
            s = fileutil.read_file(PRODUCT_ID_FILE).strip()
            
        else:
            rc, s = shellutil.run_get_output(DMIDECODE_CMD)
            if rc != 0 or UUID_PATTERN.match(s) is None:
                return ""
              
        return self._correct_instance_id(s.strip())

    @staticmethod
    def get_userentry(username):
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

    def useradd(self, username, expiration=None, comment=None):
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
        
        if comment is not None:
            cmd += " -c {0}".format(comment)
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
    
    def get_users(self):
        return getpwall()

    def conf_sudoer(self, username, nopasswd=False, remove=False):
        sudoers_dir = conf.get_sudoers_dir()
        sudoers_wagent = os.path.join(sudoers_dir, 'waagent')

        if not remove:
            # for older distros create sudoers.d
            if not os.path.isdir(sudoers_dir):
                # create the sudoers.d directory
                fileutil.mkdir(sudoers_dir)
                # add the include of sudoers.d to the /etc/sudoers
                sudoers_file = os.path.join(sudoers_dir, os.pardir, 'sudoers')
                include_sudoers_dir = "\n#includedir {0}\n".format(sudoers_dir)
                fileutil.append_file(sudoers_file, include_sudoers_dir)
            sudoer = None
            if nopasswd:
                sudoer = "{0} ALL=(ALL) NOPASSWD: ALL".format(username)
            else:
                sudoer = "{0} ALL=(ALL) ALL".format(username)
            if not os.path.isfile(sudoers_wagent) or \
                    fileutil.findstr_in_file(sudoers_wagent, sudoer) is False:
                fileutil.append_file(sudoers_wagent, "{0}\n".format(sudoer))
            fileutil.chmod(sudoers_wagent, 0o440)
        else:
            # remove user from sudoers
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

    @staticmethod
    def _norm_path(filepath):
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
            if not value.endswith("\n"):
                value += "\n"
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
        textutil.set_ssh_config(conf_file, "ClientAliveInterval", str(conf.get_ssh_client_alive_interval()))
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
                                          chk_err=False)
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

    def mount(self, device, mount_point, option="", chk_err=True):
        cmd = "mount {0} {1} {2}".format(option, device, mount_point)
        retcode, err = shellutil.run_get_output(cmd, chk_err)
        if retcode != 0:
            detail = "[{0}] returned {1}: {2}".format(cmd, retcode, err)
            err = detail
        return retcode, err

    def umount(self, mount_point, chk_err=True):
        return shellutil.run("umount {0}".format(mount_point), chk_err=chk_err)

    def allow_dhcp_broadcast(self):
        # Open DHCP port if iptables is enabled.
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
        Convenience function, returns mac addr bound to
        first non-loopback interface.
        """
        ifname = self.get_if_name()
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
        info = fcntl.ioctl(sock.fileno(), IOCTL_SIOCGIFHWADDR, param)
        sock.close()
        return ''.join(['%02X' % textutil.str_to_ord(char) for char in info[18:24]])

    @staticmethod
    def _get_struct_ifconf_size():
        """
        Return the sizeof struct ifinfo. On 64-bit platforms the size is 40 bytes;
        on 32-bit platforms the size is 32 bytes.
        """
        python_arc = platform.architecture()[0]
        struct_size = 32 if python_arc == '32bit' else 40
        return struct_size

    def _get_all_interfaces(self):
        """
        Return a dictionary mapping from interface name to IPv4 address.
        Interfaces without a name are ignored.
        """
        expected=16 # how many devices should I expect...
        struct_size = DefaultOSUtil._get_struct_ifconf_size()
        array_size = expected * struct_size

        buff = array.array('B', b'\0' * array_size)
        param = struct.pack('iL', array_size, buff.buffer_info()[0])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        ret = fcntl.ioctl(sock.fileno(), IOCTL_SIOCGIFCONF, param)
        retsize = (struct.unpack('iL', ret)[0])
        sock.close()

        if retsize == array_size:
            logger.warn(('SIOCGIFCONF returned more than {0} up '
                         'network interfaces.'), expected)

        ifconf_buff = buff.tostring()

        ifaces = {}
        for i in range(0, array_size, struct_size):
            iface = ifconf_buff[i:i+IFNAMSIZ].split(b'\0', 1)[0]
            if len(iface) > 0:
                iface_name = iface.decode('latin-1')
                if iface_name not in ifaces:
                    ifaces[iface_name] = socket.inet_ntoa(ifconf_buff[i+20:i+24])
        return ifaces

    def get_first_if(self):
        """
        Return the interface name, and IPv4 addr of the "primary" interface or,
        failing that, any active non-loopback interface.
        """
        primary = self.get_primary_interface()
        ifaces = self._get_all_interfaces()

        if primary in ifaces:
            return primary, ifaces[primary]

        for iface_name in ifaces.keys():
            if not self.is_loopback(iface_name):
                logger.info("Choosing non-primary [{0}]".format(iface_name))
                return iface_name, ifaces[iface_name]

        return '', ''

    @staticmethod
    def _build_route_list(proc_net_route):
        """
        Construct a list of network route entries
        :param list(str) proc_net_route: Route table lines, including headers, containing at least one route
        :return: List of network route objects
        :rtype: list(RouteEntry)
        """
        idx = 0
        column_index = {}
        header_line = proc_net_route[0]
        for header in filter(lambda h: len(h) > 0, header_line.split("\t")):
            column_index[header.strip()] = idx
            idx += 1
        try:
            idx_iface = column_index["Iface"]
            idx_dest = column_index["Destination"]
            idx_gw = column_index["Gateway"]
            idx_flags = column_index["Flags"]
            idx_metric = column_index["Metric"]
            idx_mask = column_index["Mask"]
        except KeyError:
            msg = "/proc/net/route is missing key information; headers are [{0}]".format(header_line)
            logger.error(msg)
            return []

        route_list = []
        for entry in proc_net_route[1:]:
            route = entry.split("\t")
            if len(route) > 0:
                route_obj = RouteEntry(route[idx_iface], route[idx_dest], route[idx_gw], route[idx_mask],
                                                   route[idx_flags], route[idx_metric])
                route_list.append(route_obj)
        return route_list

    @staticmethod
    def read_route_table():
        """
        Return a list of strings comprising the route table, including column headers. Each line is stripped of leading
        or trailing whitespace but is otherwise unmolested.

        :return: Entries in the text route table
        :rtype: list(str)
        """
        try:
            with open('/proc/net/route') as routing_table:
                return list(map(str.strip, routing_table.readlines()))
        except Exception as e:
            logger.error("Cannot read route table [{0}]", ustr(e))

        return []

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
            logger.error("/proc/net/route is missing headers")
        elif count == 1:
            logger.error("/proc/net/route contains no routes")
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
        # from linux/route.h
        RTF_GATEWAY = 0x02
        DEFAULT_DEST = "00000000"

        primary_interface = None

        if not self.disable_route_warning:
            logger.info("Examine /proc/net/route for primary interface")

        route_table = DefaultOSUtil.read_route_table()

        def is_default(route):
            return route.destination == DEFAULT_DEST and int(route.flags) & RTF_GATEWAY == RTF_GATEWAY

        candidates = list(filter(is_default, DefaultOSUtil.get_list_of_routes(route_table)))

        if len(candidates) > 0:
            def get_metric(route):
                return int(route.metric)
            primary_route = min(candidates, key=get_metric)
            primary_interface = primary_route.interface

        if primary_interface is None:
            primary_interface = ''
            if not self.disable_route_warning:
                with open('/proc/net/route') as routing_table_fh:
                    routing_table_text = routing_table_fh.read()
                    logger.warn('Could not determine primary interface, '
                                'please ensure /proc/net/route is correct')
                    logger.warn('Contents of /proc/net/route:\n{0}'.format(routing_table_text))
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
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        ifname_buff = ifname + ('\0'*256)
        result = fcntl.ioctl(s.fileno(), IOCTL_SIOCGIFFLAGS, ifname_buff)
        flags, = struct.unpack('H', result[16:18])
        isloopback = flags & 8 == 8
        if not self.disable_route_warning:
            logger.info('interface [{0}] has flags [{1}], '
                        'is loopback [{2}]'.format(ifname, flags, isloopback))
        s.close()
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
        HEADER_OPTION_245 = "option unknown-245"
        HEADER_EXPIRE = "expire"
        FOOTER_LEASE = "}"
        FORMAT_DATETIME = "%Y/%m/%d %H:%M:%S"
        option_245_re = re.compile(r'\s*option\s+unknown-245\s+([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+);')

        logger.info("looking for leases in path [{0}]".format(pathglob))
        for lease_file in glob.glob(pathglob):
            leases = open(lease_file).read()
            if HEADER_OPTION_245 in leases:
                cached_endpoint = None
                option_245_match = None
                expired = True  # assume expired
                for line in leases.splitlines():
                    if line.startswith(HEADER_LEASE):
                        cached_endpoint = None
                        expired = True
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
                            cached_endpoint, option_245_match is not None, expired))
                        if not expired and cached_endpoint is not None:
                            endpoint = cached_endpoint
                            logger.info("found endpoint [{0}]".format(endpoint))
                            # we want to return the last valid entry, so
                            # keep searching
                    else:
                        option_245_match = option_245_re.match(line)
                        if option_245_match is not None:
                            cached_endpoint = '{0}.{1}.{2}.{3}'.format(
                                int(option_245_match.group(1), 16),
                                int(option_245_match.group(2), 16),
                                int(option_245_match.group(3), 16),
                                int(option_245_match.group(4), 16))
        if endpoint is not None:
            logger.info("cached endpoint found [{0}]".format(endpoint))
        else:
            logger.info("cached endpoint not found")
        return endpoint

    def is_missing_default_route(self):
        route_cmd = "ip route show"
        routes = shellutil.run_get_output(route_cmd)[1]
        for route in routes.split("\n"):
            if route.startswith("0.0.0.0 ") or route.startswith("default "):
               return False
        return True

    def get_if_name(self):
        if_name = ''
        if_found = False
        while not if_found:
            if_name = self.get_first_if()[0]
            if_found = len(if_name) >= 2
            if not if_found:
                time.sleep(2)
        return if_name

    def get_ip4_addr(self):
        return self.get_first_if()[1]

    def set_route_for_dhcp_broadcast(self, ifname):
        route_cmd = "ip route add"
        return shellutil.run("{0} 255.255.255.255 dev {1}".format(
            route_cmd, ifname),
                             chk_err=False)

    def remove_route_for_dhcp_broadcast(self, ifname):
        route_cmd = "ip route del"
        shellutil.run("{0} 255.255.255.255 dev {1}".format(route_cmd, ifname),
                      chk_err=False)

    def is_dhcp_available(self):
        return True

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
        Add specified route 
        """
        cmd = "ip route add {0} via {1}".format(net, gateway)
        return shellutil.run(cmd, chk_err=False)

    @staticmethod
    def _text_to_pid_list(text):
        return [int(n) for n in text.split()]

    @staticmethod
    def _get_dhcp_pid(command):
        try:
            return DefaultOSUtil._text_to_pid_list(shellutil.run_command(command))
        except CommandError as exception:
            return []

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pidof", "dhclient"])

    def set_hostname(self, hostname):
        fileutil.write_file('/etc/hostname', hostname)
        shellutil.run("hostname {0}".format(hostname), chk_err=False)

    def set_dhcp_hostname(self, hostname):
        autosend = r'^[^#]*?send\s*host-name.*?(<hostname>|gethostname[(,)])'
        dhclient_files = ['/etc/dhcp/dhclient.conf', '/etc/dhcp3/dhclient.conf', '/etc/dhclient.conf']
        for conf_file in dhclient_files:
            if not os.path.isfile(conf_file):
                continue
            if fileutil.findre_in_file(conf_file, autosend):
                #Return if auto send host-name is configured
                return
            fileutil.update_conf_file(conf_file,
                                      'send host-name',
                                      'send host-name "{0}";'.format(hostname))

    def restart_if(self, ifname, retries=3, wait=5):
        retry_limit=retries+1
        for attempt in range(1, retry_limit):
            return_code=shellutil.run("ifdown {0} && ifup {0}".format(ifname), expected_errors=[1] if attempt < retries else [])
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

    @staticmethod
    def _enumerate_device_id():
        """
        Enumerate all storage device IDs.

        Args:
            None

        Returns:
            Iterator[Tuple[str, str]]: VmBus and storage devices.
        """

        if os.path.exists(STORAGE_DEVICE_PATH):
            for vmbus in os.listdir(STORAGE_DEVICE_PATH):
                deviceid = fileutil.read_file(os.path.join(STORAGE_DEVICE_PATH, vmbus, "device_id"))
                guid = deviceid.strip('{}\n')
                yield vmbus, guid

    @staticmethod
    def search_for_resource_disk(gen1_device_prefix, gen2_device_id):
        """
        Search the filesystem for a device by ID or prefix.

        Args:
            gen1_device_prefix (str): Gen1 resource disk prefix.
            gen2_device_id (str): Gen2 resource device ID.

        Returns:
            str: The found device.
        """

        device = None
        # We have to try device IDs for both Gen1 and Gen2 VMs.
        logger.info('Searching gen1 prefix {0} or gen2 {1}'.format(gen1_device_prefix, gen2_device_id))
        try:
            for vmbus, guid in DefaultOSUtil._enumerate_device_id():
                if guid.startswith(gen1_device_prefix) or guid == gen2_device_id:
                    for root, dirs, files in os.walk(STORAGE_DEVICE_PATH + vmbus):
                        root_path_parts = root.split('/')
                        # For Gen1 VMs we only have to check for the block dir in the
                        # current device. But for Gen2 VMs all of the disks (sda, sdb,
                        # sr0) are presented in this device on the same SCSI controller.
                        # Because of that we need to also read the LUN. It will be:
                        #   0 - OS disk
                        #   1 - Resource disk
                        #   2 - CDROM
                        if root_path_parts[-1] == 'block' and (
                                guid != gen2_device_id or
                                root_path_parts[-2].split(':')[-1] == '1'):
                            device = dirs[0]
                            return device
                        else:
                            # older distros
                            for d in dirs:
                                if ':' in d and "block" == d.split(':')[0]:
                                    device = d.split(':')[1]
                                    return device
        except (OSError, IOError) as exc:
            logger.warn('Error getting device for {0} or {1}: {2}', gen1_device_prefix, gen2_device_id, ustr(exc))
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

        gen1_device_prefix = '{0}-000{1}'.format(g0, port_id)
        device = DefaultOSUtil.search_for_resource_disk(
            gen1_device_prefix=gen1_device_prefix,
            gen2_device_id=GEN2_DEVICE_ID
        )
        logger.info('Found device: {0}'.format(device))
        return device

    def set_hostname_record(self, hostname):
        fileutil.write_file(conf.get_published_hostname(), contents=hostname)

    def get_hostname_record(self):
        hostname_record = conf.get_published_hostname()
        if not os.path.exists(hostname_record):
            # this file is created at provisioning time with agents >= 2.2.3
            hostname = socket.gethostname()
            logger.info('Hostname record does not exist, '
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
        try:
            pid = int(pid)
            os.kill(pid, 0)
        except (ValueError, TypeError):
            return False
        except OSError as e:
            if e.errno == errno.EPERM:
                return True
            return False
        return True

    @property
    def is_64bit(self):
        return sys.maxsize > 2**32

    @staticmethod
    def _get_proc_stat():
        """
        Get the contents of /proc/stat.
        # cpu  813599 3940 909253 154538746 874851 0 6589 0 0 0
        # cpu0 401094 1516 453006 77276738 452939 0 3312 0 0 0
        # cpu1 412505 2423 456246 77262007 421912 0 3276 0 0 0

        :return: A single string with the contents of /proc/stat
        :rtype: str
        """
        results = None
        try:
            results = fileutil.read_file('/proc/stat')
        except (OSError, IOError) as ex:
            logger.warn("Couldn't read /proc/stat: {0}".format(ex.strerror))
            raise

        return results

    @staticmethod
    def get_total_cpu_ticks_since_boot():
        """
        Compute the number of USER_HZ units of time that have elapsed in all categories, across all cores, since boot.

        :return: int
        """
        system_cpu = 0
        proc_stat = DefaultOSUtil._get_proc_stat()
        if proc_stat is not None:
            for line in proc_stat.splitlines():
                if ALL_CPUS_REGEX.match(line):
                    system_cpu = sum(int(i) for i in line.split()[1:8])  # see "man proc" for a description of these fields
                    break
        return system_cpu

    def get_nic_state(self):
        """
        Capture NIC state (IPv4 and IPv6 addresses plus link state).

        :return: Dictionary of NIC state objects, with the NIC name as key
        :rtype: dict(str,NetworkInformationCard)
        """
        state = {}

        status, output = shellutil.run_get_output("ip -a -o link", chk_err=False, log_cmd=False)
        """
        1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 addrgenmode eui64
        2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\    link/ether 00:0d:3a:30:c3:5a brd ff:ff:ff:ff:ff:ff promiscuity 0 addrgenmode eui64
        3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default \    link/ether 02:42:b5:d5:00:1d brd ff:ff:ff:ff:ff:ff promiscuity 0 \    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q addrgenmode eui64

        """
        if status != 0:
            logger.verbose("Could not fetch NIC link info; status {0}, {1}".format(status, output))
            return {}

        for entry in output.splitlines():
            result = IP_COMMAND_OUTPUT.match(entry)
            if result:
                name = result.group(1)
                state[name] = NetworkInterfaceCard(name, result.group(2))

        self._update_nic_state(state, "ip -4 -a -o address", NetworkInterfaceCard.add_ipv4, "an IPv4 address")
        """
        1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
        2: eth0    inet 10.145.187.220/26 brd 10.145.187.255 scope global eth0\       valid_lft forever preferred_lft forever
        3: docker0    inet 192.168.43.1/24 brd 192.168.43.255 scope global docker0\       valid_lft forever preferred_lft forever
        """

        self._update_nic_state(state, "ip -6 -a -o address", NetworkInterfaceCard.add_ipv6, "an IPv6 address")
        """
        1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
        2: eth0    inet6 fe80::20d:3aff:fe30:c35a/64 scope link \       valid_lft forever preferred_lft forever
        """

        return state

    def _update_nic_state(self, state, ip_command, handler, description):
        """
        Update the state of NICs based on the output of a specified ip subcommand.

        :param dict(str, NetworkInterfaceCard) state: Dictionary of NIC state objects
        :param str ip_command: The ip command to run
        :param handler: A method on the NetworkInterfaceCard class
        :param str description: Description of the particular information being added to the state
        """
        status, output = shellutil.run_get_output(ip_command, chk_err=True)
        if status != 0:
            return

        for entry in output.splitlines():
            result = IP_COMMAND_OUTPUT.match(entry)
            if result:
                interface_name = result.group(1)
                if interface_name in state:
                    handler(state[interface_name], result.group(2))
                else:
                    logger.error("Interface {0} has {1} but no link state".format(interface_name, description))
