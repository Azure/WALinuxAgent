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
import shutil
import socket
import array
import struct
import time
import pwd
import fcntl
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.textutil as textutil

__RULES_FILES__ = [ "/lib/udev/rules.d/75-persistent-net-generator.rules",
                    "/etc/udev/rules.d/70-persistent-net.rules" ]

"""
Define distro specific behavior. OSUtil class defines default behavior
for all distros. Each concrete distro classes could overwrite default behavior
if needed.
"""

class OSUtilError(Exception):
    pass

class DefaultOSUtil(object):

    def __init__(self):
        self.lib_dir = "/var/lib/waagent"
        self.ext_log_dir = "/var/log/azure"
        self.dvd_mount_point = "/mnt/cdrom/secure"
        self.ovf_env_file_path = "/mnt/cdrom/secure/ovf-env.xml"
        self.agent_pid_file_path = "/var/run/waagent.pid"
        self.passwd_file_path = "/etc/shadow"
        self.home = '/home'
        self.sshd_conf_file_path = '/etc/ssh/sshd_config'
        self.openssl_cmd = '/usr/bin/openssl'
        self.conf_file_path = '/etc/waagent.conf'
        self.selinux=None

    def get_lib_dir(self):
        return self.lib_dir

    def get_ext_log_dir(self):
        return self.ext_log_dir

    def get_dvd_mount_point(self):
        return self.dvd_mount_point

    def get_conf_file_path(self):
        return self.conf_file_path

    def get_ovf_env_file_path_on_dvd(self):
        return self.ovf_env_file_path

    def get_agent_pid_file_path(self):
        return self.agent_pid_file_path

    def get_openssl_cmd(self):
        return self.openssl_cmd

    def get_userentry(self, username):
        try:
            return pwd.getpwnam(username)
        except KeyError:
            return None

    def is_sys_user(self, username):
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
        Update password and ssh key for user account.
        New account will be created if not exists.
        """
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
            raise OSUtilError(("User {0} is a system user. "
                               "Will not set passwd.").format(username))
        passwd_hash = textutil.gen_password_hash(password, crypt_id, salt_len)
        cmd = "usermod -p '{0}' {1}".format(passwd_hash, username)
        ret, output = shellutil.run_get_output(cmd, log_cmd=False)
        if ret != 0:
            raise OSUtilError(("Failed to set password for {0}: {1}"
                               "").format(username, output))

    def conf_sudoer(self, username, nopasswd):
        # for older distros create sudoers.d
        if not os.path.isdir('/etc/sudoers.d/'):
            # create the /etc/sudoers.d/ directory
            os.mkdir('/etc/sudoers.d/')
            # add the include of sudoers.d to the /etc/sudoers
            sudoers = '\n' + '#includedir /etc/sudoers.d/\n'
            fileutil.append_file('/etc/sudoers', sudoers)
        sudoer = None
        if nopasswd:
            sudoer = "{0} ALL = (ALL) NOPASSWD\n".format(username)
        else:
            sudoer = "{0} ALL = (ALL) ALL\n".format(username)
        fileutil.append_file('/etc/sudoers.d/waagent', sudoer)
        fileutil.chmod('/etc/sudoers.d/waagent', 0o440)

    def del_root_password(self):
        try:
            passwd_content = fileutil.read_file(self.passwd_file_path)
            passwd = passwd_content.split('\n')
            new_passwd = [x for x in passwd if not x.startswith("root:")]
            new_passwd.insert(0, "root:*LOCK*:14600::::::")
            fileutil.write_file(self.passwd_file_path, "\n".join(new_passwd))
        except IOError as e:
            raise OSUtilError("Failed to delete root password:{0}".format(e))

    def get_home(self):
        return self.home

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

    def _norm_path(self, filepath):
        home = self.get_home()
        # Expand HOME variable if present in path
        path = os.path.normpath(filepath.replace("$HOME", home))
        return path

    def get_thumbprint_from_crt(self, file_name):
        cmd="{0} x509 -in {1} -fingerprint -noout".format(self.openssl_cmd,
                                                            file_name)
        thumbprint = shellutil.run_get_output(cmd)[1]
        thumbprint = thumbprint.rstrip().split('=')[1].replace(':', '').upper()
        return thumbprint

    def deploy_ssh_keypair(self, username, keypair):
        """
        Deploy id_rsa and id_rsa.pub
        """
        path, thumbprint = keypair
        path = self._norm_path(path)
        dir_path = os.path.dirname(path)
        fileutil.mkdir(dir_path, mode=0o700, owner=username)
        lib_dir = self.get_lib_dir()
        prv_path = os.path.join(lib_dir, thumbprint + '.prv')
        if not os.path.isfile(prv_path):
            raise OSUtilError("Can't find {0}.prv".format(thumbprint))
        shutil.copyfile(prv_path, path)
        pub_path = path + '.pub'
        pub = self.get_pubkey_from_prv(prv_path)
        fileutil.write_file(pub_path, pub)
        self.set_selinux_context(pub_path, 'unconfined_u:object_r:ssh_home_t:s0')
        self.set_selinux_context(path, 'unconfined_u:object_r:ssh_home_t:s0')
        os.chmod(path, 0o644)
        os.chmod(pub_path, 0o600)

    def openssl_to_openssh(self, input_file, output_file):
        shellutil.run("ssh-keygen -i -m PKCS8 -f {0} >> {1}".format(input_file,
                                                                    output_file))

    def deploy_ssh_pubkey(self, username, pubkey):
        """
        Deploy authorized_key
        """
        path, thumbprint, value = pubkey
        if path is None:
            raise OSUtilError("Publich key path is None")

        path = self._norm_path(path)
        dir_path = os.path.dirname(path)
        fileutil.mkdir(dir_path, mode=0o700, owner=username)
        if value is not None:
            if not value.startswith("ssh-"):
                raise OSUtilError("Bad public key: {0}".format(value))
            fileutil.write_file(path, value)
        elif thumbprint is not None:
            lib_dir = self.get_lib_dir()
            crt_path = os.path.join(lib_dir, thumbprint + '.crt')
            if not os.path.isfile(crt_path):
                raise OSUtilError("Can't find {0}.crt".format(thumbprint))
            pub_path = os.path.join(lib_dir, thumbprint + '.pub')
            pub = self.get_pubkey_from_crt(crt_path)
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

    def set_selinux_enforce(self, state):
        """
        Calls shell command 'setenforce' with 'state'
        and returns resulting exit code.
        """
        if self.is_selinux_system():
            if state: s = '1'
            else: s='0'
            return shellutil.run("setenforce "+s)

    def set_selinux_context(self, path, con):
        """
        Calls shell 'chcon' with 'path' and 'con' context.
        Returns exit result.
        """
        if self.is_selinux_system():
            return shellutil.run('chcon ' + con + ' ' + path)

    def get_sshd_conf_file_path(self):
        return self.sshd_conf_file_path

    def set_ssh_client_alive_interval(self):
        conf_file_path = self.get_sshd_conf_file_path()
        conf = fileutil.read_file(conf_file_path).split("\n")
        textutil.set_ssh_config(conf, "ClientAliveInterval", "180")
        fileutil.write_file(conf_file_path, '\n'.join(conf))
        logger.info("Configured SSH client probing to keep connections alive.")

    def conf_sshd(self, disable_password):
        option = "no" if disable_password else "yes"
        conf_file_path = self.get_sshd_conf_file_path()
        conf = fileutil.read_file(conf_file_path).split("\n")
        textutil.set_ssh_config(conf, "PasswordAuthentication", option)
        textutil.set_ssh_config(conf, "ChallengeResponseAuthentication", option)
        fileutil.write_file(conf_file_path, "\n".join(conf))
        logger.info("Disabled SSH password-based authentication methods.")


    def get_dvd_device(self, dev_dir='/dev'):
        patten=r'(sr[0-9]|hd[c-z]|cdrom[0-9])'
        for dvd in [re.match(patten, dev) for dev in os.listdir(dev_dir)]:
            if dvd is not None:
                return "/dev/{0}".format(dvd.group(0))
        raise OSUtilError("Failed to get dvd device")

    def mount_dvd(self, max_retry=6, chk_err=True):
        dvd = self.get_dvd_device()
        mount_point = self.get_dvd_mount_point()
        mountlist = shellutil.run_get_output("mount")[1]
        existing = self.get_mount_point(mountlist, dvd)
        if existing is not None: #Already mounted
            logger.info("{0} is already mounted at {1}", dvd, existing)
            return
        if not os.path.isdir(mount_point):
            os.makedirs(mount_point)

        for retry in range(0, max_retry):
            retcode = self.mount(dvd, mount_point, option="-o ro -t iso9660,udf",
                                 chk_err=chk_err)
            if retcode == 0:
                logger.info("Successfully mounted dvd")
                return
            if retry < max_retry - 1:
                logger.warn("Mount dvd failed: retry={0}, ret={1}", retry,
                            retcode)
                time.sleep(5)
        if chk_err:
            raise OSUtilError("Failed to mount dvd.")

    def umount_dvd(self, chk_err=True):
        mount_point = self.get_dvd_mount_point()
        retcode = self.umount(mount_point, chk_err=chk_err)
        if chk_err and retcode != 0:
            raise OSUtilError("Failed to umount dvd.")
    
    def eject_dvd(self, chk_err=True):
        dvd = self.get_dvd_device()
        retcode = shellutil.run("eject {0}".format(dvd))
        if chk_err and retcode != 0:
            raise OSUtilError("Failed to eject dvd: ret={0}".format(retcode))

    def load_atappix_mod(self):
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
        cmd = "mount {0} {1} {2}".format(dvd, option,  mount_point)
        return shellutil.run_get_output(cmd, chk_err)[0]

    def umount(self, mount_point, chk_err=True):
        return shellutil.run("umount {0}".format(mount_point), chk_err=chk_err)

    def allow_dhcp_broadcast(self):
        #Open DHCP port if iptables is enabled.
        # We supress error logging on error.
        shellutil.run("iptables -D INPUT -p udp --dport 68 -j ACCEPT",
                      chk_err=False)
        shellutil.run("iptables -I INPUT -p udp --dport 68 -j ACCEPT",
                      chk_err=False)

    def gen_transport_cert(self):
        """
        Create ssl certificate for https communication with endpoint server.
        """
        cmd = ("{0} req -x509 -nodes -subj /CN=LinuxTransport -days 32768 "
               "-newkey rsa:2048 -keyout TransportPrivate.pem "
               "-out TransportCert.pem").format(self.openssl_cmd)
        shellutil.run(cmd)

    def remove_rules_files(self, rules_files=__RULES_FILES__):
        lib_dir = self.get_lib_dir()
        for src in rules_files:
            file_name = fileutil.base_name(src)
            dest = os.path.join(lib_dir, file_name)
            if os.path.isfile(dest):
                os.remove(dest)
            if os.path.isfile(src):
                logger.warn("Move rules file {0} to {1}", file_name, dest)
                shutil.move(src, dest)

    def restore_rules_files(self, rules_files=__RULES_FILES__):
        lib_dir = self.get_lib_dir()
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
        first non-loobback interface.
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
        struct_size=40 # for 64bit the size is 40 bytes
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
        for i in range(0, struct_size * expected, struct_size):
            iface=sock[i:i+16].split(b'\0', 1)[0]
            if iface == b'lo':
                continue
            else:
                break
        return iface.decode('latin-1'), socket.inet_ntoa(sock[i+20:i+24])

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
        ret= shellutil.run_get_output("pidof dhclient")
        return ret[1] if ret[0] == 0 else None

    def set_hostname(self, hostname):
        fileutil.write_file('/etc/hostname', hostname)
        shellutil.run("hostname {0}".format(hostname), chk_err=False)

    def set_dhcp_hostname(self, hostname):
        autosend = r'^[^#]*?send\s*host-name.*?(<hostname>|gethostname[(,)])'
        dhclient_files = ['/etc/dhcp/dhclient.conf', '/etc/dhcp3/dhclient.conf']
        for conf_file in dhclient_files:
            if not os.path.isfile(conf_file):
                continue
            if fileutil.findstr_in_file(conf_file, autosend):
                #Return if auto send host-name is configured
                return
            fileutil.update_conf_file(conf_file,
                                      'send host-name',
                                      'send host-name {0}'.format(hostname))

    def restart_if(self, ifname):
        shellutil.run("ifdown {0} && ifup {1}".format(ifname, ifname))

    def publish_hostname(self, hostname):
        self.set_dhcp_hostname(hostname)
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
        for vmbus in os.listdir(path):
            deviceid = fileutil.read_file(os.path.join(path, vmbus, "device_id"))
            guid = deviceid.lstrip('{').split('-')
            if guid[0] == g0 and guid[1] == "000" + text(port_id):
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

    def del_account(self, username):
        if self.is_sys_user(username):
            logger.error("{0} is a system user. Will not delete it.", username)
        shellutil.run("> /var/run/utmp")
        shellutil.run("userdel -f -r " + username)
        #Remove user from suders
        if os.path.isfile("/etc/suders.d/waagent"):
            try:
                content = fileutil.read_file("/etc/sudoers.d/waagent")
                sudoers = content.split("\n")
                sudoers = [x for x in sudoers if username not in x]
                fileutil.write_file("/etc/sudoers.d/waagent",
                                         "\n".join(sudoers))
            except IOError as e:
                raise OSUtilError("Failed to remove sudoer: {0}".format(e))

    def decode_customdata(self, data):
        return data

    def get_total_mem(self):
        cmd = "grep MemTotal /proc/meminfo |awk '{print $2}'"
        ret = shellutil.run_get_output(cmd)
        if ret[0] == 0:
            return int(ret[1])/1024
        else:
            raise OSUtilError("Failed to get total memory: {0}".format(ret[1]))

    def get_processor_cores(self):
        ret = shellutil.run_get_output("grep 'processor.*:' /proc/cpuinfo |wc -l")
        if ret[0] == 0:
            return int(ret[1])
        else:
            raise OSUtilError("Failed to get procerssor cores")

