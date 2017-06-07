# Copyright 2016 F5 Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.4+ and Openssl 1.0+
#

import array
import fcntl
import os
import platform
import re
import socket
import struct
import time

try:
    # WAAgent > 2.1.3
    import azurelinuxagent.common.logger as logger
    import azurelinuxagent.common.utils.shellutil as shellutil

    from azurelinuxagent.common.exception import OSUtilError
    from azurelinuxagent.common.osutil.default import DefaultOSUtil
except ImportError:
    # WAAgent <= 2.1.3
    import azurelinuxagent.logger as logger
    import azurelinuxagent.utils.shellutil as shellutil

    from azurelinuxagent.exception import OSUtilError
    from azurelinuxagent.distro.default.osutil import DefaultOSUtil


class BigIpOSUtil(DefaultOSUtil):
    def __init__(self):
        super(BigIpOSUtil, self).__init__()

    def _wait_until_mcpd_is_initialized(self):
        """Wait for mcpd to become available

        All configuration happens in mcpd so we need to wait that this is
        available before we go provisioning the system. I call this method
        at the first opportunity I have (during the DVD mounting call).
        This ensures that the rest of the provisioning does not need to wait
        for mcpd to be available unless it absolutely wants to.

        :return bool: Returns True upon success
        :raises OSUtilError: Raises exception if mcpd does not come up within
                             roughly 50 minutes (100 * 30 seconds)
        """
        for retries in range(1, 100):
            # Retry until mcpd completes startup:
            logger.info("Checking to see if mcpd is up")
            rc = shellutil.run("/usr/bin/tmsh -a show sys mcp-state field-fmt 2>/dev/null | grep phase | grep running", chk_err=False)
            if rc == 0:
                logger.info("mcpd is up!")
                break
            time.sleep(30)

        if rc is 0:
            return True

        raise OSUtilError(
            "mcpd hasn't completed initialization! Cannot proceed!"
        )

    def _save_sys_config(self):
        cmd = "/usr/bin/tmsh save sys config"
        rc = shellutil.run(cmd)
        if rc != 0:
            logger.error("WARNING: Cannot save sys config on 1st boot.")
        return rc

    def restart_ssh_service(self):
        return shellutil.run("/usr/bin/bigstart restart sshd", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("/sbin/service waagent stop", chk_err=False)

    def start_agent_service(self):
        return shellutil.run("/sbin/service waagent start", chk_err=False)

    def register_agent_service(self):
        return shellutil.run("/sbin/chkconfig --add waagent", chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("/sbin/chkconfig --del waagent", chk_err=False)

    def get_dhcp_pid(self):
        ret = shellutil.run_get_output("/sbin/pidof dhclient")
        return ret[1] if ret[0] == 0 else None

    def set_hostname(self, hostname):
        """Set the static hostname of the device

        Normally, tmsh is used to set the hostname for the system. For our
        purposes at this time though, I would hesitate to trust this function.

        Azure(Stack) uses the name that you provide in the Web UI or ARM (for
        example) as the value of the hostname argument to this method. The
        problem is that there is nowhere in the UI that specifies the
        restrictions and checks that tmsh has for the hostname.

        For example, if you set the name "bigip1" in the Web UI, Azure(Stack)
        considers that a perfectly valid name. When WAAgent gets around to
        running though, tmsh will reject that value because it is not a fully
        qualified domain name. The proper value should have been bigip.xxx.yyy

        WAAgent will not fail if this command fails, but the hostname will not
        be what the user set either. Currently we do not set the hostname when
        WAAgent starts up, so I am passing on setting it here too.

        :param hostname: The hostname to set on the device
        """
        return None

    def set_dhcp_hostname(self, hostname):
        """Sets the DHCP hostname

        See `set_hostname` for an explanation of why I pass here

        :param hostname: The hostname to set on the device
        """
        return None

    def useradd(self, username, expiration=None):
        """Create user account using tmsh

        Our policy is to create two accounts when booting a BIG-IP instance.
        The first account is the one that the user specified when they did
        the instance creation. The second one is the admin account that is,
        or should be, built in to the system.

        :param username: The username that you want to add to the system
        :param expiration: The expiration date to use. We do not use this
                           value.
        """
        if self.get_userentry(username):
            logger.info("User {0} already exists, skip useradd", username)
            return None

        cmd = "/usr/bin/tmsh create auth user %s partition-access add { all-partitions { role admin } } shell bash" % (username)
        retcode, out = shellutil.run_get_output(cmd, log_cmd=True, chk_err=True)
        if retcode != 0:
            raise OSUtilError(
                "Failed to create user account:{0}, retcode:{1}, output:{2}".format(username, retcode, out)
            )
        self._save_sys_config()
        return retcode

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        """Change a user's password with tmsh

        Since we are creating the user specified account and additionally
        changing the password of the built-in 'admin' account, both must
        be modified in this method.

        Note that the default method also checks for a "system level" of the
        user; based on the value of UID_MIN in /etc/login.defs. In our env,
        all user accounts have the UID 0. So we can't rely on this value.

        :param username: The username whose password to change
        :param password: The unencrypted password to set for the user
        :param crypt_id: If encrypting the password, the crypt_id that was used
        :param salt_len: If encrypting the password, the length of the salt
                         value used to do it.
        """

        # Start by setting the password of the user provided account
        cmd = "/usr/bin/tmsh modify auth user {0} password '{1}'".format(username, password)
        ret, output = shellutil.run_get_output(cmd, log_cmd=False, chk_err=True)
        if ret != 0:
            raise OSUtilError(
                "Failed to set password for {0}: {1}".format(username, output)
            )

        # Next, set the password of the built-in 'admin' account to be have
        # the same password as the user provided account
        userentry = self.get_userentry('admin')
        if userentry is None:
            raise OSUtilError("The 'admin' user account was not found!")

        cmd = "/usr/bin/tmsh modify auth user 'admin' password '{0}'".format(password)
        ret, output = shellutil.run_get_output(cmd, log_cmd=False, chk_err=True)
        if ret != 0:
            raise OSUtilError(
                "Failed to set password for 'admin': {0}".format(output)
            )
        self._save_sys_config()
        return ret

    def del_account(self, username):
        """Deletes a user account.

        Note that the default method also checks for a "system level" of the
        user; based on the value of UID_MIN in /etc/login.defs. In our env,
        all user accounts have the UID 0. So we can't rely on this value.

        We also don't use sudo, so we remove that method call as well.

        :param username:
        :return:
        """
        shellutil.run("> /var/run/utmp")
        shellutil.run("/usr/bin/tmsh delete auth user " + username)

    def get_dvd_device(self, dev_dir='/dev'):
        """Find BIG-IP's CD/DVD device

        This device is almost certainly /dev/cdrom so I added the ? to this pattern.
        Note that this method will return upon the first device found, but in my
        tests with 12.1.1 it will also find /dev/sr0 on occasion. This is NOT the
        correct CD/DVD device though.

        :todo: Consider just always returning "/dev/cdrom" here if that device device
               exists on all platforms that are supported on Azure(Stack)
        :param dev_dir: The root directory from which to look for devices
        """
        patten = r'(sr[0-9]|hd[c-z]|cdrom[0-9]?)'
        for dvd in [re.match(patten, dev) for dev in os.listdir(dev_dir)]:
            if dvd is not None:
                return "/dev/{0}".format(dvd.group(0))
        raise OSUtilError("Failed to get dvd device")

    def mount_dvd(self, **kwargs):
        """Mount the DVD containing the provisioningiso.iso file

        This is the _first_ hook that WAAgent provides for us, so this is the
        point where we should wait for mcpd to load. I am just overloading
        this method to add the mcpd wait. Then I proceed with the stock code.

        :param max_retry: Maximum number of retries waagent will make when
                          mounting the provisioningiso.iso DVD
        :param chk_err: Whether to check for errors or not in the mounting
                        commands
        """
        self._wait_until_mcpd_is_initialized()
        return super(BigIpOSUtil, self).mount_dvd(**kwargs)

    def eject_dvd(self, chk_err=True):
        """Runs the eject command to eject the provisioning DVD

        BIG-IP does not include an eject command. It is sufficient to just
        umount the DVD disk. But I will log that we do not support this for
        future reference.

        :param chk_err: Whether or not to check for errors raised by the eject
                        command
        """
        logger.warn("Eject is not supported on this platform")

    def get_first_if(self):
        """Return the interface name, and ip addr of the management interface.

        We need to add a struct_size check here because, curiously, our 64bit
        platform is identified by python in Azure(Stack) as 32 bit and without
        adjusting the struct_size, we can't get the information we need.

        I believe this may be caused by only python i686 being shipped with
        BIG-IP instead of python x86_64??
        """
        iface = ''
        expected = 16  # how many devices should I expect...

        python_arc = platform.architecture()[0]
        if python_arc == '64bit':
            struct_size = 40  # for 64bit the size is 40 bytes
        else:
            struct_size = 32  # for 32bit the size is 32 bytes
        sock = socket.socket(socket.AF_INET,
                             socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        buff = array.array('B', b'\0' * (expected * struct_size))
        param = struct.pack('iL',
                            expected*struct_size,
                            buff.buffer_info()[0])
        ret = fcntl.ioctl(sock.fileno(), 0x8912, param)
        retsize = (struct.unpack('iL', ret)[0])
        if retsize == (expected * struct_size):
            logger.warn(('SIOCGIFCONF returned more than {0} up '
                         'network interfaces.'), expected)
        sock = buff.tostring()
        for i in range(0, struct_size * expected, struct_size):
            iface = self._format_single_interface_name(sock, i)

            # Azure public was returning "lo:1" when deploying WAF
            if b'lo' in iface:
                continue
            else:
                break
        return iface.decode('latin-1'), socket.inet_ntoa(sock[i+20:i+24])

    def _format_single_interface_name(self, sock, offset):
        return sock[offset:offset+16].split(b'\0', 1)[0]

    def route_add(self, net, mask, gateway):
        """Add specified route using tmsh.

        :param net:
        :param mask:
        :param gateway:
        :return:
        """
        cmd = ("/usr/bin/tmsh create net route "
               "{0}/{1} gw {2}").format(net, mask, gateway)
        return shellutil.run(cmd, chk_err=False)

    def device_for_ide_port(self, port_id):
        """Return device name attached to ide port 'n'.

        Include a wait in here because BIG-IP may not have yet initialized
        this list of devices.

        :param port_id:
        :return:
        """
        for retries in range(1, 100):
            # Retry until devices are ready
            if os.path.exists("/sys/bus/vmbus/devices/"):
                break
            else:
                time.sleep(10)
        return super(BigIpOSUtil, self).device_for_ide_port(port_id)
