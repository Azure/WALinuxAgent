#
# Copyright 2017 Check Point Software Technologies
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

import socket
import struct
import time

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.exception import OSUtilError
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class GaiaOSUtil(DefaultOSUtil):
    def __init__(self):
        super(GaiaOSUtil, self).__init__()

    def _run_clish(self, cmd, log_cmd=True):
        for i in xrange(10):
            ret, out = shellutil.run_get_output(
                "/bin/clish -s -c '" + cmd + "'", log_cmd=log_cmd)
            if not ret:
                break
            if 'NMSHST0025' in out:  # Entry for [hostname] already present
                ret = 0
                break
            time.sleep(2)
        return ret, out

    def useradd(self, username, expiration=None):
        logger.warn('useradd is not supported on GAiA')

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        logger.info('chpasswd')
        passwd_hash = textutil.gen_password_hash(password, crypt_id, salt_len)
        ret, out = self._run_clish(
            'set user admin password-hash ' + passwd_hash, log_cmd=False)
        if ret != 0:
            raise OSUtilError(("Failed to set password for {0}: {1}"
                               "").format('admin', out))

    def conf_sudoer(self, username, nopasswd=False, remove=False):
        logger.info('conf_sudoer is not supported on GAiA')

    def del_root_password(self):
        logger.info('del_root_password')
        ret, out = self._run_clish('set user admin password-hash *LOCK*')
        if ret != 0:
            raise OSUtilError("Failed to delete root password")

    def _replace_user(path, username):
        parts = path.split('/')
        for i in xrange(len(parts)):
            if parts[i] == '$HOME':
                parts[i + 1] = username
                break
        return '/'.join(parts)

    def deploy_ssh_keypair(self, username, keypair):
        logger.info('deploy_ssh_keypair')
        username = 'admin'
        path, thumbprint = keypair
        path = self._replace_user(path, username)
        super(GaiaOSUtil, self).deploy_ssh_keypair(
            username, (path, thumbprint))

    def deploy_ssh_pubkey(self, username, pubkey):
        logger.info('deploy_ssh_pubkey')
        username = 'admin'
        path, thumbprint, value = pubkey
        path = self._replace_user(path, username)
        super(GaiaOSUtil, self).deploy_ssh_pubkey(
            'admin', (path, thumbprint, value))

    def eject_dvd(self, chk_err=True):
        logger.warn('eject is not supported on GAiA')

    def mount(self, dvd, mount_point, option="", chk_err=True):
        logger.info('mount {0} {1} {2}', dvd, mount_point, option)
        if 'udf,iso9660' in option:
            ret, out = super(GaiaOSUtil, self).mount(
                dvd, mount_point, option=option.replace('udf,iso9660', 'udf'),
                chk_err=chk_err)
            if not ret:
                return ret, out
        return super(GaiaOSUtil, self).mount(
            dvd, mount_point, option=option, chk_err=chk_err)

    def allow_dhcp_broadcast(self):
        logger.info('allow_dhcp_broadcast is ignored on GAiA')

    def remove_rules_files(self, rules_files=''):
        pass

    def restore_rules_files(self, rules_files=''):
        logger.info('restore_rules_files is ignored on GAiA')

    def restart_ssh_service(self):
        return shellutil.run('/sbin/service sshd condrestart', chk_err=False)

    def _address_to_string(addr):
        return socket.inet_ntoa(struct.pack("!I", addr))

    def _get_prefix(self, mask):
        return str(sum([bin(int(x)).count('1') for x in mask.split('.')]))

    def route_add(self, net, mask, gateway):
        logger.info('route_add {0} {1} {2}', net, mask, gateway)

        if net == 0 and mask == 0:
            cidr = 'default'
        else:
            cidr = self._address_to_string(net) + '/' + self._get_prefix(
                self._address_to_string(mask))

        ret, out = self._run_clish(
            'set static-route ' + cidr +
            ' nexthop gateway address ' +
            self._address_to_string(gateway) + ' on')
        return ret

    def set_hostname(self, hostname):
        logger.warn('set_hostname is ignored on GAiA')

    def set_dhcp_hostname(self, hostname):
        logger.warn('set_dhcp_hostname is ignored on GAiA')

    def publish_hostname(self, hostname):
        logger.warn('publish_hostname is ignored on GAiA')

    def del_account(self, username):
        logger.warn('del_account is ignored on GAiA')

    def set_admin_access_to_ip(self, dest_ip):
        logger.warn('set_admin_access_to_ip is ignored on GAiA')
