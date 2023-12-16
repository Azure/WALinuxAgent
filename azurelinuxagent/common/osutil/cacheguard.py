#
# Copyright 2023 CacheGuard Technologies Ltd
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

import os

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil

from azurelinuxagent.common import conf
from azurelinuxagent.common.osutil.default import DefaultOSUtil

CLOUD_PROVISIONED_FILE = '.cloud-provisioned'

class CacheGuardOSUtil( DefaultOSUtil ):

    def __init__( self ):
        super( CacheGuardOSUtil, self ).__init__( )
        self.jit_enabled = True

    def _test( self ):
        logger.warn( "Hello CacheGuard" )
        return True

    def _provisioned_file_path( self ):
        return os.path.join( conf.get_lib_dir( ), CLOUD_PROVISIONED_FILE )

    def is_provisioned( self ):
        return os.path.isfile( self._provisioned_file_path( ))

    def _run_cli( self, cg_command ):
        try:
            command = ["su", "--login", "admin", "--command", cg_command]
            shellutil.run_command( command, log_error=True )

        except shellutil.CommandError as command_error:
            return command_error.returncode

        except Exception as error:
            logger.warn( "Could not perform this CacheGuard command: {0}".format( error ))
            return 1

        return 0

    def _run_apply( self ):
        if not self.is_provisioned( ):
            return 0

        try:
            command = ["apl_apply"]
            shellutil.run_command( command, log_error=True )

        except shellutil.CommandError as command_error:
            return command_error.returncode

        except Exception as error:
            logger.warn( "Could not perform this internal CacheGuard command: {0}".format( error ))
            return 1

        return 0

    def _run_cli_apply( self, command ):
        ret = self._run_cli( command )
        if ret == 0:
            ret = self._run_apply( )
        return ret

    def _chpasswd( self, username, password, crypt_id=6, salt_len=10 ):
        try:
            command = ["apl_change_password", username, password]
            shellutil.run_command( command, log_error=True )

        except shellutil.CommandError as command_error:
            return command_error.returncode

        except Exception as error:
            logger.warn( "Could not perform this internal CacheGuard command: {0}".format( error ))
            return 1

        return 0

    def stop_agent_service( self ):
        return 0

    def start_agent_service( self ):
        return 0

    def get_firewall_dropped_packets( self, dst_ip=None ):
        return 0

    def remove_firewall( self, dst_ip, uid, wait ):
        return True

    def remove_legacy_firewall_rule( self, dst_ip ):
        return True

    def enable_firewall( self, dst_ip, uid ):
        return True

    def get_firewall_list( self, wait=None ):
        return ""

    def is_selinux_enforcing( self ):
        return False

    def set_selinux_context( self, path, con ):
        return 0

    def conf_sshd( self, disable_password ):
        return

    def set_route_for_dhcp_broadcast(self, ifname):
        return ""

    def remove_route_for_dhcp_broadcast( self, ifname):
        pass

    def restart_if( self, ifname, retries=3, wait=5):
        return

    def useradd( self, username, expiration=None, comment=None ):
        return 0

    def eject_dvd( self, chk_err=True ):
        return 0

    def chpasswd( self, username, password, crypt_id=6, salt_len=10 ):
        if username == 'azure':
            username = 'admin'
        self._chpasswd( username, password, crypt_id, salt_len )

    def conf_sudoer( self, username, nopasswd=False, remove=False ):
        return

    def del_root_password( self ):
        return

    def deploy_ssh_keypair( self, username, keypair ):
        return

    def deploy_ssh_pubkey( self, username, pubkey ):
        ssh_key_id = username
        username = 'admin'
        ssh_key_id = 'Azure'
        self._run_cli( 'admin ssh key add ' + ssh_key_id )
        path, thumbprint, value = pubkey
        admin_dir = '/usr/local/home/' + username
        admin_tmp_dir = admin_dir + '/tmp'
        ssh_key_tmp_file = admin_tmp_dir + '/loaded.ssh.key.' + ssh_key_id
        fileutil.write_file( ssh_key_tmp_file, value )
        self._run_apply( )

    def allow_dhcp_broadcast( self ):
        return 0

    def remove_rules_files( self, rules_files = '' ):
        return 0

    def restore_rules_files( self, rules_files = '' ):
        return 0

    def restart_ssh_service(self):
        return 0

    def route_add( self, network, mask, gateway ):
        self._run_cli_apply( 'ip route add ' + network + ' ' + mask + ' ' + gateway )

    def set_hostname( self, hostname ):
        self._run_cli_apply( 'hostname ' + hostname )

    def set_dhcp_hostname( self, hostname ):
        return None

    def del_account( self, username ):
        return 0
