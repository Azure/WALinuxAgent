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

"""
Provision handler
"""

import os
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ProvisionError, ProtocolError, \
                                             OSUtilError
from azurelinuxagent.common.protocol.restapi import ProvisionStatus
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util

CUSTOM_DATA_FILE="CustomData"

class ProvisionHandler(object):

    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()

    def run(self):
        #If provision is not enabled, return
        if not conf.get_provision_enabled():
            logger.info("Provisioning is disabled. Skip.")
            return 

        provisioned = os.path.join(conf.get_lib_dir(), "provisioned")
        if os.path.isfile(provisioned):
            return

        logger.info("Run provision handler.")
        logger.info("Copy ovf-env.xml.")
        try:
            ovfenv = self.protocol_util.copy_ovf_env()
        except ProtocolError as e:
            self.report_event("Failed to copy ovf-env.xml: {0}".format(e))
            return
    
        self.protocol_util.get_protocol_by_file()

        self.report_not_ready("Provisioning", "Starting")
        
        try:
            logger.info("Start provisioning")
            self.provision(ovfenv)
            fileutil.write_file(provisioned, "")
            thumbprint = self.reg_ssh_host_key()
            logger.info("Finished provisioning")
        except ProvisionError as e:
            logger.error("Provision failed: {0}", e)
            self.report_not_ready("ProvisioningFailed", ustr(e))
            self.report_event(ustr(e))
            return

        self.report_ready(thumbprint)
        self.report_event("Provision succeed", is_success=True)
           
    def reg_ssh_host_key(self):
        keypair_type = conf.get_ssh_host_keypair_type()
        if conf.get_regenerate_ssh_host_key():
            shellutil.run("rm -f /etc/ssh/ssh_host_*key*")
            shellutil.run(("ssh-keygen -N '' -t {0} -f /etc/ssh/ssh_host_{1}_key"
                           "").format(keypair_type, keypair_type))
        thumbprint = self.get_ssh_host_key_thumbprint(keypair_type)
        return thumbprint

    def get_ssh_host_key_thumbprint(self, keypair_type):
        cmd = "ssh-keygen -lf /etc/ssh/ssh_host_{0}_key.pub".format(keypair_type)
        ret = shellutil.run_get_output(cmd)
        if ret[0] == 0:
            return ret[1].rstrip().split()[1].replace(':', '')
        else:
            raise ProvisionError(("Failed to generate ssh host key: "
                                  "ret={0}, out= {1}").format(ret[0], ret[1]))

    def provision(self, ovfenv):
        logger.info("Handle ovf-env.xml.")
        try:
            logger.info("Set host name.")
            self.osutil.set_hostname(ovfenv.hostname)

            logger.info("Publish host name.")
            self.osutil.publish_hostname(ovfenv.hostname)

            self.config_user_account(ovfenv)

            self.save_customdata(ovfenv)
            
            if conf.get_delete_root_password():
                self.osutil.del_root_password()

        except OSUtilError as e:
            raise ProvisionError("Failed to handle ovf-env.xml: {0}".format(e))
        
    def config_user_account(self, ovfenv):
        logger.info("Create user account if not exists")
        self.osutil.useradd(ovfenv.username)

        if ovfenv.user_password is not None:
            logger.info("Set user password.")
            crypt_id = conf.get_password_cryptid()
            salt_len = conf.get_password_crypt_salt_len()
            self.osutil.chpasswd(ovfenv.username, ovfenv.user_password,
                            crypt_id=crypt_id, salt_len=salt_len)
         
        logger.info("Configure sudoer")
        self.osutil.conf_sudoer(ovfenv.username, nopasswd=ovfenv.user_password is None)

        logger.info("Configure sshd")
        self.osutil.conf_sshd(ovfenv.disable_ssh_password_auth)

        #Disable selinux temporary
        sel = self.osutil.is_selinux_enforcing()
        if sel:
            self.osutil.set_selinux_enforce(0)

        self.deploy_ssh_pubkeys(ovfenv)
        self.deploy_ssh_keypairs(ovfenv)

        if sel:
            self.osutil.set_selinux_enforce(1)

        self.osutil.restart_ssh_service()

    def save_customdata(self, ovfenv):
        customdata = ovfenv.customdata
        if customdata is None:
            return

        logger.info("Save custom data")
        lib_dir = conf.get_lib_dir()
        if conf.get_decode_customdata():
            customdata= self.osutil.decode_customdata(customdata)

        customdata_file = os.path.join(lib_dir, CUSTOM_DATA_FILE)
        fileutil.write_file(customdata_file, customdata)
        
        if conf.get_execute_customdata():
            logger.info("Execute custom data")
            os.chmod(customdata_file, 0o700)
            shellutil.run(customdata_file)

    def deploy_ssh_pubkeys(self, ovfenv):
        for pubkey in ovfenv.ssh_pubkeys:
            logger.info("Deploy ssh public key.")
            self.osutil.deploy_ssh_pubkey(ovfenv.username, pubkey)

    def deploy_ssh_keypairs(self, ovfenv):
        for keypair in ovfenv.ssh_keypairs:
            logger.info("Deploy ssh key pairs.")
            self.osutil.deploy_ssh_keypair(ovfenv.username, keypair)

    def report_event(self, message, is_success=False):
        add_event(name="WALA", message=message, is_success=is_success,
                  op=WALAEventOperation.Provision)

    def report_not_ready(self, sub_status, description):
        status = ProvisionStatus(status="NotReady", subStatus=sub_status,
                                 description=description)
        try:
            protocol = self.protocol_util.get_protocol()
            protocol.report_provision_status(status)
        except ProtocolError as e:
            self.report_event(ustr(e))

    def report_ready(self, thumbprint=None):
        status = ProvisionStatus(status="Ready")
        status.properties.certificateThumbprint = thumbprint
        try:
            protocol = self.protocol_util.get_protocol()
            protocol.report_provision_status(status)
        except ProtocolError as e:
            self.report_event(ustr(e))

