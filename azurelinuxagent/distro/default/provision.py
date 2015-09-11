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
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text
import azurelinuxagent.conf as conf
from azurelinuxagent.event import add_event, WALAEventOperation
from azurelinuxagent.exception import *
from azurelinuxagent.utils.osutil import OSUTIL, OSUtilError
import azurelinuxagent.protocol as prot
import azurelinuxagent.protocol.ovfenv as ovf
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.fileutil as fileutil

CUSTOM_DATA_FILE="CustomData"

class ProvisionHandler(object):

    def process(self):
        #If provision is not enabled, return
        if not conf.get_switch("Provisioning.Enabled", True):
            logger.info("Provisioning is disabled. Skip.")
            return

        provisioned = os.path.join(OSUTIL.get_lib_dir(), "provisioned")
        if os.path.isfile(provisioned):
            return

        logger.info("run provision handler.")
        protocol = prot.FACTORY.get_default_protocol()
        try:
            status = prot.ProvisionStatus(status="NotReady",
                                          subStatus="Provisioning",
                                          description="Starting")
            try:
                protocol.report_provision_status(status)
            except prot.ProtocolError as e:
                add_event(name="WALA", is_success=False, message=text(e),
                          op=WALAEventOperation.Provision)

            self.provision()
            fileutil.write_file(provisioned, "")
            thumbprint = self.reg_ssh_host_key()

            logger.info("Finished provisioning")
            status = prot.ProvisionStatus(status="Ready")
            status.properties.certificateThumbprint = thumbprint

            try:
                protocol.report_provision_status(status)
            except prot.ProtocolError as pe:
                add_event(name="WALA", is_success=False, message=text(pe),
                          op=WALAEventOperation.Provision)

            add_event(name="WALA", is_success=True, message="",
                      op=WALAEventOperation.Provision)
        except ProvisionError as e:
            logger.error("Provision failed: {0}", e)
            status = prot.ProvisionStatus(status="NotReady",
                                          subStatus="ProvisioningFailed",
                                          description= text(e))
            try:
                protocol.report_provision_status(status)
            except prot.ProtocolError as pe:
                add_event(name="WALA", is_success=False, message=text(pe),
                          op=WALAEventOperation.Provision)

            add_event(name="WALA", is_success=False, message=text(e),
                      op=WALAEventOperation.Provision)

    def reg_ssh_host_key(self):
        keypair_type = conf.get("Provisioning.SshHostKeyPairType", "rsa")
        if conf.get_switch("Provisioning.RegenerateSshHostKeyPair"):
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


    def provision(self):
        logger.info("Copy ovf-env.xml.")
        try:
            ovfenv = ovf.copy_ovf_env()
        except prot.ProtocolError as e:
            raise ProvisionError("Failed to copy ovf-env.xml: {0}".format(e))
    
        logger.info("Handle ovf-env.xml.")
        try:
            logger.info("Set host name.")
            OSUTIL.set_hostname(ovfenv.hostname)

            logger.info("Publish host name.")
            OSUTIL.publish_hostname(ovfenv.hostname)

            self.config_user_account(ovfenv)

            self.save_customdata(ovfenv)

            if conf.get_switch("Provisioning.DeleteRootPassword"):
                OSUTIL.del_root_password()
        except OSUtilError as e:
            raise ProvisionError("Failed to handle ovf-env.xml: {0}".format(e))
        
    def config_user_account(self, ovfenv):
        logger.info("Create user account if not exists")
        OSUTIL.useradd(ovfenv.username)

        if ovfenv.user_password is not None:
            logger.info("Set user password.")
            crypt_id = conf.get("Provision.PasswordCryptId", "6")
            salt_len = conf.get_int("Provision.PasswordCryptSaltLength", 10)
            OSUTIL.chpasswd(ovfenv.username, ovfenv.user_password,
                            crypt_id=crypt_id, salt_len=salt_len)
         
        logger.info("Configure sudoer")
        OSUTIL.conf_sudoer(ovfenv.username, ovfenv.user_password is None)

        logger.info("Configure sshd")
        OSUTIL.conf_sshd(ovfenv.disable_ssh_password_auth)

        #Disable selinux temporary
        sel = OSUTIL.is_selinux_enforcing()
        if sel:
            OSUTIL.set_selinux_enforce(0)

        self.deploy_ssh_pubkeys(ovfenv)
        self.deploy_ssh_keypairs(ovfenv)

        if sel:
            OSUTIL.set_selinux_enforce(1)

        OSUTIL.restart_ssh_service()

    def save_customdata(self, ovfenv):
        logger.info("Save custom data")
        customdata = ovfenv.customdata
        if customdata is None:
            return
        lib_dir = OSUTIL.get_lib_dir()
        fileutil.write_file(os.path.join(lib_dir, CUSTOM_DATA_FILE),
                            OSUTIL.decode_customdata(customdata))

    def deploy_ssh_pubkeys(self, ovfenv):
        for pubkey in ovfenv.ssh_pubkeys:
            logger.info("Deploy ssh public key.")
            OSUTIL.deploy_ssh_pubkey(ovfenv.username, pubkey)

    def deploy_ssh_keypairs(self, ovfenv):
        for keypair in ovfenv.ssh_keypairs:
            logger.info("Deploy ssh key pairs.")
            OSUTIL.deploy_ssh_keypair(ovfenv.username, keypair)

