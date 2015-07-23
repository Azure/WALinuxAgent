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
import azurelinuxagent.logger as logger
import azurelinuxagent.conf as conf
from azurelinuxagent.event import add_event, WALAEventOperation
from azurelinuxagent.exception import *
from azurelinuxagent.utils.osutil import OSUTIL
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
                                          subStatus="Provision started")
            protocol.report_provision_status(status)

            self.provision()
            fileutil.write_file(provisioned, "")
            thumbprint = self.reg_ssh_host_key()

            logger.info("Finished provisioning")
            status = prot.ProvisionStatus(status="Ready")
            status.properties.certificateThumbprint = thumbprint
            protocol.report_provision_status(status)

            add_event(name="WALA", is_success=True, message="",
                              op=WALAEventOperation.Provision)
        except ProvisionError as e:
            logger.error("Provision failed: {0}", e)
            status = prot.ProvisionStatus(status="NotReady",
                                          subStatus= str(e))
            protocol.report_provision_status(status)
            add_event(name="WALA", is_success=False, message=str(e),
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

        password = ovfenv.get_user_password()
        ovfenv.clear_user_password()

        logger.info("Set host name.")
        OSUTIL.set_hostname(ovfenv.get_computer_name())
        logger.info("Publish host name.")
        OSUTIL.publish_hostname(ovfenv.get_computer_name())
        logger.info("Create user account.")
        OSUTIL.set_user_account(ovfenv.get_username(), password)

        if password is not None:
            use_salt = conf.get_switch("Provision.UseSalt", True)
            salt_type = conf.get_switch("Provision.SaltType", 6)
            logger.info("Set user password.")
            OSUTIL.chpasswd(ovfenv.get_username(), password, use_salt,
                            salt_type)

        logger.info("Configure sshd.")
        OSUTIL.conf_sshd(ovfenv.get_disable_ssh_password_auth())

        #Disable selinux temporary
        sel = OSUTIL.is_selinux_enforcing()
        if sel:
            OSUTIL.set_selinux_enforce(0)

        self.deploy_ssh_pubkeys(ovfenv)
        self.deploy_ssh_keypairs(ovfenv)
        self.save_customdata(ovfenv)

        if sel:
            OSUTIL.set_selinux_enforce(1)

        OSUTIL.restart_ssh_service()

        if conf.get_switch("Provisioning.DeleteRootPassword"):
            OSUTIL.del_root_password()


    def save_customdata(self, ovfenv):
        logger.info("Save custom data")
        customdata = ovfenv.get_customdata()
        if customdata is None:
            return
        lib_dir = OSUTIL.get_lib_dir()
        fileutil.write_file(os.path.join(lib_dir, CUSTOM_DATA_FILE),
                            OSUTIL.decode_customdata(customdata))

    def deploy_ssh_pubkeys(self, ovfenv):
        for thumbprint, path in ovfenv.get_ssh_pubkeys():
            logger.info("Deploy ssh public key.")
            OSUTIL.deploy_ssh_pubkey(ovfenv.get_username(), thumbprint, path)

    def deploy_ssh_keypairs(self, ovfenv):
        for thumbprint, path in ovfenv.get_ssh_keypairs():
            logger.info("Deploy ssh key pairs.")
            OSUTIL.deploy_ssh_keypair(ovfenv.get_username(), thumbprint, path)

