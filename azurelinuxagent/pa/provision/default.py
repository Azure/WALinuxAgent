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
import os.path
import re

from datetime import datetime

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.event import add_event, WALAEventOperation, \
    elapsed_milliseconds
from azurelinuxagent.common.exception import ProvisionError, ProtocolError, \
    OSUtilError
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.restapi import ProvisionStatus
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.version import AGENT_NAME

CUSTOM_DATA_FILE = "CustomData"
CLOUD_INIT_PATTERN = b".*/bin/cloud-init.*"
CLOUD_INIT_REGEX = re.compile(CLOUD_INIT_PATTERN)

PROVISIONED_FILE = 'provisioned'


class ProvisionHandler(object):
    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()

    def run(self):
        # If provision is not enabled, report ready and then return
        if not conf.get_provision_enabled():
            logger.info("Provisioning is disabled, skipping.")
            return

        try:
            utc_start = datetime.utcnow()
            thumbprint = None

            # if provisioning is already done, return
            if self.is_provisioned():
                logger.info("Provisioning already completed, skipping.")
                return

            logger.info("Running default provisioning handler")

            if not self.validate_cloud_init(is_expected=False):
                raise ProvisionError("cloud-init appears to be running, "
                                        "this is not expected, cannot continue")

            logger.info("Copying ovf-env.xml")
            ovf_env = self.protocol_util.copy_ovf_env()

            self.protocol_util.get_protocol_by_file()
            self.report_not_ready("Provisioning", "Starting")
            logger.info("Starting provisioning")

            self.provision(ovf_env)

            thumbprint = self.reg_ssh_host_key()
            self.osutil.restart_ssh_service()

            # write out provisioned file and report Ready
            self.write_provisioned()

            self.report_event("Provision succeed",
                is_success=True,
                duration=elapsed_milliseconds(utc_start))

            self.report_ready(thumbprint)
            logger.info("Provisioning complete")

        except (ProtocolError, ProvisionError) as e:
            self.report_not_ready("ProvisioningFailed", ustr(e))
            self.report_event(ustr(e))
            logger.error("Provisioning failed: {0}", ustr(e))
            return

    @staticmethod
    def validate_cloud_init(is_expected=True):
        is_running = False
        if os.path.isdir("/proc"):
            pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
        else:
            pids = []
        for pid in pids:
            try:
                pname = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read()
                if CLOUD_INIT_REGEX.match(pname):
                    is_running = True
                    msg = "cloud-init is running [PID {0}, {1}]".format(pid,
                                                                        pname)
                    if is_expected:
                        logger.verbose(msg)
                    else:
                        logger.error(msg)
                    break
            except IOError:
                continue
        return is_running == is_expected

    def reg_ssh_host_key(self):
        keypair_type = conf.get_ssh_host_keypair_type()
        if conf.get_regenerate_ssh_host_key():
            fileutil.rm_files(conf.get_ssh_key_glob())
            if conf.get_ssh_host_keypair_mode() == "auto":
                '''
                The -A option generates all supported key types.
                This is supported since OpenSSH 5.9 (2011).
                '''
                shellutil.run("ssh-keygen -A")
            else:
                keygen_cmd = "ssh-keygen -N '' -t {0} -f {1}"
                shellutil.run(keygen_cmd.
                              format(keypair_type,
                                     conf.get_ssh_key_private_path()))
        return self.get_ssh_host_key_thumbprint()

    def get_ssh_host_key_thumbprint(self, chk_err=True):
        cmd = "ssh-keygen -lf {0}".format(conf.get_ssh_key_public_path())
        ret = shellutil.run_get_output(cmd, chk_err=chk_err)
        if ret[0] == 0:
            return ret[1].rstrip().split()[1].replace(':', '')
        else:
            raise ProvisionError(("Failed to generate ssh host key: "
                                  "ret={0}, out= {1}").format(ret[0], ret[1]))

    def provisioned_file_path(self):
        return os.path.join(conf.get_lib_dir(), PROVISIONED_FILE)

    def is_provisioned(self):
        '''
        A VM is considered provisionend *anytime* the provisioning
        sentinel file exists and not provisioned *anytime* the file
        is absent.

        If the VM was provisioned using an agent that did not record
        the VM unique identifier, the provisioning file will be re-written
        to include the identifier.

        A warning is logged *if* the VM unique identifier has changed
        since VM was provisioned.
        '''
        if not os.path.isfile(self.provisioned_file_path()):
            return False

        s = fileutil.read_file(self.provisioned_file_path()).strip()
        if s != self.osutil.get_instance_id():
            if len(s) > 0:
                logger.warn("VM is provisioned, "
                            "but the VM unique identifier has changed -- "
                            "clearing cached state")
                from azurelinuxagent.pa.deprovision \
                    import get_deprovision_handler
                deprovision_handler = get_deprovision_handler()
                deprovision_handler.run_changed_unique_id()

            self.write_provisioned()
            self.report_ready()

        return True

    def write_provisioned(self):
        fileutil.write_file(
            self.provisioned_file_path(),
            get_osutil().get_instance_id())

    def provision(self, ovfenv):
        logger.info("Handle ovf-env.xml.")
        try:
            logger.info("Set hostname [{0}]".format(ovfenv.hostname))
            self.osutil.set_hostname(ovfenv.hostname)

            logger.info("Publish hostname [{0}]".format(ovfenv.hostname))
            self.osutil.publish_hostname(ovfenv.hostname)

            self.config_user_account(ovfenv)

            self.save_customdata(ovfenv)

            if conf.get_delete_root_password():
                self.osutil.del_root_password()

        except OSUtilError as e:
            raise ProvisionError("Failed to provision: {0}".format(ustr(e)))

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
        self.osutil.conf_sudoer(ovfenv.username,
                                nopasswd=ovfenv.user_password is None)

        logger.info("Configure sshd")
        self.osutil.conf_sshd(ovfenv.disable_ssh_password_auth)

        self.deploy_ssh_pubkeys(ovfenv)
        self.deploy_ssh_keypairs(ovfenv)

    def save_customdata(self, ovfenv):
        customdata = ovfenv.customdata
        if customdata is None:
            return

        lib_dir = conf.get_lib_dir()
        if conf.get_decode_customdata() or conf.get_execute_customdata():
            logger.info("Decode custom data")
            customdata = self.osutil.decode_customdata(customdata)

        logger.info("Save custom data")
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

    def report_event(self, message, is_success=False, duration=0):
        add_event(name=AGENT_NAME,
                    message=message,
                    duration=duration,
                    is_success=is_success,
                    op=WALAEventOperation.Provision)

    def report_not_ready(self, sub_status, description):
        status = ProvisionStatus(status="NotReady", subStatus=sub_status,
                                 description=description)
        try:
            protocol = self.protocol_util.get_protocol()
            protocol.report_provision_status(status)
        except ProtocolError as e:
            logger.error("Reporting NotReady failed: {0}", e)
            self.report_event(ustr(e))

    def report_ready(self, thumbprint=None):
        status = ProvisionStatus(status="Ready")
        status.properties.certificateThumbprint = thumbprint
        try:
            protocol = self.protocol_util.get_protocol()
            protocol.report_provision_status(status)
        except ProtocolError as e:
            logger.error("Reporting Ready failed: {0}", e)
            self.report_event(ustr(e))
