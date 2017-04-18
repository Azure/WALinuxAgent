# Microsoft Azure Linux Agent
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
import time

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.exception import ProvisionError, ProtocolError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol import OVF_FILE_NAME
from azurelinuxagent.common.protocol.ovfenv import OvfEnv
from azurelinuxagent.pa.provision.default import ProvisionHandler

"""
On ubuntu image, provision could be disabled.
"""


class UbuntuProvisionHandler(ProvisionHandler):
    def __init__(self):
        super(UbuntuProvisionHandler, self).__init__()

    def run(self):
        # If provision is enabled, run default provision handler
        if conf.get_provision_enabled():
            logger.warn("Provisioning flag is enabled, this is not typical"
                        "in Ubuntu, please ensure your config is correct.")
            super(UbuntuProvisionHandler, self).run()
            return

        provisioned = os.path.join(conf.get_lib_dir(), "provisioned")
        if os.path.isfile(provisioned):
            logger.info("Provisioning already completed, skipping.")
            return

        logger.info("Running Ubuntu provisioning handler")
        self.wait_for_ovfenv()
        self.protocol_util.get_protocol()
        self.report_not_ready("Provisioning", "Starting")
        try:
            thumbprint = self.wait_for_ssh_host_key()
            fileutil.write_file(provisioned, "")
            logger.info("Finished provisioning")
        except ProvisionError as e:
            logger.error("Provisioning failed: {0}", e.message)
            self.report_not_ready("ProvisioningFailed", ustr(e.message))
            self.report_event(ustr(e.message))
            return

        self.report_ready(thumbprint)
        self.report_event("Provision succeed", is_success=True)

    def wait_for_ovfenv(self, max_retry=360, sleep_time=5):
        """
        Wait for cloud-init to copy ovf-env.xml file from provision ISO
        """
        ovf_file_path = os.path.join(conf.get_lib_dir(), OVF_FILE_NAME)
        for retry in range(0, max_retry):
            # debugging
            self.validate_cloud_init()

            if os.path.isfile(ovf_file_path):
                try:
                    OvfEnv(fileutil.read_file(ovf_file_path))
                    return
                except ProtocolError as pe:
                    raise ProvisionError("OVF xml could not be parsed "
                                         "[{0}]: {1}".format(ovf_file_path,
                                                             pe.message))
            else:
                if retry < max_retry - 1:
                    logger.info(
                        "Waiting for cloud-init to copy ovf-env.xml to {0} "
                        "[{1} retries remaining, "
                        "sleeping {2}s]".format(ovf_file_path,
                                                max_retry - retry,
                                                sleep_time))
                    time.sleep(sleep_time)
        raise ProvisionError("Giving up, ovf-env.xml was not copied to {0} "
                             "after {1}s".format(ovf_file_path,
                                                 max_retry * sleep_time))

    def wait_for_ssh_host_key(self, max_retry=360, sleep_time=5):
        """
        Wait for cloud-init to generate ssh host key
        """
        keypair_type = conf.get_ssh_host_keypair_type()
        path = '/etc/ssh/ssh_host_{0}_key.pub'.format(keypair_type)
        for retry in range(0, max_retry):
            if os.path.isfile(path):
                logger.info("ssh host key found at: {0}".format(path))
                try:
                    thumbprint = self.get_ssh_host_key_thumbprint(keypair_type, chk_err=False)
                    logger.info("Thumbprint obtained from : {0}".format(path))
                    return thumbprint
                except ProvisionError:
                    logger.warn("Could not get thumbprint from {0}".format(path))
            if retry < max_retry - 1:
                logger.info("Waiting for ssh host key be generated at {0} "
                            "[{1} attempts remaining, "
                            "sleeping {2}s]".format(path,
                                                    max_retry - retry,
                                                    sleep_time))
                time.sleep(sleep_time)
        raise ProvisionError("Giving up, ssh host key was not found at {0} "
                             "after {1}s".format(path,
                                                 max_retry * sleep_time))
