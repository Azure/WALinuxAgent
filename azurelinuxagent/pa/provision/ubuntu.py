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
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.protocol.ovfenv as ovfenv
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ProvisionError, ProtocolError
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.pa.provision.default import ProvisionHandler

"""
On ubuntu image, provision could be disabled.
"""
class UbuntuProvisionHandler(ProvisionHandler):
    def __init__(self):
        super(UbuntuProvisionHandler, self).__init__()

    def run(self):
        #If provision is enabled, run default provision handler
        if conf.get_provision_enabled():
            super(UbuntuProvisionHandler, self).run()
            return

        logger.info("run Ubuntu provision handler")
        provisioned = os.path.join(conf.get_lib_dir(), "provisioned")
        if os.path.isfile(provisioned):
            return

        logger.info("Waiting cloud-init to copy ovf-env.xml.")
        self.wait_for_ovfenv()

        protocol = self.protocol_util.get_protocol()
        self.report_not_ready("Provisioning", "Starting")
        logger.info("Sleep 15 seconds to prevent throttling")
        time.sleep(15) #Sleep to prevent throttling
        try:
            logger.info("Wait for ssh host key to be generated.")
            thumbprint = self.wait_for_ssh_host_key()
            fileutil.write_file(provisioned, "")
            logger.info("Finished provisioning")
           
        except ProvisionError as e:
            logger.error("Provision failed: {0}", e)
            self.report_not_ready("ProvisioningFailed", ustr(e))
            self.report_event(ustr(e))
            return
            
        self.report_ready(thumbprint)
        self.report_event("Provision succeed", is_success=True)

    def wait_for_ovfenv(self, max_retry=60):
        """
        Wait for cloud-init to copy ovf-env.xml file from provision ISO
        """
        for retry in range(0, max_retry):
            try:
                self.protocol_util.get_ovf_env()
                return
            except ProtocolError:
                if retry < max_retry - 1:
                    logger.info("Wait for cloud-init to copy ovf-env.xml")
                    time.sleep(5)
        raise ProvisionError("ovf-env.xml is not copied")

    def wait_for_ssh_host_key(self, max_retry=60):
        """
        Wait for cloud-init to generate ssh host key
        """
        kepair_type = conf.get_ssh_host_keypair_type()
        path = '/etc/ssh/ssh_host_{0}_key'.format(kepair_type)
        for retry in range(0, max_retry):
            if os.path.isfile(path):
                return self.get_ssh_host_key_thumbprint(kepair_type)
            if retry < max_retry - 1:
                logger.info("Wait for ssh host key be generated: {0}", path)
                time.sleep(5)
        raise ProvisionError("Ssh hsot key is not generated.")
