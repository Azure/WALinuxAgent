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
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text
import azurelinuxagent.conf as conf
import azurelinuxagent.protocol as prot
from azurelinuxagent.event import add_event, WALAEventOperation
from azurelinuxagent.exception import *
from azurelinuxagent.utils.osutil import OSUTIL
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.fileutil as fileutil
from azurelinuxagent.distro.default.provision import ProvisionHandler

"""
On ubuntu image, provision could be disabled.
"""
class UbuntuProvisionHandler(ProvisionHandler):
    def process(self):
        #If provision is enabled, run default provision handler
        if conf.get_switch("Provisioning.Enabled", False):
            super(UbuntuProvisionHandler, self).process()
            return

        logger.info("run Ubuntu provision handler")
        provisioned = os.path.join(OSUTIL.get_lib_dir(), "provisioned")
        if os.path.isfile(provisioned):
            return

        logger.info("Waiting cloud-init to finish provisioning.")
        protocol = prot.FACTORY.get_default_protocol()
        try:
            logger.info("Wait for ssh host key to be generated.")
            thumbprint = self.wait_for_ssh_host_key()
            fileutil.write_file(provisioned, "")

            logger.info("Finished provisioning")
            status = prot.ProvisionStatus(status="Ready")
            status.properties.certificateThumbprint = thumbprint
            try:
                protocol.report_provision_status(status)
            except prot.ProtocolError as pe:
                add_event(name="WALA", is_success=False, message=text(pe),
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

    def wait_for_ssh_host_key(self, max_retry=60):
        kepair_type = conf.get("Provisioning.SshHostKeyPairType", "rsa")
        path = '/etc/ssh/ssh_host_{0}_key'.format(kepair_type)
        for retry in range(0, max_retry):
            if os.path.isfile(path):
                return self.get_ssh_host_key_thumbprint(kepair_type)
            if retry < max_retry - 1:
                logger.info("Wait for ssh host key be generated: {0}", path)
                time.sleep(5)
        raise ProvisionError("Ssh hsot key is not generated.")
