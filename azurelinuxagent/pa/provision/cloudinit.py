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
import os.path
import time

from datetime import datetime

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil

from azurelinuxagent.common.event import elapsed_milliseconds
from azurelinuxagent.common.exception import ProvisionError, ProtocolError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol import OVF_FILE_NAME
from azurelinuxagent.common.protocol.ovfenv import OvfEnv
from azurelinuxagent.pa.provision.default import ProvisionHandler


class CloudInitProvisionHandler(ProvisionHandler):
    def __init__(self):
        super(CloudInitProvisionHandler, self).__init__()

    def run(self):
        # If provision is enabled, run default provision handler
        if conf.get_provision_enabled():
            logger.warn("Provisioning flag is enabled, which overrides using "
                        "cloud-init; running the default provisioning code")
            super(CloudInitProvisionHandler, self).run()
            return

        try:
            if super(CloudInitProvisionHandler, self).is_provisioned():
                logger.info("Provisioning already completed, skipping.")
                return

            utc_start = datetime.utcnow()
            logger.info("Running CloudInit provisioning handler")
            self.wait_for_ovfenv()
            self.protocol_util.get_protocol()
            self.report_not_ready("Provisioning", "Starting")

            thumbprint = self.wait_for_ssh_host_key()
            self.write_provisioned()
            logger.info("Finished provisioning")

            self.report_ready(thumbprint)
            self.report_event("Provision succeed",
                is_success=True,
                duration=elapsed_milliseconds(utc_start))

        except ProvisionError as e:
            logger.error("Provisioning failed: {0}", ustr(e))
            self.report_not_ready("ProvisioningFailed", ustr(e))
            self.report_event(ustr(e))
            return

    def wait_for_ovfenv(self, max_retry=360, sleep_time=5):
        """
        Wait for cloud-init to copy ovf-env.xml file from provision ISO
        """
        ovf_file_path = os.path.join(conf.get_lib_dir(), OVF_FILE_NAME)
        for retry in range(0, max_retry):
            if os.path.isfile(ovf_file_path):
                try:
                    OvfEnv(fileutil.read_file(ovf_file_path))
                    return
                except ProtocolError as pe:
                    raise ProvisionError("OVF xml could not be parsed "
                                         "[{0}]: {1}".format(ovf_file_path,
                                                             ustr(pe)))
            else:
                if retry < max_retry - 1:
                    logger.info(
                        "Waiting for cloud-init to copy ovf-env.xml to {0} "
                        "[{1} retries remaining, "
                        "sleeping {2}s]".format(ovf_file_path,
                                                max_retry - retry,
                                                sleep_time))
                    if not self.validate_cloud_init():
                        logger.warn("cloud-init does not appear to be running")
                    time.sleep(sleep_time)
        raise ProvisionError("Giving up, ovf-env.xml was not copied to {0} "
                             "after {1}s".format(ovf_file_path,
                                                 max_retry * sleep_time))

    def wait_for_ssh_host_key(self, max_retry=360, sleep_time=5):
        """
        Wait for cloud-init to generate ssh host key
        """
        keypair_type = conf.get_ssh_host_keypair_type()
        path = conf.get_ssh_key_public_path()
        for retry in range(0, max_retry):
            if os.path.isfile(path):
                logger.info("ssh host key found at: {0}".format(path))
                try:
                    thumbprint = self.get_ssh_host_key_thumbprint(chk_err=False)
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
                if not self.validate_cloud_init():
                    logger.warn("cloud-init does not appear to be running")
                time.sleep(sleep_time)
        raise ProvisionError("Giving up, ssh host key was not found at {0} "
                             "after {1}s".format(path,
                                                 max_retry * sleep_time))
