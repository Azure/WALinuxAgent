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

import glob
import os
import re
import time
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.rdma import RDMAHandler


class UbuntuRDMAHandler(RDMAHandler):

    def install_driver(self):
        #Install the appropriate driver package for the RDMA firmware

        nd_version = RDMAHandler.get_rdma_version()
        if not nd_version:
            logger.error("RDMA: Could not determine firmware version. No driver will be installed")
            return
        nd_version = re.sub('\..*', '', nd_version) #strip the trailing .*

        #Check to see if we need to reconfigure driver
        status,output = shellutil.run_get_output('modprobe -R hv_network_direct')
        if status != 0:
            logger.error("RDMA: modprobe -R hv_network_direct failed. Skip updating driver")
            return
        logger.info("RDMA: current RDMA driver %s nd_version %s" % (output, nd_version))
        if output == 'hv_netowrk_direct_%s' % nd_version:
            logger.info("RDMA: driver is installed and ND version matched. Skip reconfiguring driver")
            return

        #Reconfigure driver if one is available
        status,output = shellutil.run_get_output('modinfo hv_network_direct_%s' % nd_version);
        if status == 0:
            logger.info("RDMA: driver with ND version is installed. Link to module name")
            self.update_modprobed_conf(nd_version)
            return

	#Driver not found. We need to check to see if we need to update kernel
	if not conf.enable_rdma_update():
            logger.info("RDMA: driver update is disabled. Skip kernel update")
            return

        status,output = shellutil.run_get_output('uname -r')
        if status != 0:
            logger.error("RDMA: uname -r failed.")
            return
        kernel_version = re.sub('-azure$', '', output)

        #Find the new kernel package version
        status,output = shellutil.run_get_output('apt-get update')
        if status != 0:
            logger.error("RDMA: apt-get update failed.")
            return
        status,output = shellutil.run_get_output('apt show linux-azure')
        if status != 0:
            logger.error("RDMA: apt show linux-azure failed.")
            return
        r = re.search('Version: (\S+)', output)
        if not r:
            logger.error("RDMA: version not found in package linux-azure.")
            return
        package_version = r.groups()[0]

        logger.info('RDMA: kernel_version=%s package_version=%s' % (kernel_version, package_version))
        if kernel_version < package_version:
            logger.info("RDMA: newer version available, update kernel and reboot")
            status,output = shellutil.run_get_output('apt-get -y install linux-azure')
            if status:
                logger.error("RDMA: apt-get -y install linux-azure failed")
                logger.error("RDMA: %s" % output)
                logger.error("RDMA: kernel update failed")
                return
            self.reboot_system()
        else:
            logger.error("RDMA: no kernel update is avaiable for ND version %s" % nd_version)

    def update_modprobed_conf(self, nd_version):
        #Update /etc/modprobe.d/vmbus-rdma.conf to point to the correct driver

        modprobed_file = '/etc/modprobe.d/vmbus-rdma.conf'
        if not os.path.isfile(modprobed_file):
            logger.error("RDMA: % not found" % modprobed_file)
            logger.error("RDMA: modprobed black rule is required for Ubuntu")
            return

        f = open(modprobed_file, 'r')
        lines = f.read()
        f.close()
        r = re.search('alias hv_network_direct hv_network_direct_\S+', lines)
        if r:
            lines = re.sub('alias hv_network_direct hv_network_direct_\S+', 'alias hv_network_direct hv_network_direct_%s' % nd_version, lines)
        else:
            lines += '\nalias hv_network_direct hv_network_direct_%s' % nd_version
        f = open('/etc/modprobe.d/vmbus-rdma.conf', 'w')
        f.write(lines)
        f.close()
        logger.info("RDMA: hv_network_direct alias updated to ND %s" % nd_version)
