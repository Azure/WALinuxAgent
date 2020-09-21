# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
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

import glob # pylint: disable=W0611
import os
import re
import time # pylint: disable=W0611
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.rdma import RDMAHandler


class UbuntuRDMAHandler(RDMAHandler):

    def install_driver(self): # pylint: disable=R0912,R0911
        #Install the appropriate driver package for the RDMA firmware

        nd_version = self.get_rdma_version()
        if not nd_version:
            logger.error("RDMA: Could not determine firmware version. No driver will be installed")
            return
        #replace . with _, we are looking for number like 144_0
        nd_version = re.sub('\.', '_', nd_version) # pylint: disable=W1401

        #Check to see if we need to reconfigure driver
        status,module_name = shellutil.run_get_output('modprobe -R hv_network_direct', chk_err=False)
        if status != 0:
            logger.info("RDMA: modprobe -R hv_network_direct failed. Use module name hv_network_direct")
            module_name = "hv_network_direct"
        else:
            module_name = module_name.strip()
        logger.info("RDMA: current RDMA driver %s nd_version %s" % (module_name, nd_version))
        if module_name == 'hv_network_direct_%s' % nd_version:
            logger.info("RDMA: driver is installed and ND version matched. Skip reconfiguring driver")
            return

        #Reconfigure driver if one is available
        status,output = shellutil.run_get_output('modinfo hv_network_direct_%s' % nd_version); # pylint: disable=W0301
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
            return
        if not re.search('-azure$', output):
            logger.error("RDMA: skip driver update on non-Azure kernel")
            return
        kernel_version = re.sub('-azure$', '', output)
        kernel_version = re.sub('-', '.', kernel_version)

        #Find the new kernel package version
        status,output = shellutil.run_get_output('apt-get update')
        if status != 0:
            return
        status,output = shellutil.run_get_output('apt-cache show --no-all-versions linux-azure')
        if status != 0:
            return
        r = re.search('Version: (\S+)', output) # pylint: disable=W1401,C0103
        if not r:
            logger.error("RDMA: version not found in package linux-azure.")
            return
        package_version = r.groups()[0]
        #Remove the ending .<upload number> after <ABI number>
        package_version = re.sub("\.\d+$", "", package_version) # pylint: disable=W1401

        logger.info('RDMA: kernel_version=%s package_version=%s' % (kernel_version, package_version))
        kernel_version_array = [ int(x) for x in kernel_version.split('.') ]
        package_version_array = [ int(x) for x in package_version.split('.') ]
        if kernel_version_array < package_version_array:
            logger.info("RDMA: newer version available, update kernel and reboot")
            status,output = shellutil.run_get_output('apt-get -y install linux-azure')
            if status:
                logger.error("RDMA: kernel update failed")
                return
            self.reboot_system()
        else:
            logger.error("RDMA: no kernel update is avaiable for ND version %s" % nd_version)

    def update_modprobed_conf(self, nd_version):
        #Update /etc/modprobe.d/vmbus-rdma.conf to point to the correct driver

        modprobed_file = '/etc/modprobe.d/vmbus-rdma.conf'
        lines = ''
        if not os.path.isfile(modprobed_file):
            logger.info("RDMA: %s not found, it will be created" % modprobed_file)
        else:
            f = open(modprobed_file, 'r') # pylint: disable=C0103
            lines = f.read()
            f.close()
        r = re.search('alias hv_network_direct hv_network_direct_\S+', lines) # pylint: disable=W1401,C0103
        if r:
            lines = re.sub('alias hv_network_direct hv_network_direct_\S+', 'alias hv_network_direct hv_network_direct_%s' % nd_version, lines) # pylint: disable=W1401
        else:
            lines += '\nalias hv_network_direct hv_network_direct_%s\n' % nd_version
        f = open('/etc/modprobe.d/vmbus-rdma.conf', 'w') # pylint: disable=C0103
        f.write(lines)
        f.close()
        logger.info("RDMA: hv_network_direct alias updated to ND %s" % nd_version)
