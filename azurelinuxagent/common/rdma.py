# Windows Azure Linux Agent
#
# Copyright 2016 Microsoft Corporation
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

"""
Handle packages and modules to enable RDMA for IB networking
"""

import os
import re
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil


class RDMAHandler(object):

    driver_module_name = 'hv_network_direct'

    def __get_rdma_version(self):
        """Retrieve the firmware version information from the system.
           This depends on information provided by the Linux kernel."""

        driver_info_source = '/var/lib/hyperv/.kvp_pool_0'
        base_kernel_err_msg = 'Kernel does not provide the necessary '
        base_kernel_err_msg += 'information or the hv_kvp_daemon is not '
        base_kernel_err_msg += 'running.'
        if not os.path.isfile(driver_info_source):
            error_msg = 'Source file "%s" does not exist. '
            error_msg += base_kernel_err_msg
            logger.error(error_msg % driver_info_source)
            return

        lines = open(driver_info_source).read()
        if not lines:
            error_msg = 'Source file "%s" is empty. '
            error_msg += base_kernel_err_msg
            logger.error(error_msg % driver_info_source)
            return

        r = re.search("NdDriverVersion\0+(\d\d\d\.\d)", lines)
        if r:
            NdDriverVersion = r.groups()[0]
            return NdDriverVersion
        else:
            error_msg = 'NdDriverVersion not found in "%s"'
            logger.error(error_msg % driver_info_source)
            return

    def load_driver_module(self):
        """Load the kernel driver, this depends on the proper driver
           to be installed with the install_driver() method"""
        result = shellutil.run('modprobe %s' % self.driver_module_name)
        if result != 0:
            error_msg = 'Could not load "%s" kernel module. '
            error_msg += 'Run "modprobe %s" as root for more details'
            logger.error(
                error_msg % (self.driver_module_name, self.driver_module_name)
            )
            return

        return True

    def install_driver(self):
        """Install the driver. This is distribution specific and must
           be overwritten in the child implementation."""
        logger.error('RDMAHandler.install_driver not implemented')

    def is_driver_loaded(self):
        """Check if the network module is loaded in kernel space"""
        cmd = 'lsmod | grep %s' % self.driver_module_name
        status, loaded_modules = shellutil.run_get_output(cmd)
        if loaded_modules:
            return True

    def reboot_system(self):
        """Reboot the system. This is required as the kernel module for
           the rdma driver cannot be unloaded with rmmod"""
        logger.info('System reboot')
        shellutil.run('shutdown -r now')
