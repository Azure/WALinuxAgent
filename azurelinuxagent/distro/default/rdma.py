# Windows Azure Linux Agent
#
# Copyright 2016 Microsoft Corporation, SUSE LLC, Robert Schweikert
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
import azurelinuxagent.logger as logger


class RDMAHandler(object):
    def __get_rdma_version(self):
        """Retrieve the firmware version information from the system.
           This depends on information provided by the Linux kernel."""

        driver_info_source = '/var/lib/hyperv/.kvp_pool_0'
        base_kernel_err_msg = 'Kernel does not provide the necessary '
        base_kernel_err_msg += 'information or the hv_kvp_daemon is not '
        base_kernel_err_msg += 'running.'
        if not os.path.exists(driver_info_source):
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

    def initialize_driver(self):
        """Load the kernel driver, this depends on the proper driver
           to be installed with the install_driver() method"""
        driver_module_name = 'modprobe hv_network_direct'
        result = os.system(driver_module_name)
        if result != 0:
            error_msg = 'Could not load "%s" kernel module. '
            error_msg += 'Run "modprobe %s" as root for more details'
            logger.error(error_msg % (driver_module_name, driver_module_name))
            return

        return True

    def install_driver(self):
        """Install the driver. This is distribution specific and must
           be overwritted in the child implementation."""

        raise Exception('RDMAHandler.install_driver not implemented')
