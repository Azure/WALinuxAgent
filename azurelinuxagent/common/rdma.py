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
import threading
import time
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil

dapl_config_paths = ['/etc/dat.conf', '/etc/rdma/dat.conf',
                     '/usr/local/etc/dat.conf']


class RDMAHandler(object):

    driver_module_name = 'hv_network_direct'

    @staticmethod
    def get_rdma_version():
        """Retrieve the firmware version information from the system.
           This depends on information provided by the Linux kernel."""

        driver_info_source = '/var/lib/hyperv/.kvp_pool_0'
        base_kernel_err_msg = 'Kernel does not provide the necessary '
        base_kernel_err_msg += 'information or the hv_kvp_daemon is not '
        base_kernel_err_msg += 'running.'
        if not os.path.isfile(driver_info_source):
            error_msg = 'RDMA: Source file "%s" does not exist. '
            error_msg += base_kernel_err_msg
            logger.error(error_msg % driver_info_source)
            return

        lines = open(driver_info_source).read()
        if not lines:
            error_msg = 'RDMA: Source file "%s" is empty. '
            error_msg += base_kernel_err_msg
            logger.error(error_msg % driver_info_source)
            return

        r = re.search("NdDriverVersion\0+(\d\d\d\.\d)", lines)
        if r:
            NdDriverVersion = r.groups()[0]
            return NdDriverVersion
        else:
            error_msg = 'RDMA: NdDriverVersion not found in "%s"'
            logger.error(error_msg % driver_info_source)
            return

    def load_driver_module(self):
        """Load the kernel driver, this depends on the proper driver
           to be installed with the install_driver() method"""
        logger.info('RDMA: Loading the kernel driver.')
        result = shellutil.run('modprobe %s' % self.driver_module_name)
        if result != 0:
            error_msg = 'Could not load "%s" kernel module. '
            error_msg += 'Run "modprobe %s" as root for more details'
            logger.error(
                error_msg % (self.driver_module_name, self.driver_module_name)
            )
            return
        logger.info('RDMA: Loaded the kernel driver successfully.')
        return True

    def install_driver(self):
        """Install the driver. This is distribution specific and must
           be overwritten in the child implementation."""
        logger.error('RDMAHandler.install_driver not implemented')

    def is_driver_loaded(self):
        """Check if the network module is loaded in kernel space"""
        cmd = 'lsmod | grep %s' % self.driver_module_name
        status, loaded_modules = shellutil.run_get_output(cmd)
        logger.info('RDMA: Checking if the module loaded.')
        if loaded_modules:
            logger.info('RDMA: module loaded.')
            return True
        logger.info('RDMA: module not loaded.')

    def reboot_system(self):
        """Reboot the system. This is required as the kernel module for
           the rdma driver cannot be unloaded with rmmod"""
        logger.info('RDMA: Rebooting system.')
        ret = shellutil.run('shutdown -r now')
        if ret != 0:
            logger.error('RDMA: Failed to reboot the system')


dapl_config_paths = [
    '/etc/dat.conf', '/etc/rdma/dat.conf', '/usr/local/etc/dat.conf']

class RDMADeviceHandler(object):

    """
    Responsible for writing RDMA IP and MAC address to the /dev/hvnd_rdma
    interface.
    """

    rdma_dev = '/dev/hvnd_rdma'
    device_check_timeout_sec = 120
    device_check_interval_sec = 1

    ipv4_addr = None
    mac_adr = None

    def __init__(self, ipv4_addr, mac_addr):
        self.ipv4_addr = ipv4_addr
        self.mac_addr = mac_addr

    def start(self):
        """
        Start a thread in the background to process the RDMA tasks and returns.
        """
        logger.info("RDMA: starting device processing in the background.")
        threading.Thread(target=self.process).start()

    def process(self):
        RDMADeviceHandler.wait_rdma_device(
            self.rdma_dev, self.device_check_timeout_sec, self.device_check_interval_sec)
        RDMADeviceHandler.update_dat_conf(dapl_config_paths, self.ipv4_addr)
        RDMADeviceHandler.write_rdma_config_to_device(
            self.rdma_dev, self.ipv4_addr, self.mac_addr)
        RDMADeviceHandler.update_network_interface(self.mac_addr, self.ipv4_addr)

    @staticmethod
    def update_dat_conf(paths, ipv4_addr):
        """
        Looks at paths for dat.conf file and updates the ip address for the
        infiniband interface.
        """
        logger.info("Updating DAPL configuration file")
        for f in paths:
            logger.info("RDMA: trying {0}".format(f))
            if not os.path.isfile(f):
                logger.info(
                    "RDMA: DAPL config not found at {0}".format(f))
                continue
            logger.info("RDMA: DAPL config is at: {0}".format(f))
            cfg = fileutil.read_file(f)
            new_cfg = RDMADeviceHandler.replace_dat_conf_contents(
                cfg, ipv4_addr)
            fileutil.write_file(f, new_cfg)
            logger.info("RDMA: DAPL configuration is updated")
            return

        raise Exception("RDMA: DAPL configuration file not found at predefined paths")

    @staticmethod
    def replace_dat_conf_contents(cfg, ipv4_addr):
        old = "ofa-v2-ib0 u2.0 nonthreadsafe default libdaplofa.so.2 dapl.2.0 \"\S+ 0\""
        new = "ofa-v2-ib0 u2.0 nonthreadsafe default libdaplofa.so.2 dapl.2.0 \"{0} 0\"".format(
            ipv4_addr)
        return re.sub(old, new, cfg)

    @staticmethod
    def write_rdma_config_to_device(path, ipv4_addr, mac_addr):
        data = RDMADeviceHandler.generate_rdma_config(ipv4_addr, mac_addr)
        logger.info(
            "RDMA: Updating device with configuration: {0}".format(data))
        with open(path, "w") as f:
            f.write(data)
        logger.info("RDMA: Updated device with IPv4/MAC addr successfully")

    @staticmethod
    def generate_rdma_config(ipv4_addr, mac_addr):
        return 'rdmaMacAddress="{0}" rdmaIPv4Address="{1}"'.format(mac_addr, ipv4_addr)

    @staticmethod
    def wait_rdma_device(path, timeout_sec, check_interval_sec):
        logger.info("RDMA: waiting for device={0} timeout={1}s".format(path, timeout_sec))
        total_retries = timeout_sec/check_interval_sec
        n = 0
        while n < total_retries:
            if os.path.exists(path):
                logger.info("RDMA: device ready")
                return
            logger.verbose(
                "RDMA: device not ready, sleep {0}s".format(check_interval_sec))
            time.sleep(check_interval_sec)
            n += 1
        logger.error("RDMA device wait timed out")
        raise Exception("The device did not show up in {0} seconds ({1} retries)".format(
            timeout_sec, total_retries))

    @staticmethod
    def update_network_interface(mac_addr, ipv4_addr):
        netmask=16
        
        logger.info("RDMA: will update the network interface with IPv4/MAC")

        if_name=RDMADeviceHandler.get_interface_by_mac(mac_addr)
        logger.info("RDMA: network interface found: {0}", if_name)
        logger.info("RDMA: bringing network interface up")
        if shellutil.run("ifconfig {0} up".format(if_name)) != 0:
            raise Exception("Could not bring up RMDA interface: {0}".format(if_name))

        logger.info("RDMA: configuring IPv4 addr and netmask on interface")
        addr = '{0}/{1}'.format(ipv4_addr, netmask)
        if shellutil.run("ifconfig {0} {1}".format(if_name, addr)) != 0:
            raise Exception("Could set addr to {1} on {0}".format(if_name, addr))
        logger.info("RDMA: network address and netmask configured on interface")

    @staticmethod
    def get_interface_by_mac(mac):
        ret, output = shellutil.run_get_output("ifconfig -a")
        if ret != 0:
            raise Exception("Failed to list network interfaces")
        output = output.replace('\n', '')
        match = re.search(r"(eth\d).*(HWaddr|ether) {0}".format(mac), 
                          output, re.IGNORECASE)
        if match is None:
            raise Exception("Failed to get ifname with mac: {0}".format(mac))
        output = match.group(0)
        eths = re.findall(r"eth\d", output)
        if eths is None or len(eths) == 0:
            raise Exception("ifname with mac: {0} not found".format(mac))
        return eths[-1]
