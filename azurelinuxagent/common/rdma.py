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
import time

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.utils.textutil import parse_doc, find, getattrib

dapl_config_paths = [ # pylint: disable=invalid-name
    '/etc/dat.conf',
    '/etc/rdma/dat.conf',
    '/usr/local/etc/dat.conf'
]


def setup_rdma_device(nd_version, shared_conf):
    logger.verbose("Parsing SharedConfig XML contents for RDMA details")
    xml_doc = parse_doc(shared_conf.xml_text)
    if xml_doc is None:
        logger.error("Could not parse SharedConfig XML document")
        return
    instance_elem = find(xml_doc, "Instance")
    if not instance_elem:
        logger.error("Could not find <Instance> in SharedConfig document")
        return

    rdma_ipv4_addr = getattrib(instance_elem, "rdmaIPv4Address")
    if not rdma_ipv4_addr:
        logger.error(
            "Could not find rdmaIPv4Address attribute on Instance element of SharedConfig.xml document")
        return

    rdma_mac_addr = getattrib(instance_elem, "rdmaMacAddress")
    if not rdma_mac_addr:
        logger.error(
            "Could not find rdmaMacAddress attribute on Instance element of SharedConfig.xml document")
        return

    # add colons to the MAC address (e.g. 00155D33FF1D ->
    # 00:15:5D:33:FF:1D)
    rdma_mac_addr = ':'.join([rdma_mac_addr[i:i + 2]
                              for i in range(0, len(rdma_mac_addr), 2)])
    logger.info("Found RDMA details. IPv4={0} MAC={1}".format(
        rdma_ipv4_addr, rdma_mac_addr))

    # Set up the RDMA device with collected informatino
    RDMADeviceHandler(rdma_ipv4_addr, rdma_mac_addr, nd_version).start()
    logger.info("RDMA: device is set up")
    return

class RDMAHandler(object):

    driver_module_name = 'hv_network_direct'
    nd_version = None

    def get_rdma_version(self): # pylint: disable=R1710
        """Retrieve the firmware version information from the system.
           This depends on information provided by the Linux kernel."""

        if self.nd_version :
            return self.nd_version

        kvp_key_size = 512
        kvp_value_size = 2048
        driver_info_source = '/var/lib/hyperv/.kvp_pool_0'
        base_kernel_err_msg = 'Kernel does not provide the necessary '
        base_kernel_err_msg += 'information or the kvp daemon is not running.'
        if not os.path.isfile(driver_info_source):
            error_msg = 'RDMA: Source file "%s" does not exist. '
            error_msg += base_kernel_err_msg
            logger.error(error_msg % driver_info_source)
            return

        f = open(driver_info_source) # pylint: disable=C0103
        while True :
            key = f.read(kvp_key_size)
            value = f.read(kvp_value_size)
            if key and value :
                key_0 = key.split("\x00")[0]
                value_0 = value.split("\x00")[0]
                if key_0 == "NdDriverVersion" :
                    f.close()
                    self.nd_version = value_0
                    return self.nd_version
            else :
                break
        f.close()

        error_msg = 'RDMA: NdDriverVersion not found in "%s"'
        logger.error(error_msg % driver_info_source)
        return

    @staticmethod
    def is_kvp_daemon_running():
        """Look for kvp daemon names in ps -ef output and return True/False
        """
        # for centos, the hypervkvpd and the hv_kvp_daemon both are ok.
        # for suse, it uses hv_kvp_daemon
        kvp_daemon_names = ['hypervkvpd', 'hv_kvp_daemon']

        exitcode, ps_out  = shellutil.run_get_output("ps -ef")
        if exitcode != 0:
            raise Exception('RDMA: ps -ef failed: %s' % ps_out)
        for n in  kvp_daemon_names: # pylint: disable=C0103
            if n in ps_out: # pylint: disable=R1705
                logger.info('RDMA: kvp daemon (%s) is running' % n)
                return True
            else:
                logger.verbose('RDMA: kvp daemon (%s) is not running' % n)
        return False


    def load_driver_module(self):
        """Load the kernel driver, this depends on the proper driver
           to be installed with the install_driver() method"""
        logger.info("RDMA: probing module '%s'" % self.driver_module_name)
        result = shellutil.run('modprobe --first-time %s' % self.driver_module_name)
        if result != 0:
            error_msg = 'Could not load "%s" kernel module. '
            error_msg += 'Run "modprobe --first-time %s" as root for more details'
            logger.error(
                error_msg % (self.driver_module_name, self.driver_module_name)
            )
            return False
        logger.info('RDMA: Loaded the kernel driver successfully.')
        return True

    def install_driver_if_needed(self):
        if self.nd_version:
            if conf.enable_check_rdma_driver():
                self.install_driver()
            else:
                logger.info('RDMA: check RDMA driver is disabled, skip installing driver')
        else:
            logger.info('RDMA: skip installing driver when ndversion not present\n')

    def install_driver(self):
        """Install the driver. This is distribution specific and must
           be overwritten in the child implementation."""
        logger.error('RDMAHandler.install_driver not implemented')

    def is_driver_loaded(self):
        """Check if the network module is loaded in kernel space"""
        cmd = 'lsmod | grep ^%s' % self.driver_module_name
        status, loaded_modules = shellutil.run_get_output(cmd) # pylint: disable=W0612
        logger.info('RDMA: Checking if the module loaded.')
        if loaded_modules:
            logger.info('RDMA: module loaded.')
            return True
        logger.info('RDMA: module not loaded.')
        return False

    def reboot_system(self):
        """Reboot the system. This is required as the kernel module for
           the rdma driver cannot be unloaded with rmmod"""
        logger.info('RDMA: Rebooting system.')
        ret = shellutil.run('shutdown -r now')
        if ret != 0:
            logger.error('RDMA: Failed to reboot the system')


dapl_config_paths = [ # pylint: disable=invalid-name
    '/etc/dat.conf', '/etc/rdma/dat.conf', '/usr/local/etc/dat.conf']

class RDMADeviceHandler(object):

    """
    Responsible for writing RDMA IP and MAC address to the /dev/hvnd_rdma
    interface.
    """

    rdma_dev = '/dev/hvnd_rdma'
    sriov_dir = '/sys/class/infiniband'
    device_check_timeout_sec = 120
    device_check_interval_sec = 1
    ipoib_check_timeout_sec = 60
    ipoib_check_interval_sec = 1

    ipv4_addr = None
    mac_adr = None
    nd_version = None

    def __init__(self, ipv4_addr, mac_addr, nd_version):
        self.ipv4_addr = ipv4_addr
        self.mac_addr = mac_addr
        self.nd_version = nd_version

    def start(self):
        logger.info("RDMA: starting device processing.")
        self.process()
        logger.info("RDMA: completed device processing.")

    def process(self):
        try:
            if not self.nd_version :
                logger.info("RDMA: provisioning SRIOV RDMA device.")
                self.provision_sriov_rdma()
            else :
                logger.info("RDMA: provisioning Network Direct RDMA device.")
                self.provision_network_direct_rdma()
        except Exception as e: # pylint: disable=C0103
            logger.error("RDMA: device processing failed: {0}".format(e))

    def provision_network_direct_rdma(self) :
        RDMADeviceHandler.update_dat_conf(dapl_config_paths, self.ipv4_addr)

        if not conf.enable_check_rdma_driver():
            logger.info("RDMA: skip checking RDMA driver version")
            RDMADeviceHandler.update_network_interface(self.mac_addr, self.ipv4_addr)
            return

        skip_rdma_device = False
        module_name = "hv_network_direct"
        retcode,out = shellutil.run_get_output("modprobe -R %s" % module_name, chk_err=False)
        if retcode == 0:
            module_name = out.strip()
        else:
            logger.info("RDMA: failed to resolve module name. Use original name")
        retcode,out = shellutil.run_get_output("modprobe %s" % module_name)
        if retcode != 0:
            logger.error("RDMA: failed to load module %s" % module_name)
            return
        retcode,out = shellutil.run_get_output("modinfo %s" % module_name)
        if retcode == 0:
            version = re.search("version:\s+(\d+)\.(\d+)\.(\d+)\D", out, re.IGNORECASE) # pylint: disable=W1401
            if version:
                v1 = int(version.groups(0)[0]) # pylint: disable=C0103
                v2 = int(version.groups(0)[1]) # pylint: disable=C0103
                if v1>4 or v1==4 and v2>0:
                    logger.info("Skip setting /dev/hvnd_rdma on 4.1 or later")
                    skip_rdma_device = True
            else:
                logger.info("RDMA: hv_network_direct driver version not present, assuming 4.0.x or older.")
        else:
            logger.warn("RDMA: failed to get module info on hv_network_direct.")

        if not skip_rdma_device:
            RDMADeviceHandler.wait_rdma_device(
                self.rdma_dev, self.device_check_timeout_sec, self.device_check_interval_sec)
            RDMADeviceHandler.write_rdma_config_to_device(
                self.rdma_dev, self.ipv4_addr, self.mac_addr)

        RDMADeviceHandler.update_network_interface(self.mac_addr, self.ipv4_addr)

    def provision_sriov_rdma(self) : # pylint: disable=R1711
        RDMADeviceHandler.wait_any_rdma_device(
            self.sriov_dir, self.device_check_timeout_sec, self.device_check_interval_sec)
        RDMADeviceHandler.update_iboip_interface(self.ipv4_addr, self.ipoib_check_timeout_sec, self.ipoib_check_interval_sec)
        return

    @staticmethod
    def update_iboip_interface(ipv4_addr, timeout_sec, check_interval_sec) :
        logger.info("Wait for ib0 become available")
        total_retries = timeout_sec/check_interval_sec
        n = 0 # pylint: disable=C0103
        found_ib0 = None
        while not found_ib0 and n < total_retries:
            ret, output = shellutil.run_get_output("ifconfig -a")
            if ret != 0:
                raise Exception("Failed to list network interfaces")
            found_ib0 = re.search("ib0", output, re.IGNORECASE)
            if found_ib0:
                break
            time.sleep(check_interval_sec)
            n += 1 # pylint: disable=C0103

        if not found_ib0:
            raise Exception("ib0 is not available")

        netmask = 16
        logger.info("RDMA: configuring IPv4 addr and netmask on ipoib interface")
        addr = '{0}/{1}'.format(ipv4_addr, netmask)
        if shellutil.run("ifconfig ib0 {0}".format(addr)) != 0:
            raise Exception("Could set addr to {0} on ib0".format(addr))
        logger.info("RDMA: ipoib address and netmask configured on interface")

    @staticmethod
    def update_dat_conf(paths, ipv4_addr):
        """
        Looks at paths for dat.conf file and updates the ip address for the
        infiniband interface.
        """
        logger.info("Updating DAPL configuration file")
        for f in paths: # pylint: disable=C0103
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
        old = "ofa-v2-ib0 u2.0 nonthreadsafe default libdaplofa.so.2 dapl.2.0 \"\S+ 0\"" # pylint: disable=W1401
        new = "ofa-v2-ib0 u2.0 nonthreadsafe default libdaplofa.so.2 dapl.2.0 \"{0} 0\"".format(
            ipv4_addr)
        return re.sub(old, new, cfg)

    @staticmethod
    def write_rdma_config_to_device(path, ipv4_addr, mac_addr):
        data = RDMADeviceHandler.generate_rdma_config(ipv4_addr, mac_addr)
        logger.info(
            "RDMA: Updating device with configuration: {0}".format(data))
        with open(path, "w") as f: # pylint: disable=C0103
            logger.info("RDMA: Device opened for writing")
            f.write(data)
        logger.info("RDMA: Updated device with IPv4/MAC addr successfully")

    @staticmethod
    def generate_rdma_config(ipv4_addr, mac_addr):
        return 'rdmaMacAddress="{0}" rdmaIPv4Address="{1}"'.format(mac_addr, ipv4_addr)

    @staticmethod
    def wait_rdma_device(path, timeout_sec, check_interval_sec):
        logger.info("RDMA: waiting for device={0} timeout={1}s".format(path, timeout_sec))
        total_retries = timeout_sec/check_interval_sec
        n = 0 # pylint: disable=C0103
        while n < total_retries:
            if os.path.exists(path):
                logger.info("RDMA: device ready")
                return
            logger.verbose(
                "RDMA: device not ready, sleep {0}s".format(check_interval_sec))
            time.sleep(check_interval_sec)
            n += 1 # pylint: disable=C0103
        logger.error("RDMA device wait timed out")
        raise Exception("The device did not show up in {0} seconds ({1} retries)".format(
            timeout_sec, total_retries))

    @staticmethod
    def wait_any_rdma_device(dir, timeout_sec, check_interval_sec): # pylint: disable=W0622
        logger.info(
            "RDMA: waiting for any Infiniband device at directory={0} timeout={1}s".format(
            dir, timeout_sec)) 
        total_retries = timeout_sec/check_interval_sec
        n = 0 # pylint: disable=C0103
        while n < total_retries:
            r = os.listdir(dir) # pylint: disable=C0103
            if r:
                logger.info("RDMA: device found in {0}".format(dir))
                return
            logger.verbose(
                "RDMA: device not ready, sleep {0}s".format(check_interval_sec))
            time.sleep(check_interval_sec)
            n += 1 # pylint: disable=C0103
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
        if eths is None or len(eths) == 0: # pylint: disable=len-as-condition
            raise Exception("ifname with mac: {0} not found".format(mac))
        return eths[-1]
