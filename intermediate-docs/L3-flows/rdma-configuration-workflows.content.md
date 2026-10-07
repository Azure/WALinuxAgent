# Compose Content for: L3-flows/rdma-configuration-workflows.md

Total files: 5

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.rdma_user_mode_package_name`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.rdma_kernel_mode_package_name`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.rdma_wrapper_package_name`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.hyper_v_package_name`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.hyper_v_package_name_new`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.version_major`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.version_minor`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.__init__`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.__init__.self`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.__init__.distro_version`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.install_driver`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.install_driver.self`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.is_kvp_daemon_running`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.check_or_install_kvp_daemon`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.get_rdma_version`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler.get_int_rdma_version`
- `%REPO%/azu

### Source excerpt

````
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

import glob  # pylint: disable=W0611
import os
import re
import time
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.pa.rdma.rdma import RDMAHandler


class CentOSRDMAHandler(RDMAHandler):
    rdma_user_mode_package_name = 'microsoft-hyper-v-rdma'
    rdma_kernel_mode_package_name = 'kmod-microsoft-hyper-v-rdma'
    rdma_wrapper_package_name = 'msft-rdma-drivers'

    hyper_v_package_name = "hypervkvpd"
    hyper_v_package_name_new = "microsoft-hyper-v"

    version_major = None
    version_minor = None

    def __init__(self, distro_version):
        v = distro_version.split('.')
        if len(v) < 2:
            raise Exception('Unexpected centos version: %s' % distro_version)
        self.version_major, self.version_minor = v[0], v[1]

    def install_driver(self):
        """
        Install the KVP daemon and the appropriate RDMA driver package for the
        RDMA firmware.
        """

        # Check and install the KVP deamon if it not running
        time.sleep(10) # give some time for the hv_hvp_daemon to start up.
        kvpd_running = RDMAHandler.is_kvp_daemon_running()
        logger.info('RDMA: kvp daemon running: %s' % kvpd_running)
        if not kvpd_running:
            self.check_or_install_kvp_daemon()
        time.sleep(10) # wait for post-install reboot or kvp to come up

        # Find out RDMA firmware version and see if the existing package needs
        # updating or if the package is missing altogether (an
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_FULL_NAME`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_VERSION`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion`
- `%REPO%/azurelinuxagent/pa/rdma/centos.py.CentOSRDMAHandler`
- `%REPO%/azurelinuxagent/pa/rdma/suse.py.SUSERDMAHandler`
- `%REPO%/azurelinuxagent/pa/rdma/ubuntu.py.UbuntuRDMAHandler`
- `%REPO%/azurelinuxagent/pa/rdma/factory.py.get_rdma_handler`
- `%REPO%/azurelinuxagent/pa/rdma/factory.py.get_rdma_handler.distro_full_name`
- `%REPO%/azurelinuxagent/pa/rdma/factory.py.get_rdma_handler.distro_version`
- `%REPO%/azurelinuxagent/common/logger.py.info`

### Source excerpt

````
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
# Requires Python 2.6+ and Openssl 1.0+
#

import azurelinuxagent.common.logger as logger
from azurelinuxagent.pa.rdma.rdma import RDMAHandler
from azurelinuxagent.common.version import DISTRO_FULL_NAME, DISTRO_VERSION
from azurelinuxagent.common.utils.distro_version import DistroVersion
from .centos import CentOSRDMAHandler
from .suse import SUSERDMAHandler
from .ubuntu import UbuntuRDMAHandler


def get_rdma_handler(
        distro_full_name=DISTRO_FULL_NAME,
        distro_version=DISTRO_VERSION
):
    """Return the handler object for RDMA driver handling"""
    if (
            (distro_full_name == 'SUSE Linux Enterprise Server' or
             distro_full_name == 'SLES' or
             distro_full_name == 'SLE_HPC') and
            DistroVersion(distro_version) > DistroVersion('11')
    ):
        return SUSERDMAHandler()

    if distro_full_name in ('CentOS Linux', 'CentOS',
                            'Red Hat Enterprise Linux Server', 'AlmaLinux',
                            'CloudLinux', 'Rocky Linux'):
        return CentOSRDMAHandler(distro_version)

    if distro_full_name == 'Ubuntu':
        return UbuntuRDMAHandler()

    logger.info("No RDMA handler exists for distro='{0}' version='{1}'", distro_full_name, distro_version)
    return RDMAHandler()

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/utils/textutil.py.parse_doc`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.find`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.getattrib`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.dapl_config_paths`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.setup_rdma_device`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.setup_rdma_device.nd_version`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.setup_rdma_device.shared_conf`
- `%REPO%/azurelinuxagent/common/logger.py.verbose`
- `%REPO%/azurelinuxagent/common/logger.py.error`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMADeviceHandler.start`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMADeviceHandler`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.driver_module_name`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.nd_version`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.get_rdma_version`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.get_rdma_version.self`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.is_kvp_daemon_running`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.load_driver_module`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.load_driver_module.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.install_driver_if_ne

### Source excerpt

````
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

dapl_config_paths = [
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
    rdma_mac_addr = getattrib(instance_elem, "rdmaMacAddress")

    # add colons to the MAC address (e.g. 00155D33FF1D ->
    # 00:15:5D:33:FF:1D)
    if rdma_mac_addr:
        rdma_mac_addr = ':'.join([rdma_mac_addr[i:i + 2]
                                  for i in range(0, len(rdma_mac_addr), 2)])
    logger.info("Found RDMA details. IPv4={0} MAC={1}".format(
        rdma_ipv4_addr, rdma_mac_addr))

    # Set up the RDMA device with collected information
    RDMADeviceHandler(rdma_ipv4_addr, rdma_mac_addr, nd_version).start()
    logger.info("RDMA: device is set up")
    return


c
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_VERSION`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion`
- `%REPO%/azurelinuxagent/pa/rdma/suse.py.SUSERDMAHandler`
- `%REPO%/azurelinuxagent/pa/rdma/suse.py.SUSERDMAHandler.install_driver`
- `%REPO%/azurelinuxagent/pa/rdma/suse.py.SUSERDMAHandler.install_driver.self`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.get_rdma_version`
- `%REPO%/azurelinuxagent/common/logger.py.error`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.is_driver_loaded`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.load_driver_module`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.reboot_system`

### Source excerpt

````
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

import glob
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil

from azurelinuxagent.pa.rdma.rdma import RDMAHandler
from azurelinuxagent.common.version import DISTRO_VERSION
from azurelinuxagent.common.utils.distro_version import DistroVersion


class SUSERDMAHandler(RDMAHandler):

    def install_driver(self):  # pylint: disable=R1710
        """Install the appropriate driver package for the RDMA firmware"""

        if DistroVersion(DISTRO_VERSION) >= DistroVersion('15'):
            msg = 'SLE 15 and later only supports PCI pass through, no '
            msg += 'special driver needed for IB interface'
            logger.info(msg)
            return True

        fw_version = self.get_rdma_version()
        if not fw_version:
            error_msg = 'RDMA: Could not determine firmware version. '
            error_msg += 'Therefore, no driver will be installed.'
            logger.error(error_msg)
            return
        zypper_install = 'zypper -n in %s'
        zypper_install_noref = 'zypper -n --no-refresh in %s'
        zypper_lock = 'zypper addlock %s'
        zypper_remove = 'zypper -n rm %s'
        zypper_search = 'zypper -n se -s %s'
        zypper_unlock = 'zypper removelock %s'
        package_name = 'dummy'
        # Figure out the kernel that is running to find the proper kmp
        cmd = 'uname -r'
        status, kernel_release = shellutil.run_get_output(cmd)  # pylint: disable=W0612
        if 'default' in kernel_release:

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler`
- `%REPO%/azurelinuxagent/pa/rdma/ubuntu.py.UbuntuRDMAHandler`
- `%REPO%/azurelinuxagent/pa/rdma/ubuntu.py.UbuntuRDMAHandler.install_driver`
- `%REPO%/azurelinuxagent/pa/rdma/ubuntu.py.UbuntuRDMAHandler.install_driver.self`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.get_rdma_version`
- `%REPO%/azurelinuxagent/common/logger.py.error`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/pa/rdma/ubuntu.py.UbuntuRDMAHandler.update_modprobed_conf`
- `%REPO%/azurelinuxagent/common/conf.py.enable_rdma_update`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.RDMAHandler.reboot_system`
- `%REPO%/azurelinuxagent/pa/rdma/ubuntu.py.UbuntuRDMAHandler.update_modprobed_conf.self`
- `%REPO%/azurelinuxagent/pa/rdma/ubuntu.py.UbuntuRDMAHandler.update_modprobed_conf.nd_version`

### Source excerpt

````
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

import glob  # pylint: disable=W0611
import os
import re
import time  # pylint: disable=W0611
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.pa.rdma.rdma import RDMAHandler


class UbuntuRDMAHandler(RDMAHandler):

    def install_driver(self):
        #Install the appropriate driver package for the RDMA firmware

        nd_version = self.get_rdma_version()
        if not nd_version:
            logger.error("RDMA: Could not determine firmware version. No driver will be installed")
            return
        #replace . with _, we are looking for number like 144_0
        nd_version = re.sub(r'\.', '_', nd_version)

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
        status,output = shellutil.run_get_output('modinfo hv_network_dir
````

---
