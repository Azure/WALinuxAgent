# Compose Content for: L3-flows/scvmm-agent-integration.md

Total files: 1

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.VMM_CONF_FILE_NAME`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.VMM_STARTUP_SCRIPT_NAME`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.get_scvmm_handler`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler.__init__`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler.__init__.self`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler.detect_scvmm_env`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler.detect_scvmm_env.self`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler.detect_scvmm_env.dev_dir`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/conf.py.get_dvd_mount_point`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler.start_scvmm_agent`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler.start_scvmm_agent.self`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler.start_scvmm_agent.mount_point`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler.run`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.ScvmmHandler.run.self`

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

import re
import os
import sys
import subprocess
import time
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.osutil import get_osutil

VMM_CONF_FILE_NAME = "linuxosconfiguration.xml"
VMM_STARTUP_SCRIPT_NAME= "install"

def get_scvmm_handler():
    return ScvmmHandler()

class ScvmmHandler(object):
    def __init__(self):
        self.osutil = get_osutil()

    def detect_scvmm_env(self, dev_dir='/dev'):
        logger.info("Detecting Microsoft System Center VMM Environment")
        found=False

        # try to load the ATAPI driver, continue on failure
        self.osutil.try_load_atapiix_mod()

        # cycle through all available /dev/sr*|hd*|cdrom*|cd* looking for the scvmm configuration file
        mount_point = conf.get_dvd_mount_point()
        for devices in filter(lambda x: x is not None, [re.match(r'(sr[0-9]|hd[c-z]|cdrom[0-9]?|cd[0-9]+)', dev) for dev in os.listdir(dev_dir)]):
            dvd_device = os.path.join(dev_dir, devices.group(0))
            self.osutil.mount_dvd(max_retry=1, chk_err=False, dvd_device=dvd_device, mount_point=mount_point)
            found = os.path.isfile(os.path.join(mount_point, VMM_CONF_FILE_NAME))
            if found:
                self.start_scvmm_agent(mount_point=mount_point)
                break
            else:
                self.osutil.umount_dvd(chk_err=False, mount_point=mount_point)

        return found

    def start_scvmm_agent(self, mount_point=None):
        logger.info("Startin
````

---
