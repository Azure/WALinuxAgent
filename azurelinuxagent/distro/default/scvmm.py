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
import subprocess
import azurelinuxagent.logger as logger
from azurelinuxagent.utils.osutil import OSUTIL

VMM_CONF_FILE_NAME = "linuxosconfiguration.xml"
VMM_STARTUP_SCRIPT_NAME= "install"

class ScvmmHandler(object):

    def detect_scvmm_env(self):
        logger.info("Detecting Microsoft System Center VMM Environment")
        OSUTIL.mount_dvd(max_retry=1, chk_err=False)
        mount_point = OSUTIL.get_dvd_mount_point()
        found = os.path.isfile(os.path.join(mount_point, VMM_CONF_FILE_NAME))
        if found:
            self.start_scvmm_agent()
        else:
            OSUTIL.umount_dvd(chk_err=False)
        return found

    def start_scvmm_agent(self):
        logger.info("Starting Microsoft System Center VMM Initialization "
                    "Process")
        mount_point = OSUTIL.get_dvd_mount_point()
        startup_script = os.path.join(mount_point, VMM_STARTUP_SCRIPT_NAME)
        subprocess.Popen(["/bin/bash", startup_script, "-p " + mount_point])

