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
import time
import sys
import azurelinuxagent.conf as conf
import azurelinuxagent.logger as logger
from azurelinuxagent.future import ustr
from azurelinuxagent.exception import ProtocolError
from azurelinuxagent.metadata import AGENT_LONG_NAME, AGENT_VERSION, \
                                     DISTRO_NAME, DISTRO_VERSION, \
                                     DISTRO_FULL_NAME, PY_VERSION_MAJOR, \
                                     PY_VERSION_MINOR, PY_VERSION_MICRO
import azurelinuxagent.event as event
import azurelinuxagent.utils.fileutil as fileutil


class DaemonHandler(object):
    def __init__(self, distro):
        self.distro = distro

    def run(self):
        logger.info("{0} Version:{1}", AGENT_LONG_NAME, AGENT_VERSION)
        logger.info("OS: {0} {1}", DISTRO_NAME, DISTRO_VERSION)
        logger.info("Python: {0}.{1}.{2}", PY_VERSION_MAJOR, PY_VERSION_MINOR,
                    PY_VERSION_MICRO)
        
        #Create lib dir
        if not os.path.isdir(self.distro.conf.get_lib_dir()):
            fileutil.mkdir(self.distro.conf.get_lib_dir(), mode=0o700)
            os.chdir(self.distro.conf.get_lib_dir())

        #TODO check running daemon
        fileutil.write_file(self.distro.osutil.get_agent_pid_file_path(), 
                            ustr(os.getpid()))

        if conf.get_detect_scvmm_env():
            if self.distro.scvmm_handler.run():
                return

        self.distro.provision_handler.run()
        
        if conf.get_resourcedisk_format():
            self.distro.resource_disk_handler.run()

        try:
            protocol = self.distro.protocol_util.detect_protocol()
        except ProtocolError as e:
            logger.error("Failed to detect protocol, exit", e)
            return
        
        self.distro.event_handler.run()
        self.distro.env_handler.run()
        
        while True:
            #Handle extensions
            self.distro.ext_distro_handler.run()
            time.sleep(25)

