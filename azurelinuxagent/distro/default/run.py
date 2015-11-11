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
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text
import azurelinuxagent.conf as conf
from azurelinuxagent.metadata import AGENT_LONG_NAME, AGENT_VERSION, \
                                     DISTRO_NAME, DISTRO_VERSION, \
                                     DISTRO_FULL_NAME, PY_VERSION_MAJOR, \
                                     PY_VERSION_MINOR, PY_VERSION_MICRO
import azurelinuxagent.event as event
import azurelinuxagent.protocol as prot
from azurelinuxagent.utils.osutil import OSUTIL
import azurelinuxagent.utils.fileutil as fileutil


class MainHandler(object):
    def __init__(self, handlers):
        self.handlers = handlers

    def run(self):
        logger.info("{0} Version:{1}", AGENT_LONG_NAME, AGENT_VERSION)
        logger.info("OS: {0} {1}", DISTRO_NAME, DISTRO_VERSION)
        logger.info("Python: {0}.{1}.{2}", PY_VERSION_MAJOR, PY_VERSION_MINOR,
                    PY_VERSION_MICRO)

        event.enable_unhandled_err_dump("Azure Linux Agent")
        fileutil.write_file(OSUTIL.get_agent_pid_file_path(), text(os.getpid()))

        if conf.get_switch("DetectScvmmEnv", False):
            if self.handlers.scvmm_handler.detect_scvmm_env():
                return

        self.handlers.dhcp_handler.probe()

        prot.detect_default_protocol()

        event.EventMonitor().start()

        self.handlers.provision_handler.process()

        if conf.get_switch("ResourceDisk.Format", False):
            self.handlers.resource_disk_handler.start_activate_resource_disk()

        self.handlers.env_handler.start()

        protocol = prot.FACTORY.get_default_protocol()
        while True:
            #Handle extensions
            self.handlers.ext_handlers_handler.process()
            time.sleep(25)

