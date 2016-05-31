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
import traceback
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ProtocolError
from azurelinuxagent.common.version import AGENT_LONG_NAME, AGENT_VERSION, \
                                     DISTRO_NAME, DISTRO_VERSION, \
                                     DISTRO_FULL_NAME, PY_VERSION_MAJOR, \
                                     PY_VERSION_MINOR, PY_VERSION_MICRO
import azurelinuxagent.common.event as event
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.daemon.scvmm import get_scvmm_handler
from azurelinuxagent.daemon.resourcedisk import get_resourcedisk_handler
from azurelinuxagent.daemon.monitor import get_monitor_handler
from azurelinuxagent.daemon.env import get_env_handler
from azurelinuxagent.pa.provision import get_provision_handler
from azurelinuxagent.ga.update import get_update_handler

def get_daemon_handler():
    return DaemonHandler()

class DaemonHandler(object):
    """
    Main thread of daemon. It will invoke other threads to do actual work
    """
    def __init__(self):
        self.running = True
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()
        self.scvmm_handler = get_scvmm_handler()
        self.resourcedisk_handler = get_resourcedisk_handler()
        self.monitor_handler = get_monitor_handler()
        self.env_handler = get_env_handler()
        self.provision_handler = get_provision_handler()
        self.update_handler = get_update_handler()

    def run(self):
        logger.info("{0} Version:{1}", AGENT_LONG_NAME, AGENT_VERSION)
        logger.info("OS: {0} {1}", DISTRO_NAME, DISTRO_VERSION)
        logger.info("Python: {0}.{1}.{2}", PY_VERSION_MAJOR, PY_VERSION_MINOR,
                    PY_VERSION_MICRO)

        self.check_pid()

        while self.running:
            try:
                self.daemon()
            except Exception as e:
                err_msg = traceback.format_exc()
                add_event("WALA", is_success=False, message=ustr(err_msg), 
                          op=WALAEventOperation.UnhandledError)
                logger.info("Sleep 15 seconds and restart daemon")
                time.sleep(15)


    def check_pid(self):
        """Check whether daemon is already running"""
        pid = None
        pid_file = conf.get_agent_pid_file_path()
        if os.path.isfile(pid_file):
            pid = fileutil.read_file(pid_file)

        if self.osutil.check_pid_alive(pid):
            logger.info("Daemon is already running: {0}", pid)
            sys.exit(0)
            
        fileutil.write_file(pid_file, ustr(os.getpid()))

    def daemon(self):
        logger.info("Run daemon") 
        #Create lib dir
        if not os.path.isdir(conf.get_lib_dir()):
            fileutil.mkdir(conf.get_lib_dir(), mode=0o700)
            os.chdir(conf.get_lib_dir())

        if conf.get_detect_scvmm_env():
            self.scvmm_handler.run()
        
        if conf.get_resourcedisk_format():
            self.resourcedisk_handler.run()
        
        self.protocol_util.clear_protocol()

        self.provision_handler.run()

        self.monitor_handler.run()

        self.env_handler.run()
        
        while self.running:
            self.update_handler.run()
            time.sleep(25)
