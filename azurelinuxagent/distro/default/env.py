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
import socket
import threading
import time
import azurelinuxagent.logger as logger
import azurelinuxagent.conf as conf
from azurelinuxagent.utils.osutil import OSUTIL

class EnvHandler(object):
    """
    Monitor changes to dhcp and hostname.
    If dhcp clinet process re-start has occurred, reset routes, dhcp with fabric.

    Monitor scsi disk.
    If new scsi disk found, set
    """
    def __init__(self, handlers):
        self.monitor = EnvMonitor(handlers.dhcp_handler)

    def start(self):
        self.monitor.start()

    def stop(self):
        self.monitor.stop()

class EnvMonitor(object):

    def __init__(self, dhcp_handler):
        self.dhcp_handler = dhcp_handler
        self.stopped = True
        self.hostname = None
        self.dhcpid = None
        self.server_thread=None

    def start(self):
        if not self.stopped:
            logger.info("Stop existing env monitor service.")
            self.stop()

        self.stopped = False
        logger.info("Start env monitor service.")
        self.hostname = socket.gethostname()
        self.dhcpid = OSUTIL.get_dhcp_pid()
        self.server_thread = threading.Thread(target = self.monitor)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

    def monitor(self):
        """
        Monitor dhcp client pid and hostname.
        If dhcp clinet process re-start has occurred, reset routes.
        """
        while not self.stopped:
            OSUTIL.remove_rules_files()
            timeout = conf.get("OS.RootDeviceScsiTimeout", None)
            if timeout is not None:
                OSUTIL.set_scsi_disks_timeout(timeout)
            if conf.get_switch("Provisioning.MonitorHostName", False):
                self.handle_hostname_update()
            self.handle_dhclient_restart()
            time.sleep(5)

    def handle_hostname_update(self):
        curr_hostname = socket.gethostname()
        if curr_hostname != self.hostname:
            logger.info("EnvMonitor: Detected host name change: {0} -> {1}",
                        self.hostname, curr_hostname)
            OSUTIL.set_hostname(curr_hostname)
            OSUTIL.publish_hostname(curr_hostname)
            self.hostname = curr_hostname

    def handle_dhclient_restart(self):
        if self.dhcpid is None:
            logger.warn("Dhcp client is not running. ")
            self.dhcpid = OSUTIL.get_dhcp_pid()
            return

        #The dhcp process hasn't changed since last check
        if os.path.isdir(os.path.join('/proc', self.dhcpid.strip())):
            return

        newpid = OSUTIL.get_dhcp_pid()
        if newpid is not None and newpid != self.dhcpid:
           logger.info("EnvMonitor: Detected dhcp client restart. "
                       "Restoring routing table.")
           self.dhcp_handler.conf_routes()
           self.dhcpid = newpid

    def stop(self):
        """
        Stop server comminucation and join the thread to main thread.
        """
        self.stopped = True
        if self.server_thread is not None:
            self.server_thread.join()

