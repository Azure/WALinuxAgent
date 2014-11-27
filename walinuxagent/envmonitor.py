# Windows Azure Linux Agent
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
import walinuxagent.logger as logger
from walinuxagent.utils.osutil import CurrOS, CurrOSInfo

class EnvMonitor(object):
    """
    Montor changes to dhcp and hostname.
    If dhcp clinet process re-start has occurred, reset routes, dhcp with fabric.
    """
    def __init__(self, config, dhcphandler):
        self.shutdown = False
        self.config = config
        self.dhcphandler = dhcphandler
        self.hostname = socket.gethostname()
        self.dhcpid = CurrOS.GetDhcpProcessId()
        self.server_thread = threading.Thread(target = self.monitor)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

    def monitor(self):
        """
        Monitor dhcp client pid and hostname.
        If dhcp clinet process re-start has occurred, reset routes.
        """
        while not self.shutdown:
            CurrOS.RemoveRulesFiles()
            timeout = self.config.get("OS.RootDeviceScsiTimeout", None)
            if timeout is not None:
                CurrOS.SetScsiDiskTimeout(timeout)
            required = self.config.getSwitch("Provisioning.MonitorHostName", 
                                             False)
            if required:
                self.handleHostnameUpdate()
            self.handleDhcpClientRestart()
            time.sleep(5)

    def handleHostnameUpdate(self):
        currHostname = socket.gethostname()
        if currHostname != self.hostname:
            logger.Info("EnvMonitor: Detected host name change: {0} -> {1}",
                        self.hostname, currHostname)
            CurrOS.SetHostname(currHostname)
            CurrOS.PublishHostname(currHostname)
            self.hostname = currHostname

    def handleDhcpClientRestart(self):
        if self.dhcpid is None:
            self.dhcpid = CurrOS.GetDhcpProcessId()
            return

        #The dhcp process hasn't changed since last check
        if os.path.isdir(os.path.join('/proc', self.dhcpid.strip())):
            return
        
        newpid = CurrOS.GetDhcpProcessId()
        if newpid is not None and newpid != self.dhcpid:
           logger.Info("EnvMonitor: Detected dhcp client restart. "
                       "Restoring routing table.")
           self.dhcphandler.configRoutes()
           self.dhcpid = newpid

    def shutdownService(self):
        """
        Stop server comminucation and join the thread to main thread.
        """
        self.shutdown = True
        self.server_thread.join()

