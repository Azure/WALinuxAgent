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
import azureguestagent.logger as logger
import azureguestagent.conf as conf
from azureguestagent.utils.osutil import CurrOSUtil

class EnvHandler(object):
    """
    Monitor changes to dhcp and hostname.
    If dhcp clinet process re-start has occurred, reset routes, dhcp with fabric.

    Monitor scsi disk.
    If new scsi disk found, set 
    """
    def __init__(self,dhcpHandler):
        self.monitor = EnvMonitor(dhcpHandler)

    def startMonitor(self):
        self.monitor.start()

    def stopMonitor(self):
        self.monitor.stop()

class EnvMonitor(object):

    def __init__(self, dhcpHandler):
        self.stopped = False
        self.dhcpHandler = dhcpHandler
        self.hostname = socket.gethostname()
        self.dhcpid = CurrOSUtil.GetDhcpProcessId()
    
    def start(self):
        if not self.stopped:
            logger.Info("Stop existing env monitor service.")
            self.stop()
            self.stopped = False

        logger.Info("Start env monitor service.")
        self.server_thread = threading.Thread(target = self.monitor)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

    def monitor(self):
        """
        Monitor dhcp client pid and hostname.
        If dhcp clinet process re-start has occurred, reset routes.
        """
        while not self.stopped:
            CurrOSUtil.RemoveRulesFiles()
            timeout = conf.Get("OS.RootDeviceScsiTimeout", None)
            if timeout is not None:
                CurrOSUtil.SetScsiDiskTimeout(timeout)
            if conf.GetSwitch("Provisioning.MonitorHostName", False):
                self.handleHostnameUpdate()
            self.handleDhcpClientRestart()
            time.sleep(5)

    def handleHostnameUpdate(self):
        currHostname = socket.gethostname()
        if currHostname != self.hostname:
            logger.Info("EnvMonitor: Detected host name change: {0} -> {1}",
                        self.hostname, currHostname)
            CurrOSUtil.SetHostname(currHostname)
            CurrOSUtil.PublishHostname(currHostname)
            self.hostname = currHostname

    def handleDhcpClientRestart(self):
        if self.dhcpid is None:
            logger.Warn("Dhcp client is not running. ")
            self.dhcpid = CurrOSUtil.GetDhcpProcessId()
            return
       
        #The dhcp process hasn't changed since last check
        if os.path.isdir(os.path.join('/proc', self.dhcpid.strip())):
            return
        
        newpid = CurrOSUtil.GetDhcpProcessId()
        if newpid is not None and newpid != self.dhcpid:
           logger.Info("EnvMonitor: Detected dhcp client restart. "
                       "Restoring routing table.")
           self.dhcpHandler.configRoutes()
           self.dhcpid = newpid

    def stop(self):
        """
        Stop server comminucation and join the thread to main thread.
        """
        self.stopped = True
        self.server_thread.join()

