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
import datetime
import azurelinuxagent.common.utils.shellutil as shellutil 
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.dhcp import get_dhcp_handler

def get_env_handler():
    return EnvHandler()

class EnvHandler(object):
    """
    Monitor changes to dhcp and hostname.
    If dhcp clinet process re-start has occurred, reset routes, dhcp with fabric.

    Monitor scsi disk.
    If new scsi disk found, set timeout
    """
    def __init__(self):
        self.osutil = get_osutil()
        self.dhcp_handler = get_dhcp_handler()
        self.stopped = True
        self.hostname = None
        self.dhcpid = None
        self.server_thread=None
        self.lastNotice = datetime.datetime.min
        self.fstabModTime = None 

    def run(self):
        if not self.stopped:
            logger.info("Stop existing env monitor service.")
            self.stop()

        self.stopped = False
        self.fstabModTime = os.path.getmtime("/etc/fstab")
        logger.info("Start env monitor service.")
        self.dhcp_handler.conf_routes()
        self.hostname = socket.gethostname()
        self.dhcpid = self.osutil.get_dhcp_pid()
        self.server_thread = threading.Thread(target = self.monitor)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

    def monitor(self):
        """
        Monitor dhcp client pid and hostname.
        Montor for changes in fstab, warn if content is invalid
        If dhcp clinet process re-start has occurred, reset routes.
        """
        while not self.stopped:
            self.osutil.remove_rules_files()
            timeout = conf.get_root_device_scsi_timeout()
            if timeout is not None:
                self.osutil.set_scsi_disks_timeout(timeout)
            if conf.get_monitor_hostname():
                self.handle_hostname_update()
            self.handle_dhclient_restart()
            self.handle_fstab_update() 
            time.sleep(5)

    def handle_hostname_update(self):
        curr_hostname = socket.gethostname()
        if curr_hostname != self.hostname:
            logger.info("EnvMonitor: Detected host name change: {0} -> {1}",
                        self.hostname, curr_hostname)
            self.osutil.set_hostname(curr_hostname)
            self.osutil.publish_hostname(curr_hostname)
            self.hostname = curr_hostname

    def handle_dhclient_restart(self):
        if self.dhcpid is None:
            logger.warn("Dhcp client is not running. ")
            self.dhcpid = self.osutil.get_dhcp_pid()
            return

        #The dhcp process hasn't changed since last check
        if self.osutil.check_pid_alive(self.dhcpid.strip()):
            return

        newpid = self.osutil.get_dhcp_pid()
        if newpid is not None and newpid != self.dhcpid:
           logger.info("EnvMonitor: Detected dhcp client restart. "
                       "Restoring routing table.")
           self.dhcp_handler.conf_routes()
           self.dhcpid = newpid

    def handle_fstab_update(self):
        """
        Look for changes in fstab, mount if the fstab has new modified stamp 
        If error, only re-check every minute to give an admin
         time to correct it and avoid filling the log
        """
        fstabCurrentModifiedStamp = os.path.getmtime("/etc/fstab")
        if fstabCurrentModifiedStamp != self.fstabModTime and \
                            datetime.datetime.now() >  \
                            self.lastNotice + datetime.timedelta(seconds=60):
            ret, output = shellutil.run_get_output("mount -av")
            if ret != 0:
                logger.error(output)
                # Notify the logged on users to take action
                notice = "[AZURE AGENT] Current boot settings are invalid. " \
                      "Please correct the /etc/fstab file contents before " \
                      "rebooting using the error information " \
                      "in /var/log/waagent.log"
                quotedNotice = shellutil.quote(notice)
                shellutil.run("echo '{0}' | wall".format(quotedNotice))
                self.lastNotice = datetime.datetime.now()
            else:
                # no errors during the mount, avoid any warnings
                self.fstabModTime = fstabCurrentModifiedStamp
                logger.info("A fstab modification passed mount validation.")


    def stop(self):
        """
        Stop server comminucation and join the thread to main thread.
        """
        self.stopped = True
        if self.server_thread is not None:
            self.server_thread.join()


