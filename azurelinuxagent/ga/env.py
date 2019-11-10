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
import socket
import time
import threading
import datetime

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.dhcp import get_dhcp_handler
from azurelinuxagent.common.event import add_periodic, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.utils.archive import StateArchiver
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION

CACHE_PATTERNS = [
    re.compile("^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE),
    re.compile("^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE),
    re.compile("^(.*)\.(\d+)\.(xml)$", re.IGNORECASE)
]

MAXIMUM_CACHED_FILES = 50

ARCHIVE_INTERVAL = datetime.timedelta(hours=24)


def get_env_handler():
    return EnvHandler()


class EnvHandler(object):
    """
    Monitor changes to dhcp and hostname.
    If dhcp client process re-start has occurred, reset routes, dhcp with fabric.

    Monitor scsi disk.
    If new scsi disk found, set timeout
    """
    def __init__(self):
        self.osutil = get_osutil()
        self.dhcp_handler = get_dhcp_handler()
        self.protocol_util = get_protocol_util()
        self.stopped = True
        self.hostname = None
        self.dhcp_id_list = []
        self.server_thread = None
        self.dhcp_warning_enabled = True
        self.last_archive = None
        self.archiver = StateArchiver(conf.get_lib_dir())

    def run(self):
        if not self.stopped:
            logger.info("Stop existing env monitor service.")
            self.stop()

        self.stopped = False
        logger.info("Start env monitor service.")
        self.dhcp_handler.conf_routes()
        self.hostname = self.osutil.get_hostname_record()
        self.dhcp_id_list = self.get_dhcp_client_pid()
        self.start()

    def is_alive(self):
        return self.server_thread.is_alive()

    def start(self):
        self.server_thread = threading.Thread(target=self.monitor)
        self.server_thread.setDaemon(True)
        self.server_thread.setName("EnvHandler")
        self.server_thread.start()

    def monitor(self):
        """
        Monitor firewall rules
        Monitor dhcp client pid and hostname.
        If dhcp client process re-start has occurred, reset routes.
        Purge unnecessary files from disk cache.
        """
        protocol = self.protocol_util.get_protocol()
        reset_firewall_fules = False
        while not self.stopped:
            self.osutil.remove_rules_files()

            if conf.enable_firewall():
                # If the rules ever change we must reset all rules and start over again.
                #
                # There was a rule change at 2.2.26, which started dropping non-root traffic
                # to WireServer.  The previous rules allowed traffic.  Having both rules in
                # place negated the fix in 2.2.26.
                if not reset_firewall_fules:
                    self.osutil.remove_firewall(dst_ip=protocol.endpoint, uid=os.getuid())
                    reset_firewall_fules = True

                success = self.osutil.enable_firewall(dst_ip=protocol.endpoint, uid=os.getuid())

                add_periodic(
                    logger.EVERY_HOUR,
                    AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.Firewall,
                    is_success=success,
                    log_event=False)

            timeout = conf.get_root_device_scsi_timeout()
            if timeout is not None:
                self.osutil.set_scsi_disks_timeout(timeout)

            if conf.get_monitor_hostname():
                self.handle_hostname_update()

            self.handle_dhclient_restart()

            self.archive_history()

            time.sleep(5)

    def handle_hostname_update(self):
        curr_hostname = socket.gethostname()
        if curr_hostname != self.hostname:
            logger.info("EnvMonitor: Detected hostname change: {0} -> {1}",
                        self.hostname,
                        curr_hostname)
            self.osutil.set_hostname(curr_hostname)
            self.osutil.publish_hostname(curr_hostname)
            self.hostname = curr_hostname

    def get_dhcp_client_pid(self):
        pid = []

        try:
            # return a sorted list since handle_dhclient_restart needs to compare the previous value with
            # the new value and the comparison should not be affected by the order of the items in the list
            pid = sorted(self.osutil.get_dhcp_pid())

            if len(pid) == 0 and self.dhcp_warning_enabled:
                logger.warn("Dhcp client is not running.")
        except Exception as exception:
            if self.dhcp_warning_enabled:
                logger.error("Failed to get the PID of the DHCP client: {0}", ustr(exception))

        self.dhcp_warning_enabled = len(pid) != 0

        return pid

    def handle_dhclient_restart(self):
        if len(self.dhcp_id_list) == 0:
            self.dhcp_id_list = self.get_dhcp_client_pid()
            return

        if all(self.osutil.check_pid_alive(pid) for pid in self.dhcp_id_list):
            return

        new_pid = self.get_dhcp_client_pid()
        if len(new_pid) != 0 and new_pid != self.dhcp_id_list:
            logger.info("EnvMonitor: Detected dhcp client restart. Restoring routing table.")
            self.dhcp_handler.conf_routes()
            self.dhcp_id_list = new_pid

    def archive_history(self):
        """
        Purge history if we have exceed the maximum count.
        Create a .zip of the history that has been preserved.
        """
        if self.last_archive is not None \
                and datetime.datetime.utcnow() < \
                self.last_archive + ARCHIVE_INTERVAL:
            return

        self.archiver.purge()
        self.archiver.archive()

    def stop(self):
        """
        Stop server communication and join the thread to main thread.
        """
        self.stopped = True
        if self.server_thread is not None:
            self.server_thread.join()
