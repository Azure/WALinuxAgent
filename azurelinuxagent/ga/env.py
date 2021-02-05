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
import threading

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.dhcp import get_dhcp_handler
from azurelinuxagent.common.event import add_periodic, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils.archive import StateArchiver
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.ga.periodic_operation import PeriodicOperation

CACHE_PATTERNS = [
    re.compile("^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE),  # pylint: disable=W1401
    re.compile("^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE),  # pylint: disable=W1401
    re.compile("^(.*)\.(\d+)\.(xml)$", re.IGNORECASE)  # pylint: disable=W1401
]

MAXIMUM_CACHED_FILES = 50


def get_env_handler():
    return EnvHandler()


class EnvHandler(ThreadHandlerInterface):
    """
    Monitor changes to dhcp and hostname.
    If dhcp client process re-start has occurred, reset routes, dhcp with fabric.

    Monitor scsi disk.
    If new scsi disk found, set timeout
    """

    _THREAD_NAME = "EnvHandler"

    @staticmethod
    def get_thread_name():
        return EnvHandler._THREAD_NAME

    def __init__(self):
        self.osutil = get_osutil()
        self.dhcp_handler = get_dhcp_handler()
        self.protocol_util = None
        self._protocol = None
        self.stopped = True
        self.hostname = None
        self.dhcp_id_list = []
        self.server_thread = None
        self.dhcp_warning_enabled = True
        self.archiver = StateArchiver(conf.get_lib_dir())
        self._reset_firewall_rules = False

        self._periodic_operations = [
            PeriodicOperation("_remove_persistent_net_rules", self._remove_persistent_net_rules_period, conf.get_remove_persistent_net_rules_period()),
            PeriodicOperation("_monitor_dhcp_client_restart", self._monitor_dhcp_client_restart, conf.get_monitor_dhcp_client_restart_period()),
            PeriodicOperation("_cleanup_goal_state_history", self._cleanup_goal_state_history, conf.get_goal_state_history_cleanup_period())
        ]
        if conf.enable_firewall():
            self._periodic_operations.append(PeriodicOperation("_enable_firewall", self._enable_firewall, conf.get_enable_firewall_period()))
        if conf.get_root_device_scsi_timeout() is not None:
            self._periodic_operations.append(PeriodicOperation("_set_root_device_scsi_timeout", self._set_root_device_scsi_timeout, conf.get_root_device_scsi_timeout_period()))
        if conf.get_monitor_hostname():
            self._periodic_operations.append(PeriodicOperation("_monitor_hostname", self._monitor_hostname_changes, conf.get_monitor_hostname_period()))

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
        self.server_thread.setName(self.get_thread_name())
        self.server_thread.start()

    def monitor(self):
        try:
            # The initialization of ProtocolUtil for the Environment thread should be done within the thread itself rather
            # than initializing it in the ExtHandler thread. This is done to avoid any concurrency issues as each
            # thread would now have its own ProtocolUtil object as per the SingletonPerThread model.
            self.protocol_util = get_protocol_util()
            self._protocol = self.protocol_util.get_protocol()
            while not self.stopped:
                try:
                    for op in self._periodic_operations:
                        op.run()
                except Exception as e:
                    logger.error("An error occurred in the environment thread main loop; will skip the current iteration.\n{0}", ustr(e))
                finally:
                    PeriodicOperation.sleep_until_next_operation(self._periodic_operations)
        except Exception as e:
            logger.error("An error occurred in the environment thread; will exit the thread.\n{0}", ustr(e))

    def _remove_persistent_net_rules_period(self):
        self.osutil.remove_rules_files()

    def _enable_firewall(self):
        # If the rules ever change we must reset all rules and start over again.
        #
        # There was a rule change at 2.2.26, which started dropping non-root traffic
        # to WireServer.  The previous rules allowed traffic.  Having both rules in
        # place negated the fix in 2.2.26.
        if not self._reset_firewall_rules:
            self.osutil.remove_firewall(dst_ip=self._protocol.get_endpoint(), uid=os.getuid())
            self._reset_firewall_rules = True

        success = self.osutil.enable_firewall(dst_ip=self._protocol.get_endpoint(), uid=os.getuid())

        add_periodic(
            logger.EVERY_HOUR,
            AGENT_NAME,
            version=CURRENT_VERSION,
            op=WALAEventOperation.Firewall,
            is_success=success,
            log_event=False)

    def _set_root_device_scsi_timeout(self):
        self.osutil.set_scsi_disks_timeout(conf.get_root_device_scsi_timeout())

    def _monitor_hostname_changes(self):
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

    def _monitor_dhcp_client_restart(self):
        self.handle_dhclient_restart()

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

    def _cleanup_goal_state_history(self):
        """
        Purge history and create a .zip of the history that has been preserved.
        """
        self.archiver.purge()
        self.archiver.archive()

    def stop(self):
        """
        Stop server communication and join the thread to main thread.
        """
        self.stopped = True
        if self.server_thread is not None:
            self.server_thread.join()
