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
import datetime
import re
import socket
import threading

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.dhcp import get_dhcp_handler
from azurelinuxagent.common import event
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common.future import UTC
from azurelinuxagent.ga.firewall_manager import FirewallManager, FirewallStateError, IptablesInconsistencyError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.ga.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.version import AGENT_NAME
from azurelinuxagent.ga.periodic_operation import PeriodicOperation

CACHE_PATTERNS = [
    re.compile(r"^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(xml)$", re.IGNORECASE)
]

MAXIMUM_CACHED_FILES = 50


def get_env_handler():
    return EnvHandler()


class RemovePersistentNetworkRules(PeriodicOperation):
    def __init__(self, osutil):
        super(RemovePersistentNetworkRules, self).__init__(conf.get_remove_persistent_net_rules_period())
        self.osutil = osutil

    def _operation(self):
        self.osutil.remove_rules_files()


class MonitorDhcpClientRestart(PeriodicOperation):
    def __init__(self, osutil):
        super(MonitorDhcpClientRestart, self).__init__(conf.get_monitor_dhcp_client_restart_period())
        self.osutil = osutil
        self.dhcp_handler = get_dhcp_handler()
        self.dhcp_handler.conf_routes()
        self.dhcp_warning_enabled = True
        self.dhcp_id_list = []

    def _operation(self):
        if len(self.dhcp_id_list) == 0:
            self.dhcp_id_list = self._get_dhcp_client_pid()
            return

        if all(self.osutil.check_pid_alive(pid) for pid in self.dhcp_id_list):
            return

        new_pid = self._get_dhcp_client_pid()
        if len(new_pid) != 0 and new_pid != self.dhcp_id_list:
            logger.info("EnvMonitor: Detected dhcp client restart. Restoring routing table.")
            self.dhcp_handler.conf_routes()
            self.dhcp_id_list = new_pid

    def _get_dhcp_client_pid(self):
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


class EnableFirewall(PeriodicOperation):
    def __init__(self, wire_server_address):
        super(EnableFirewall, self).__init__(conf.get_enable_firewall_period())
        self._wire_server_address = wire_server_address
        self._firewall_manager = None  # initialized on demand in the _operation method
        self._message_count = 0
        self._report_after = datetime.datetime.now(UTC)

    def _operation(self):
        try:
            if self._firewall_manager is None:
                self._firewall_manager = FirewallManager.create(self._wire_server_address)

            try:
                if self._firewall_manager.check():
                    return  # The firewall is configured correctly
                self._report(event.warn, WALAEventOperation.Firewall, "The firewall has not been setup. Will set it up.")
            except IptablesInconsistencyError as e:
                self._report(event.warn, WALAEventOperation.FirewallInconsistency, "The results returned by iptables are inconsistent, will not change the current state of the firewall: {0}", ustr(e))
                return
            except FirewallStateError as e:
                self._report(event.warn, WALAEventOperation.ResetFirewall, "The firewall is not configured correctly. {0}. Will reset it. Current state:\n{1}", ustr(e), self._firewall_manager.get_state())
                self._firewall_manager.remove()
            self._firewall_manager.setup()
            self._report(event.info, WALAEventOperation.Firewall, "The firewall was setup successfully:\n{0}", self._firewall_manager.get_state())
        except Exception as e:
            self._report(event.warn, WALAEventOperation.Firewall, "An error occurred while setting up the firewall: {0}", ustr(e))

    def _report(self, report_function, operation, message, *args):
        # Report the first 3 messages, then stop reporting for 12 hours
        if datetime.datetime.now(UTC) < self._report_after:
            return

        self._message_count += 1
        if self._message_count > 3:
            self._report_after = datetime.datetime.now(UTC) + datetime.timedelta(hours=12)
            self._message_count = 0
            return

        report_function(operation, message, *args)


class SetRootDeviceScsiTimeout(PeriodicOperation):
    def __init__(self, osutil):
        super(SetRootDeviceScsiTimeout, self).__init__(conf.get_root_device_scsi_timeout_period())
        self._osutil = osutil

    def _operation(self):
        self._osutil.set_scsi_disks_timeout(conf.get_root_device_scsi_timeout())


class MonitorHostNameChanges(PeriodicOperation):
    def __init__(self, osutil):
        super(MonitorHostNameChanges, self).__init__(conf.get_monitor_hostname_period())
        self._osutil = osutil
        self._hostname = self._osutil.get_hostname_record()

    def _operation(self):
        curr_hostname = socket.gethostname()
        if curr_hostname != self._hostname:
            logger.info("EnvMonitor: Detected hostname change: {0} -> {1}",
                        self._hostname,
                        curr_hostname)
            self._osutil.set_hostname(curr_hostname)
            try:
                self._osutil.publish_hostname(curr_hostname, recover_nic=True)
            except Exception as e:
                msg = "Error while publishing the hostname: {0}".format(e)
                add_event(AGENT_NAME, op=WALAEventOperation.HostnamePublishing, is_success=False, message=msg, log_event=False)
            self._hostname = curr_hostname


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
        self.stopped = True
        self.hostname = None
        self.env_thread = None

    def run(self):
        if not self.stopped:
            logger.info("Stop existing env monitor service.")
            self.stop()

        self.stopped = False
        logger.info("Starting env monitor service.")
        self.start()

    def is_alive(self):
        return self.env_thread.is_alive()

    def start(self):
        self.env_thread = threading.Thread(target=self.daemon)
        self.env_thread.daemon = True
        self.env_thread.name = self.get_thread_name()
        self.env_thread.start()

    def daemon(self):
        try:
            # The initialization of the protocol needs to be done within the environment thread itself rather
            # than initializing it in the ExtHandler thread. This is done to avoid any concurrency issues as each
            # thread would now have its own ProtocolUtil object as per the SingletonPerThread model.
            protocol_util = get_protocol_util()
            protocol = protocol_util.get_protocol()
            osutil = get_osutil()

            periodic_operations = [
                RemovePersistentNetworkRules(osutil),
                MonitorDhcpClientRestart(osutil),
            ]

            if conf.enable_firewall():
                periodic_operations.append(EnableFirewall(protocol.get_endpoint()))
            if conf.get_root_device_scsi_timeout() is not None:
                periodic_operations.append(SetRootDeviceScsiTimeout(osutil))
            if conf.get_monitor_hostname():
                periodic_operations.append(MonitorHostNameChanges(osutil))
            while not self.stopped:
                try:
                    for op in periodic_operations:
                        op.run()
                except Exception as e:
                    logger.error("An error occurred in the environment thread main loop; will skip the current iteration.\n{0}", ustr(e))
                finally:
                    PeriodicOperation.sleep_until_next_operation(periodic_operations)
        except Exception as e:
            logger.error("An error occurred in the environment thread; will exit the thread.\n{0}", ustr(e))

    def stop(self):
        """
        Stop server communication and join the thread to main thread.
        """
        self.stopped = True
        if self.env_thread is not None:
            self.env_thread.join()
