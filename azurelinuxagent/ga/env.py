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

import re
import os
import socket
import time
import threading

import operator

import datetime

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.dhcp import get_dhcp_handler
from azurelinuxagent.common.event import add_periodic, WALAEventOperation
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.protocol.wire import INCARNATION_FILE_NAME
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION

CACHE_PATTERNS = [
    re.compile("^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE),
    re.compile("^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE),
    re.compile("^(.*)\.(\d+)\.(xml)$", re.IGNORECASE)
]

MAXIMUM_CACHED_FILES = 50

CACHE_PURGE_INTERVAL = datetime.timedelta(hours=24)


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
        self.dhcp_id = None
        self.server_thread = None
        self.dhcp_warning_enabled = True
        self.last_purge = None

    def run(self):
        if not self.stopped:
            logger.info("Stop existing env monitor service.")
            self.stop()

        self.stopped = False
        logger.info("Start env monitor service.")
        self.dhcp_handler.conf_routes()
        self.hostname = self.osutil.get_hostname_record()
        self.dhcp_id = self.osutil.get_dhcp_pid()
        self.server_thread = threading.Thread(target=self.monitor)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

    def monitor(self):
        """
        Monitor firewall rules
        Monitor dhcp client pid and hostname.
        If dhcp client process re-start has occurred, reset routes.
        Purge unnecessary files from disk cache.
        """
        protocol = self.protocol_util.get_protocol()
        while not self.stopped:
            self.osutil.remove_rules_files()

            if conf.enable_firewall():
                success = self.osutil.enable_firewall(
                                dst_ip=protocol.endpoint,
                                uid=os.getuid())
                add_periodic(
                    logger.EVERY_HOUR,
                    AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.Firewall,
                    is_success=success,
                    log_event=True)

            timeout = conf.get_root_device_scsi_timeout()
            if timeout is not None:
                self.osutil.set_scsi_disks_timeout(timeout)

            if conf.get_monitor_hostname():
                self.handle_hostname_update()

            self.handle_dhclient_restart()

            self.purge_disk_cache()

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

    def handle_dhclient_restart(self):
        if self.dhcp_id is None:
            if self.dhcp_warning_enabled:
                logger.warn("Dhcp client is not running. ")
            self.dhcp_id = self.osutil.get_dhcp_pid()
            # disable subsequent error logging
            self.dhcp_warning_enabled = self.dhcp_id is not None
            return

        # the dhcp process has not changed since the last check
        if self.osutil.check_pid_alive(self.dhcp_id.strip()):
            return

        new_pid = self.osutil.get_dhcp_pid()
        if new_pid is not None and new_pid != self.dhcp_id:
            logger.info("EnvMonitor: Detected dhcp client restart. "
                        "Restoring routing table.")
            self.dhcp_handler.conf_routes()
            self.dhcp_id = new_pid

    def purge_disk_cache(self):
        """
        Ensure the number of cached files does not exceed a maximum count.
        Purge only once per interval, and never delete files related to the
        current incarnation.  
        """
        if self.last_purge is not None \
                and datetime.datetime.utcnow() < \
                self.last_purge + CACHE_PURGE_INTERVAL:
            return

        current_incarnation = -1
        self.last_purge = datetime.datetime.utcnow()
        incarnation_file = os.path.join(conf.get_lib_dir(),
                                        INCARNATION_FILE_NAME)
        if os.path.exists(incarnation_file):
            last_incarnation = fileutil.read_file(incarnation_file)
            if last_incarnation is not None:
                current_incarnation = int(last_incarnation)

        logger.info("Purging disk cache, current incarnation is {0}"
                    .format('not found'
                            if current_incarnation == -1
                            else current_incarnation))

        # Create tuples: (prefix, suffix, incarnation, name, file_modified)
        files = []
        for f in os.listdir(conf.get_lib_dir()):
            full_path = os.path.join(conf.get_lib_dir(), f)
            for pattern in CACHE_PATTERNS:
                m = pattern.match(f)
                if m is not None:
                    prefix = m.group(1)
                    suffix = m.group(3)
                    incarnation = int(m.group(2))
                    file_modified = os.path.getmtime(full_path)
                    t = (prefix, suffix, incarnation, f, file_modified)
                    files.append(t)
                    break

        if len(files) <= 0:
            return

        # Sort by (prefix, suffix, file_modified) in reverse order
        files = sorted(files, key=operator.itemgetter(0, 1, 4), reverse=True)

        # Remove any files in excess of the maximum allowed
        # -- Restart then whenever the (prefix, suffix) change
        count = 0
        last_match = [None, None]
        for f in files:
            if last_match != f[0:2]:
                last_match = f[0:2]
                count = 0

            if current_incarnation == f[2]:
                logger.verbose("Skipping {0}".format(f[3]))
                continue

            count += 1

            if count > MAXIMUM_CACHED_FILES:
                full_name = os.path.join(conf.get_lib_dir(), f[3])
                logger.verbose("Deleting {0}".format(full_name))
                os.remove(full_name)

    def stop(self):
        """
        Stop server communication and join the thread to main thread.
        """
        self.stopped = True
        if self.server_thread is not None:
            self.server_thread.join()
