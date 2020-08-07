# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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
import os
import threading

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.event import elapsed_milliseconds, add_event, WALAEventOperation
from azurelinuxagent.common.exception import HttpError, ProtocolError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logcollector import LogCollector
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.ga.periodic_operation import PeriodicOperation
from azurelinuxagent.common.version import PY_VERSION_MAJOR, PY_VERSION_MINOR, AGENT_NAME, CURRENT_VERSION


def get_collect_logs_handler():
    return CollectLogsHandler()


class CollectLogsHandler(object):
    """
    Periodically collects and uploads logs from the VM to the host.
    """

    def __init__(self):
        self.protocol = None
        self.protocol_util = None
        self.event_thread = None
        self.should_run = True
        self.last_state = None

        self._periodic_operations = [
            PeriodicOperation("collect_and_send_logs", self.collect_and_send_logs, conf.get_collect_logs_period())
        ]

    def log_collection_allowed(self):
        # There are three conditions that need to be met in order to allow periodic log collection:
        # 1) It should be enabled in the configuration.
        # 2) The system must be using systemd to manage services. Needed for resource limiting of the log collection.
        # 3) The python version must be greater than 2.6 in order to support the ZipFile library used when collecting.
        conf_enabled = conf.get_collect_logs()
        systemd_present = os.path.exists("/run/systemd/system/")
        supported_python = (PY_VERSION_MAJOR == 2 and PY_VERSION_MINOR >= 7) or (PY_VERSION_MAJOR == 3)
        is_allowed = conf_enabled and systemd_present and supported_python

        if self.last_state != is_allowed:
            msg = "Checking if log collection is allowed at this time [{0}]. All three conditions must be met: " \
                  "configuration enabled [{1}], systemd present [{2}], python supported: [{3}]".format(is_allowed,
                                                                                                       conf_enabled,
                                                                                                       systemd_present,
                                                                                                       supported_python)
            self.last_state = is_allowed
            logger.info(msg)
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.LogCollection,
                is_success=is_allowed,
                message=msg,
                log_event=False)

        return is_allowed

    def run(self):
        self.start(init_data=True)

    def is_alive(self):
        return self.event_thread.is_alive()

    def start(self, init_data=False):
        self.event_thread = threading.Thread(target=self.daemon, args=(init_data,))
        self.event_thread.setDaemon(True)
        self.event_thread.setName("CollectLogsHandler")
        self.event_thread.start()

    def stopped(self):
        return not self.should_run

    def stop(self):
        self.should_run = False
        if self.is_alive():
            self.event_thread.join()

    def init_protocols(self):
        # The initialization of ProtocolUtil for the log collection thread should be done within the thread itself
        # rather than initializing it in the ExtHandler thread. This is done to avoid any concurrency issues as each
        # thread would now have its own ProtocolUtil object as per the SingletonPerThread model.
        self.protocol_util = get_protocol_util()
        self.protocol = self.protocol_util.get_protocol()

    def daemon(self, init_data=False):
        try:
            if init_data:
                self.init_protocols()

            while not self.stopped() and self.log_collection_allowed():
                try:
                    for op in self._periodic_operations:
                        op.run()
                except Exception as e:
                    logger.error("An error occurred in the log collection thread main loop; "
                                 "will skip the current iteration.\n{0}", ustr(e))
                finally:
                    PeriodicOperation.sleep_until_next_operation(self._periodic_operations)
        except Exception as e:
            logger.error("An error occurred in the log collection thread; will exit the thread.\n{0}", ustr(e))

    def collect_and_send_logs(self):
        archive_file_path = self.collect_logs()
        self.send_logs(archive_file_path)

    @staticmethod
    def collect_logs():
        logger.info("Starting log collection.")

        archive_file_path = None
        start_time = datetime.datetime.utcnow()
        try:
            # Current directory is /WALinuxAgent/azurelinuxagent/ga/, manifest directory is /WALinuxAgent/config/.
            curr_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
            manifest_file_path = os.path.join(os.path.dirname(os.path.dirname(curr_dir)), "config",
                                              "logcollector_manifest_normal")

            log_collector = LogCollector(manifest_file_path)
            archive_file_path = log_collector.collect_logs()

            duration = elapsed_milliseconds(start_time)
            archive_size = os.path.getsize(archive_file_path)

            msg = "Successfully collected logs. Archive size: {0}b, elapsed time: {0} ms.".format(archive_size, duration)
            logger.info(msg)
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.LogCollection,
                is_success=True,
                message=msg,
                log_event=False)

        except Exception as e:
            duration = elapsed_milliseconds(start_time)

            msg = "Failed to collect logs. Elapsed time: {0} ms. Error: {1}".format(duration, ustr(e))
            logger.warn(msg)
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.LogCollection,
                is_success=False,
                message=msg,
                log_event=False)

        return archive_file_path

    def send_logs(self, archive_file_path):
        if not archive_file_path:
            return

        try:
            with open(archive_file_path, "rb") as fh:
                archive_content = fh.read()
                self.protocol.upload_logs(archive_content)
                msg = "Successfully uploaded logs."
                logger.info(msg)
                add_event(
                    name=AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.LogCollection,
                    is_success=True,
                    message=msg,
                    log_event=False)

        except Exception as e:
            msg = "Failed to upload logs. Error: {0}".format(ustr(e))
            logger.warn(msg)
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.LogCollection,
                is_success=False,
                message=msg,
                log_event=False)

    def _invoke_command_with_limits(self, command):
        # README: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/resource_
        # management_guide/sec-modifying_control_groups

        # systemd-run --scope --unit=bla
        # --property=CPUAccounting=1 --property=CPUQuota=20%
        # --property=MemoryAccounting=1 --property=MemoryLimit=100M
        # echo 42
        # CPUQuota available since systemd 213: https://github.com/systemd/systemd/blob/master/NEWS

        # Persistent unit for reporting resource usage? Or existing track cgroups?

        # cat cpuhog.sh
        # #!/usr/bin/env bash
        # dd if=/dev/zero of=/dev/null
        pass
