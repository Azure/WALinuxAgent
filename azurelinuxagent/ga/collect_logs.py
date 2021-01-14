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
import sys
import threading
import time

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroupapi import CGroupsApi
from azurelinuxagent.common.event import elapsed_milliseconds, add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.logcollector import COMPRESSED_ARCHIVE_PATH
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.shellutil import CommandError
from azurelinuxagent.common.version import PY_VERSION_MAJOR, PY_VERSION_MINOR, AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.ga.periodic_operation import PeriodicOperation


def get_collect_logs_handler():
    return CollectLogsHandler()


def is_log_collection_allowed():
    # There are three conditions that need to be met in order to allow periodic log collection:
    # 1) It should be enabled in the configuration.
    # 2) The system must be using systemd to manage services. Needed for resource limiting of the log collection.
    # 3) The python version must be greater than 2.6 in order to support the ZipFile library used when collecting.
    conf_enabled = conf.get_collect_logs()
    systemd_present = CGroupsApi.is_systemd()
    supported_python = PY_VERSION_MINOR >= 7 if PY_VERSION_MAJOR == 2 else PY_VERSION_MAJOR == 3
    is_allowed = conf_enabled and systemd_present and supported_python

    msg = "Checking if log collection is allowed at this time [{0}]. All three conditions must be met: " \
          "configuration enabled [{1}], systemd present [{2}], python supported: [{3}]".format(is_allowed,
                                                                                               conf_enabled,
                                                                                               systemd_present,
                                                                                               supported_python)
    logger.info(msg)
    add_event(
        name=AGENT_NAME,
        version=CURRENT_VERSION,
        op=WALAEventOperation.LogCollection,
        is_success=is_allowed,
        message=msg,
        log_event=False)

    return is_allowed


class CollectLogsHandler(ThreadHandlerInterface):
    """
    Periodically collects and uploads logs from the VM to the host.
    """

    _THREAD_NAME = "CollectLogsHandler"

    @staticmethod
    def get_thread_name():
        return CollectLogsHandler._THREAD_NAME

    def __init__(self):
        self.protocol = None
        self.protocol_util = None
        self.event_thread = None
        self.should_run = True
        self.last_state = None

        self._periodic_operations = [
            PeriodicOperation("collect_and_send_logs", self.collect_and_send_logs, conf.get_collect_logs_period())
        ]

    def run(self):
        self.start()

    def is_alive(self):
        return self.event_thread.is_alive()

    def start(self):
        self.event_thread = threading.Thread(target=self.daemon)
        self.event_thread.setDaemon(True)
        self.event_thread.setName(self.get_thread_name())
        self.event_thread.start()

    def join(self):
        self.event_thread.join()

    def stopped(self):
        return not self.should_run

    def stop(self):
        self.should_run = False
        if self.is_alive():
            self.join()

    def init_protocols(self):
        # The initialization of ProtocolUtil for the log collection thread should be done within the thread itself
        # rather than initializing it in the ExtHandler thread. This is done to avoid any concurrency issues as each
        # thread would now have its own ProtocolUtil object as per the SingletonPerThread model.
        self.protocol_util = get_protocol_util()
        self.protocol = self.protocol_util.get_protocol()

    def daemon(self):
        try:
            if self.protocol_util is None or self.protocol is None:
                self.init_protocols()

            while not self.stopped():
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
        if self._collect_logs():
            self._send_logs()

    @staticmethod
    def _get_resource_limits():
        # Define CPU limit (as percentage of CPU time) and memory limit (absolute value in megabytes).
        cpu_limit = "5%"
        memory_limit = "30M"  # K for kb, M for mb
        return cpu_limit, memory_limit

    @staticmethod
    def _collect_logs():
        logger.info("Starting log collection...")

        # Invoke the command line tool in the agent to collect logs, with resource limits on CPU and memory (RAM).
        scope_name = "collect-logs-{0}.scope".format(ustr(int(time.time() * 1000000)))
        systemd_cmd = ["systemd-run", "--unit={0}".format(scope_name), "--scope"]

        # More info on resource limits properties in systemd here:
        # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/resource_management_guide/sec-modifying_control_groups
        cpu_limit, memory_limit = CollectLogsHandler._get_resource_limits()
        resource_limits = ["--property=CPUAccounting=1", "--property=CPUQuota={0}".format(cpu_limit),
                           "--property=MemoryAccounting=1", "--property=MemoryLimit={0}".format(memory_limit)]

        # The log tool is invoked from the current agent's egg with the command line option
        collect_logs_cmd = [sys.executable, "-u", sys.argv[0], "-collect-logs"]
        final_command = systemd_cmd + resource_limits + collect_logs_cmd

        start_time = datetime.datetime.utcnow()
        success = False
        msg = None
        try:
            # TODO: Remove track_process (and its implementation) when the log collector is moved to the agent's cgroup
            shellutil.run_command(final_command, log_error=True, track_process=False)
            duration = elapsed_milliseconds(start_time)
            archive_size = os.path.getsize(COMPRESSED_ARCHIVE_PATH)

            msg = "Successfully collected logs. Archive size: {0} b, elapsed time: {1} ms.".format(archive_size,
                                                                                                   duration)
            logger.info(msg)
            success = True

            return True
        except Exception as e:
            duration = elapsed_milliseconds(start_time)

            if isinstance(e, CommandError):
                exception_message = ustr("[stderr] %s", e.stderr)  # pylint: disable=no-member
            else:
                exception_message = ustr(e)

            msg = "Failed to collect logs. Elapsed time: {0} ms. Error: {1}".format(duration, exception_message)
            # No need to log to the local log since we ran run_command with logging errors as enabled

            return False
        finally:
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.LogCollection,
                is_success=success,
                message=msg,
                log_event=False)

    def _send_logs(self):
        msg = None
        success = False
        try:
            with open(COMPRESSED_ARCHIVE_PATH, "rb") as fh:
                archive_content = fh.read()
                self.protocol.upload_logs(archive_content)
                msg = "Successfully uploaded logs."
                logger.info(msg)

            success = True
        except Exception as e:
            msg = "Failed to upload logs. Error: {0}".format(ustr(e))
            logger.warn(msg)
        finally:
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.LogCollection,
                is_success=success,
                message=msg,
                log_event=False)
