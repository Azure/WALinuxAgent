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
from azurelinuxagent.ga import logcollector, cgroupconfigurator

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common import logger
from azurelinuxagent.ga.cgroupcontroller import MetricsCounter
from azurelinuxagent.common.event import elapsed_milliseconds, add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.ga.interfaces import ThreadHandlerInterface
from azurelinuxagent.ga.logcollector import COMPRESSED_ARCHIVE_PATH, GRACEFUL_KILL_ERRCODE
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator, LOGCOLLECTOR_ANON_MEMORY_LIMIT_FOR_V1_AND_V2, LOGCOLLECTOR_CACHE_MEMORY_LIMIT_FOR_V1_AND_V2, LOGCOLLECTOR_MAX_THROTTLED_EVENTS_FOR_V2
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.shellutil import CommandError
from azurelinuxagent.common.version import PY_VERSION_MAJOR, PY_VERSION_MINOR, AGENT_NAME, CURRENT_VERSION


def get_collect_logs_handler():
    return CollectLogsHandler()


def is_log_collection_allowed():
    # There are three conditions that need to be met in order to allow periodic log collection:
    # 1) It should be enabled in the configuration.
    # 2) The system must be using cgroups to manage services - needed for resource limiting of the log collection. The
    # agent currently fully supports resource limiting for v1, but only supports log collector resource limiting for v2
    # if enabled via configuration.
    #    This condition is True if either:
    #       a. cgroup usage in the agent is enabled; OR
    #       b. the machine is using cgroup v2 and v2 resource limiting is enabled in the configuration.
    # 3) The python version must be greater than 2.6 in order to support the ZipFile library used when collecting.
    conf_enabled = conf.get_collect_logs()
    cgroups_enabled = CGroupConfigurator.get_instance().enabled()
    cgroup_v2_resource_limiting_enabled = CGroupConfigurator.get_instance().using_cgroup_v2() and conf.get_enable_cgroup_v2_resource_limiting()
    supported_python = PY_VERSION_MINOR >= 6 if PY_VERSION_MAJOR == 2 else PY_VERSION_MAJOR == 3
    is_allowed = conf_enabled and (cgroups_enabled or cgroup_v2_resource_limiting_enabled) and supported_python

    msg = "Checking if log collection is allowed at this time [{0}]. All three conditions must be met: " \
          "1. configuration enabled [{1}], " \
          "2. cgroups v1 enabled [{2}] OR cgroups v2 is in use and v2 resource limiting configuration enabled [{3}], " \
          "3. python supported: [{4}]".format(is_allowed,
                                              conf_enabled,
                                              cgroups_enabled,
                                              cgroup_v2_resource_limiting_enabled,
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
    __CGROUPS_FLAG_ENV_VARIABLE = "_AZURE_GUEST_AGENT_LOG_COLLECTOR_MONITOR_CGROUPS_"

    @staticmethod
    def get_thread_name():
        return CollectLogsHandler._THREAD_NAME

    @staticmethod
    def enable_monitor_cgroups_check():
        os.environ[CollectLogsHandler.__CGROUPS_FLAG_ENV_VARIABLE] = "1"

    @staticmethod
    def disable_monitor_cgroups_check():
        if CollectLogsHandler.__CGROUPS_FLAG_ENV_VARIABLE in os.environ:
            del os.environ[CollectLogsHandler.__CGROUPS_FLAG_ENV_VARIABLE]

    @staticmethod
    def is_enabled_monitor_cgroups_check():
        if CollectLogsHandler.__CGROUPS_FLAG_ENV_VARIABLE in os.environ:
            return os.environ[CollectLogsHandler.__CGROUPS_FLAG_ENV_VARIABLE] == "1"
        return False

    def __init__(self):
        self.protocol = None
        self.protocol_util = None
        self.event_thread = None
        self.should_run = True
        self.last_state = None
        self.period = conf.get_collect_logs_period()

    def run(self):
        self.start()

    def keep_alive(self):
        return self.should_run

    def is_alive(self):
        return self.event_thread.is_alive()

    def start(self):
        self.event_thread = threading.Thread(target=self.daemon)
        self.event_thread.daemon = True
        self.event_thread.name = self.get_thread_name()
        self.event_thread.start()

    def join(self):
        self.event_thread.join()

    def stopped(self):
        return not self.should_run

    def stop(self):
        self.should_run = False
        if self.is_alive():
            try:
                self.join()
            except RuntimeError:
                pass

    def init_protocols(self):
        # The initialization of ProtocolUtil for the log collection thread should be done within the thread itself
        # rather than initializing it in the ExtHandler thread. This is done to avoid any concurrency issues as each
        # thread would now have its own ProtocolUtil object as per the SingletonPerThread model.
        self.protocol_util = get_protocol_util()
        self.protocol = self.protocol_util.get_protocol()

    def daemon(self):
        # Delay the first collector on start up to give short lived VMs (that might be dead before the second 
        # collection has a chance to run) an opportunity to do produce meaningful logs to collect.
        time.sleep(conf.get_log_collector_initial_delay())

        try:
            CollectLogsHandler.enable_monitor_cgroups_check()
            if self.protocol_util is None or self.protocol is None:
                self.init_protocols()

            while not self.stopped():
                try:
                    self.collect_and_send_logs()
                except Exception as e:
                    logger.error("An error occurred in the log collection thread main loop; "
                                 "will skip the current iteration.\n{0}", ustr(e))
                finally:
                    time.sleep(self.period)
        except Exception as e:
            logger.error("An error occurred in the log collection thread; will exit the thread.\n{0}", ustr(e))
        finally:
            CollectLogsHandler.disable_monitor_cgroups_check()

    def collect_and_send_logs(self):
        if self._collect_logs():
            self._send_logs()

    def _collect_logs(self):
        logger.info("Starting log collection...")

        # Invoke the command line tool in the agent to collect logs. The --scope option starts the process as a systemd
        # transient scope unit. The --property option is used to set systemd memory and cpu properties on the scope.
        systemd_cmd = [
            "systemd-run",
            "--unit={0}".format(logcollector.CGROUPS_UNIT),
            "--slice={0}".format(cgroupconfigurator.LOGCOLLECTOR_SLICE), "--scope"
        ] + CGroupConfigurator.get_instance().get_logcollector_unit_properties()

        # The log tool is invoked from the current agent's egg with the command line option
        collect_logs_cmd = [sys.executable, "-u", sys.argv[0], "-collect-logs"]
        final_command = systemd_cmd + collect_logs_cmd

        def exec_command():
            start_time = datetime.datetime.utcnow()
            success = False
            msg = None
            try:
                shellutil.run_command(final_command, log_error=False)
                duration = elapsed_milliseconds(start_time)
                archive_size = os.path.getsize(COMPRESSED_ARCHIVE_PATH)

                msg = "Successfully collected logs. Archive size: {0} b, elapsed time: {1} ms.".format(archive_size,
                                                                                                       duration)
                logger.info(msg)
                success = True

                return True
            except Exception as e:
                duration = elapsed_milliseconds(start_time)
                err_msg = ustr(e)

                if isinstance(e, CommandError):
                    # pylint has limited (i.e. no) awareness of control flow w.r.t. typing. we disable=no-member
                    # here because we know e must be a CommandError but pylint still considers the case where
                    # e is a different type of exception.
                    err_msg = ustr("Log Collector exited with code {0}").format(e.returncode)  # pylint: disable=no-member

                    if e.returncode == logcollector.INVALID_CGROUPS_ERRCODE:  # pylint: disable=no-member
                        logger.info("Disabling periodic log collection until service restart due to process error.")
                        self.stop()

                    # When the log collector memory limit is exceeded, Agent gracefully exit the process with this error code.
                    # Stop the periodic operation because it seems to be persistent.
                    elif e.returncode == logcollector.GRACEFUL_KILL_ERRCODE:  # pylint: disable=no-member
                        logger.info("Disabling periodic log collection until service restart due to exceeded process memory limit.")
                        self.stop()
                    else:
                        logger.info(err_msg)

                msg = "Failed to collect logs. Elapsed time: {0} ms. Error: {1}".format(duration, err_msg)
                # No need to log to the local log since we logged stdout, stderr from the process.

                return False
            finally:
                add_event(
                    name=AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.LogCollection,
                    is_success=success,
                    message=msg,
                    log_event=False)

        return exec_command()

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


def get_log_collector_monitor_handler(controllers):
    return LogCollectorMonitorHandler(controllers)


class LogCollectorMonitorHandler(ThreadHandlerInterface):
    """
    Periodically monitor and checks the Log collector Cgroups and sends telemetry to Kusto.
    """

    _THREAD_NAME = "LogCollectorMonitorHandler"

    @staticmethod
    def get_thread_name():
        return LogCollectorMonitorHandler._THREAD_NAME

    def __init__(self, controllers):
        self.event_thread = None
        self.should_run = True
        self.period = 2  # Log collector monitor runs every 2 secs.
        self.controllers = controllers
        self.max_recorded_metrics = {}
        self.__should_log_metrics = conf.get_cgroup_log_metrics()

    def run(self):
        self.start()

    def stop(self):
        self.should_run = False
        if self.is_alive():
            self.join()

    def join(self):
        self.event_thread.join()

    def stopped(self):
        return not self.should_run

    def is_alive(self):
        return self.event_thread is not None and self.event_thread.is_alive()

    def start(self):
        self.event_thread = threading.Thread(target=self.daemon)
        self.event_thread.daemon = True
        self.event_thread.name = self.get_thread_name()
        self.event_thread.start()

    def daemon(self):
        try:
            while not self.stopped():
                try:
                    metrics = self._poll_resource_usage()
                    if self.__should_log_metrics:
                        self._log_metrics(metrics)
                    self._verify_memory_limit(metrics)
                except Exception as e:
                    logger.error("An error occurred in the log collection monitor thread loop; "
                                 "will skip the current iteration.\n{0}", ustr(e))
                finally:
                    time.sleep(self.period)
        except Exception as e:
            logger.error(
                "An error occurred in the MonitorLogCollectorCgroupsHandler thread; will exit the thread.\n{0}",
                ustr(e))

    def get_max_recorded_metrics(self):
        return self.max_recorded_metrics

    def _poll_resource_usage(self):
        metrics = []
        for controller in self.controllers:
            metrics.extend(controller.get_tracked_metrics(track_throttled_time=True))

        for metric in metrics:
            current_max = self.max_recorded_metrics.get(metric.counter)
            self.max_recorded_metrics[metric.counter] = metric.value if current_max is None else max(current_max, metric.value)

        return metrics

    def _log_metrics(self, metrics):
        for metric in metrics:
            logger.info("Metric {0}/{1} [{2}] = {3}".format(metric.category, metric.counter, metric.instance, metric.value))

    def _verify_memory_limit(self, metrics):
        current_anon_and_swap_usage = 0
        current_cache_usage = 0
        memory_throttled_events = 0
        for metric in metrics:
            if metric.counter == MetricsCounter.ANON_MEM_USAGE:
                current_anon_and_swap_usage += metric.value
            elif metric.counter == MetricsCounter.SWAP_MEM_USAGE:
                current_anon_and_swap_usage += metric.value
            elif metric.counter == MetricsCounter.CACHE_MEM_USAGE:
                current_cache_usage = metric.value
            elif metric.counter == MetricsCounter.MEM_THROTTLED:
                memory_throttled_events = metric.value

        mem_limit_exceeded = False
        if current_anon_and_swap_usage > LOGCOLLECTOR_ANON_MEMORY_LIMIT_FOR_V1_AND_V2:
            mem_limit_exceeded = True
            msg = "Log collector anon + swap memory limit {0} bytes exceeded. The reported usage is {1} bytes.".format(LOGCOLLECTOR_ANON_MEMORY_LIMIT_FOR_V1_AND_V2, current_anon_and_swap_usage)
            logger.info(msg)
            add_event(name=AGENT_NAME, version=CURRENT_VERSION, op=WALAEventOperation.LogCollection, message=msg)
        if current_cache_usage > LOGCOLLECTOR_CACHE_MEMORY_LIMIT_FOR_V1_AND_V2:
            mem_limit_exceeded = True
            msg = "Log collector cache memory limit {0} bytes exceeded. The reported usage is {1} bytes.".format(LOGCOLLECTOR_CACHE_MEMORY_LIMIT_FOR_V1_AND_V2, current_cache_usage)
            logger.info(msg)
            add_event(name=AGENT_NAME, version=CURRENT_VERSION, op=WALAEventOperation.LogCollection, message=msg)
        if memory_throttled_events > LOGCOLLECTOR_MAX_THROTTLED_EVENTS_FOR_V2:
            mem_limit_exceeded = True
            msg = "Log collector memory throttled events limit {0} exceeded. The reported number of throttled events is {1}.".format(LOGCOLLECTOR_MAX_THROTTLED_EVENTS_FOR_V2, memory_throttled_events)
            logger.info(msg)
            add_event(name=AGENT_NAME, version=CURRENT_VERSION, op=WALAEventOperation.LogCollection, message=msg)

        if mem_limit_exceeded:
            os._exit(GRACEFUL_KILL_ERRCODE)
