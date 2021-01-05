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
import threading
import uuid

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.networkutil as networkutil
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator, UnexpectedProcessesInCGroupException
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.errorstate import ErrorState
from azurelinuxagent.common.event import add_event, WALAEventOperation, report_metric
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.healthservice import HealthService
from azurelinuxagent.common.protocol.imds import get_imds_client
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils.restutil import IOErrorCounter
from azurelinuxagent.common.utils.textutil import hash_strings
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.ga.periodic_operation import PeriodicOperation


def get_monitor_handler():
    return MonitorHandler()


class PollResourceUsageOperation(PeriodicOperation):
    """
    Periodic operation to poll the tracked cgroups for resource usage data.

    It also checks whether there are processes in the agent's cgroup that should not be there.
    """
    def __init__(self):
        super(PollResourceUsageOperation, self).__init__(
            name="poll resource usage",
            operation=self._operation_impl,
            period=datetime.timedelta(minutes=5))
        self._last_error = None
        self._error_count = 0

    def _operation_impl(self):
        try:
            CGroupConfigurator.get_instance().check_processes_in_agent_cgroup()
        except UnexpectedProcessesInCGroupException as exception:
            exception.unexpected.sort()
            message = "The agent's cgroup includes unexpected processes: {0}".format(exception.unexpected)

            # Report a small sample of errors
            if message != self._last_error and self._error_count < 5:
                self._error_count += 1
                self._last_error = message
                logger.info(message)
                add_event(op=WALAEventOperation.CGroupsDebug, message=message)

        for metric in CGroupsTelemetry.poll_all_tracked():
            report_metric(metric.category, metric.counter, metric.instance, metric.value)


class ResetPeriodicLogMessagesOperation(PeriodicOperation):
    """
    Periodic operation to clean up the hash-tables maintained by the loggers. For reference, please check
    azurelinuxagent.common.logger.Logger and azurelinuxagent.common.event.EventLogger classes
    """
    def __init__(self):
        super(ResetPeriodicLogMessagesOperation, self).__init__(
            name="reset periodic log messages",
            operation=ResetPeriodicLogMessagesOperation._operation_impl,
            period=datetime.timedelta(hours=12))

    @staticmethod
    def _operation_impl():
        logger.reset_periodic()


class ReportNetworkErrorsOperation(PeriodicOperation):
    def __init__(self):
        super(ReportNetworkErrorsOperation, self).__init__(
            name="report network errors",
            operation=ReportNetworkErrorsOperation._operation_impl,
            period=datetime.timedelta(minutes=30))

    @staticmethod
    def _operation_impl():
        io_errors = IOErrorCounter.get_and_reset()
        hostplugin_errors = io_errors.get("hostplugin")
        protocol_errors = io_errors.get("protocol")
        other_errors = io_errors.get("other")

        if hostplugin_errors > 0 or protocol_errors > 0 or other_errors > 0:
            msg = "hostplugin:{0};protocol:{1};other:{2}".format(hostplugin_errors, protocol_errors, other_errors)
            add_event(op=WALAEventOperation.HttpErrors, message=msg)


class ReportNetworkConfigurationChangesOperation(PeriodicOperation):
    """
    Periodic operation to check and log changes in network configuration.
    """

    def __init__(self):
        super(ReportNetworkConfigurationChangesOperation, self).__init__(
            name="report network configuration changes",
            operation=self._operation_impl,
            period=datetime.timedelta(minutes=1))
        self.osutil = get_osutil()
        self.last_route_table_hash = b''
        self.last_nic_state = {}

    def _operation_impl(self):
        raw_route_list = self.osutil.read_route_table()
        digest = hash_strings(raw_route_list)
        if digest != self.last_route_table_hash:
            self.last_route_table_hash = digest
            route_list = self.osutil.get_list_of_routes(raw_route_list)
            logger.info("Route table: [{0}]".format(",".join(map(networkutil.RouteEntry.to_json, route_list))))

        nic_state = self.osutil.get_nic_state()
        if nic_state != self.last_nic_state:
            description = "Initial" if self.last_nic_state == {} else "Updated"
            logger.info("{0} NIC state: [{1}]".format(description, ", ".join(map(str, nic_state.values()))))
            self.last_nic_state = nic_state


class MonitorHandler(ThreadHandlerInterface):
    # telemetry
    EVENT_COLLECTION_PERIOD = datetime.timedelta(minutes=1)
    # host plugin
    HOST_PLUGIN_HEARTBEAT_PERIOD = datetime.timedelta(minutes=1)
    HOST_PLUGIN_HEALTH_PERIOD = datetime.timedelta(minutes=5)
    # imds
    IMDS_HEARTBEAT_PERIOD = datetime.timedelta(minutes=1)
    IMDS_HEALTH_PERIOD = datetime.timedelta(minutes=3)

    _THREAD_NAME = "MonitorHandler"

    @staticmethod
    def get_thread_name():
        return MonitorHandler._THREAD_NAME

    def __init__(self):
        self.osutil = get_osutil()
        self.imds_client = None

        self.event_thread = None
        self._periodic_operations = [
            ResetPeriodicLogMessagesOperation(),
            ReportNetworkErrorsOperation(),
            PeriodicOperation("send_host_plugin_heartbeat", self.send_host_plugin_heartbeat, self.HOST_PLUGIN_HEARTBEAT_PERIOD),
            PeriodicOperation("send_imds_heartbeat", self.send_imds_heartbeat, self.IMDS_HEARTBEAT_PERIOD),
            ReportNetworkConfigurationChangesOperation(),
        ]
        if CGroupConfigurator.get_instance().enabled():
            self._periodic_operations.append(PollResourceUsageOperation())

        self.protocol = None
        self.protocol_util = None
        self.health_service = None

        self.should_run = True
        self.heartbeat_id = str(uuid.uuid4()).upper()
        self.host_plugin_errorstate = ErrorState(min_timedelta=MonitorHandler.HOST_PLUGIN_HEALTH_PERIOD)
        self.imds_errorstate = ErrorState(min_timedelta=MonitorHandler.IMDS_HEALTH_PERIOD)

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

    def init_protocols(self):
        # The initialization of ProtocolUtil for the Monitor thread should be done within the thread itself rather
        # than initializing it in the ExtHandler thread. This is done to avoid any concurrency issues as each
        # thread would now have its own ProtocolUtil object as per the SingletonPerThread model.
        self.protocol_util = get_protocol_util()
        self.protocol = self.protocol_util.get_protocol()
        self.health_service = HealthService(self.protocol.get_endpoint())

    def init_imds_client(self):
        wireserver_endpoint = self.protocol_util.get_wireserver_endpoint()
        self.imds_client = get_imds_client(wireserver_endpoint)

    def is_alive(self):
        return self.event_thread is not None and self.event_thread.is_alive()

    def start(self):
        self.event_thread = threading.Thread(target=self.daemon)
        self.event_thread.setDaemon(True)
        self.event_thread.setName(self.get_thread_name())
        self.event_thread.start()

    def daemon(self):
        try:
            if self.protocol_util is None or self.protocol is None:
                self.init_protocols()

            if self.imds_client is None:
                self.init_imds_client()

            while not self.stopped():
                try:
                    self.protocol.update_host_plugin_from_goal_state()

                    for op in self._periodic_operations:
                        op.run()

                except Exception as e:
                    logger.error("An error occurred in the monitor thread main loop; will skip the current iteration.\n{0}", ustr(e))
                finally:
                    PeriodicOperation.sleep_until_next_operation(self._periodic_operations)
        except Exception as e:
            logger.error("An error occurred in the monitor thread; will exit the thread.\n{0}", ustr(e))

    def send_imds_heartbeat(self):
        """
        Send a health signal every IMDS_HEARTBEAT_PERIOD. The signal is 'Healthy' when we have
        successfully called and validated a response in the last IMDS_HEALTH_PERIOD.
        """
        try:
            is_currently_healthy, response = self.imds_client.validate()

            if is_currently_healthy:
                self.imds_errorstate.reset()
            else:
                self.imds_errorstate.incr()

            is_healthy = self.imds_errorstate.is_triggered() is False
            logger.verbose("IMDS health: {0} [{1}]", is_healthy, response)

            self.health_service.report_imds_status(is_healthy, response)

        except Exception as e:
            msg = "Exception sending imds heartbeat: {0}".format(ustr(e))
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.ImdsHeartbeat,
                is_success=False,
                message=msg,
                log_event=False)

    def send_host_plugin_heartbeat(self):
        """
        Send a health signal every HOST_PLUGIN_HEARTBEAT_PERIOD. The signal is 'Healthy' when we have been able to
        communicate with HostGAPlugin at least once in the last HOST_PLUGIN_HEALTH_PERIOD.
        """
        try:
            host_plugin = self.protocol.client.get_host_plugin()
            host_plugin.ensure_initialized()
            is_currently_healthy = host_plugin.get_health()

            if is_currently_healthy:
                self.host_plugin_errorstate.reset()
            else:
                self.host_plugin_errorstate.incr()

            is_healthy = self.host_plugin_errorstate.is_triggered() is False
            logger.verbose("HostGAPlugin health: {0}", is_healthy)

            self.health_service.report_host_plugin_heartbeat(is_healthy)

            if not is_healthy:
                add_event(
                    name=AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.HostPluginHeartbeatExtended,
                    is_success=False,
                    message='{0} since successful heartbeat'.format(self.host_plugin_errorstate.fail_time),
                    log_event=False)

        except Exception as e:
            msg = "Exception sending host plugin heartbeat: {0}".format(ustr(e))
            add_event(
                name=AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.HostPluginHeartbeat,
                is_success=False,
                message=msg,
                log_event=False)

