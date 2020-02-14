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
import json
import os
import random
import shutil
import string
import sys
import tempfile
import time
from datetime import timedelta

from azurelinuxagent.common.protocol.util import ProtocolUtil, get_protocol_util
from nose.plugins.attrib import attr

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common import event, logger
from azurelinuxagent.common.cgroup import CGroup, CpuCgroup, MemoryCgroup
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.cgroupstelemetry import CGroupsTelemetry, MetricValue
from azurelinuxagent.common.datacontract import get_properties
from azurelinuxagent.common.event import EventLogger, WALAEventOperation
from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logger import Logger
from azurelinuxagent.common.osutil.default import BASE_CGROUPS, DefaultOSUtil
from azurelinuxagent.common.protocol.wire import ExtHandler, ExtHandlerProperties
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventParam
from azurelinuxagent.common.utils import fileutil, restutil
from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, CURRENT_VERSION, CURRENT_AGENT
from azurelinuxagent.ga.exthandlers import ExtHandlerInstance
from azurelinuxagent.ga.monitor import generate_extension_metrics_telemetry_dictionary, get_monitor_handler, \
    MonitorHandler
from tests.common.test_cgroupstelemetry import make_new_cgroup
from tests.common.mocksysinfo import SysInfoData
from tests.protocol.mockwiredata import DATA_FILE, WireProtocolData
from tests.tools import Mock, MagicMock, patch, AgentTestCase, data_dir, are_cgroups_enabled, i_am_root, \
    skip_if_predicate_false, is_trusty_in_travis, skip_if_predicate_true, clear_singleton_instances, PropertyMock


class ResponseMock(Mock):
    def __init__(self, status=restutil.httpclient.OK, response=None, reason=None):
        Mock.__init__(self)
        self.status = status
        self.reason = reason
        self.response = response

    def read(self):
        return self.response


def random_generator(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for x in range(size))


def create_dummy_event(size=0,
                       name="DummyExtension",
                       op=WALAEventOperation.Unknown,
                       is_success=True,
                       duration=0,
                       version=CURRENT_VERSION,
                       message="DummyMessage"):
    return get_event_message(name=size if size != 0 else name,
                             op=op,
                             is_success=is_success,
                             duration=duration,
                             version=version,
                             message=random_generator(size) if size != 0 else message)


def get_event_message(duration, is_success, message, name, op, version, eventId=1):
    event = TelemetryEvent(eventId, "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
    event.parameters.append(TelemetryEventParam('Name', name))
    event.parameters.append(TelemetryEventParam('Version', str(version)))
    event.parameters.append(TelemetryEventParam('IsInternal', False))
    event.parameters.append(TelemetryEventParam('Operation', op))
    event.parameters.append(TelemetryEventParam('OperationSuccess', is_success))
    event.parameters.append(TelemetryEventParam('Message', message))
    event.parameters.append(TelemetryEventParam('Duration', duration))
    event.parameters.append(TelemetryEventParam('ExtensionType', ''))
    event.parameters.append(TelemetryEventParam('OpcodeName', 'TEST_OpcodeName'))

    data = get_properties(event)
    return json.dumps(data)


@patch('azurelinuxagent.common.event.EventLogger.add_event')
@patch('azurelinuxagent.common.osutil.get_osutil')
@patch('azurelinuxagent.common.protocol.util.get_protocol_util')
@patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol')
@patch("azurelinuxagent.common.protocol.healthservice.HealthService._report")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestMonitor(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        prefix = "UnitTest"
        logger.DEFAULT_LOGGER = Logger(prefix=prefix)

        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)

    def tearDown(self):
        AgentTestCase.tearDown(self)

    @patch("azurelinuxagent.ga.monitor.MonitorHandler.send_telemetry_heartbeat")
    @patch("azurelinuxagent.ga.monitor.MonitorHandler.collect_and_send_events")
    @patch("azurelinuxagent.ga.monitor.MonitorHandler.send_host_plugin_heartbeat")
    @patch("azurelinuxagent.ga.monitor.MonitorHandler.poll_telemetry_metrics")
    @patch("azurelinuxagent.ga.monitor.MonitorHandler.send_telemetry_metrics")
    @patch("azurelinuxagent.ga.monitor.MonitorHandler.send_imds_heartbeat")
    def test_heartbeats(self,
                        patch_imds_heartbeat,
                        patch_send_telemetry_metrics,
                        patch_poll_telemetry_metrics,
                        patch_hostplugin_heartbeat,
                        patch_send_events,
                        patch_telemetry_heartbeat,
                        *args):
        monitor_handler = get_monitor_handler()

        MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD = timedelta(milliseconds=100)
        MonitorHandler.EVENT_COLLECTION_PERIOD = timedelta(milliseconds=100)
        MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD = timedelta(milliseconds=100)
        MonitorHandler.IMDS_HEARTBEAT_PERIOD = timedelta(milliseconds=100)

        self.assertEqual(0, patch_hostplugin_heartbeat.call_count)
        self.assertEqual(0, patch_send_events.call_count)
        self.assertEqual(0, patch_telemetry_heartbeat.call_count)
        self.assertEqual(0, patch_imds_heartbeat.call_count)
        self.assertEqual(0, patch_send_telemetry_metrics.call_count)
        self.assertEqual(0, patch_poll_telemetry_metrics.call_count)

        with patch.object(monitor_handler, 'protocol'):
            monitor_handler.start()
            time.sleep(1)
            self.assertTrue(monitor_handler.is_alive())

            self.assertNotEqual(0, patch_hostplugin_heartbeat.call_count)
            self.assertNotEqual(0, patch_send_events.call_count)
            self.assertNotEqual(0, patch_telemetry_heartbeat.call_count)
            self.assertNotEqual(0, patch_imds_heartbeat.call_count)
            self.assertNotEqual(0, patch_send_telemetry_metrics.call_count)
            self.assertNotEqual(0, patch_poll_telemetry_metrics.call_count)

            monitor_handler.stop()

    @patch("azurelinuxagent.ga.monitor.MonitorHandler.send_telemetry_metrics")
    @patch("azurelinuxagent.ga.monitor.MonitorHandler.poll_telemetry_metrics")
    def test_heartbeat_timings_updates_after_window(self, *args):
        monitor_handler = get_monitor_handler()

        MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD = timedelta(milliseconds=100)
        MonitorHandler.EVENT_COLLECTION_PERIOD = timedelta(milliseconds=100)
        MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD = timedelta(milliseconds=100)
        MonitorHandler.IMDS_HEARTBEAT_PERIOD = timedelta(milliseconds=100)

        self.assertEqual(None, monitor_handler.last_host_plugin_heartbeat)
        self.assertEqual(None, monitor_handler.last_event_collection)
        self.assertEqual(None, monitor_handler.last_telemetry_heartbeat)
        self.assertEqual(None, monitor_handler.last_imds_heartbeat)

        with patch.object(monitor_handler, 'protocol'):
            monitor_handler.start()
            time.sleep(0.2)
            self.assertTrue(monitor_handler.is_alive())

            self.assertNotEqual(None, monitor_handler.last_host_plugin_heartbeat)
            self.assertNotEqual(None, monitor_handler.last_event_collection)
            self.assertNotEqual(None, monitor_handler.last_telemetry_heartbeat)
            self.assertNotEqual(None, monitor_handler.last_imds_heartbeat)

            heartbeat_hostplugin = monitor_handler.last_host_plugin_heartbeat
            heartbeat_imds = monitor_handler.last_imds_heartbeat
            heartbeat_telemetry = monitor_handler.last_telemetry_heartbeat
            events_collection = monitor_handler.last_event_collection

            time.sleep(0.5)

            self.assertNotEqual(heartbeat_imds, monitor_handler.last_imds_heartbeat)
            self.assertNotEqual(heartbeat_hostplugin, monitor_handler.last_host_plugin_heartbeat)
            self.assertNotEqual(events_collection, monitor_handler.last_event_collection)
            self.assertNotEqual(heartbeat_telemetry, monitor_handler.last_telemetry_heartbeat)

            monitor_handler.stop()

    @patch("azurelinuxagent.ga.monitor.MonitorHandler.send_telemetry_metrics")
    @patch("azurelinuxagent.ga.monitor.MonitorHandler.poll_telemetry_metrics")
    def test_heartbeat_timings_no_updates_within_window(self, *args):
        monitor_handler = get_monitor_handler()

        MonitorHandler.TELEMETRY_HEARTBEAT_PERIOD = timedelta(seconds=1)
        MonitorHandler.EVENT_COLLECTION_PERIOD = timedelta(seconds=1)
        MonitorHandler.HOST_PLUGIN_HEARTBEAT_PERIOD = timedelta(seconds=1)
        MonitorHandler.IMDS_HEARTBEAT_PERIOD = timedelta(seconds=1)

        self.assertEqual(None, monitor_handler.last_host_plugin_heartbeat)
        self.assertEqual(None, monitor_handler.last_event_collection)
        self.assertEqual(None, monitor_handler.last_telemetry_heartbeat)
        self.assertEqual(None, monitor_handler.last_imds_heartbeat)

        with patch.object(monitor_handler, 'protocol'):
            monitor_handler.start()
            time.sleep(0.2)
            self.assertTrue(monitor_handler.is_alive())

            self.assertNotEqual(None, monitor_handler.last_host_plugin_heartbeat)
            self.assertNotEqual(None, monitor_handler.last_event_collection)
            self.assertNotEqual(None, monitor_handler.last_telemetry_heartbeat)
            self.assertNotEqual(None, monitor_handler.last_imds_heartbeat)

            heartbeat_hostplugin = monitor_handler.last_host_plugin_heartbeat
            heartbeat_imds = monitor_handler.last_imds_heartbeat
            heartbeat_telemetry = monitor_handler.last_telemetry_heartbeat
            events_collection = monitor_handler.last_event_collection

            time.sleep(0.5)

            self.assertEqual(heartbeat_hostplugin, monitor_handler.last_host_plugin_heartbeat)
            self.assertEqual(heartbeat_imds, monitor_handler.last_imds_heartbeat)
            self.assertEqual(events_collection, monitor_handler.last_event_collection)
            self.assertEqual(heartbeat_telemetry, monitor_handler.last_telemetry_heartbeat)

            monitor_handler.stop()

    @patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_heartbeat")
    def test_heartbeat_creates_signal(self, patch_report_heartbeat, *args):
        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_host_plugin_heartbeat = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.send_host_plugin_heartbeat()
        self.assertEqual(1, patch_report_heartbeat.call_count)
        self.assertEqual(0, args[5].call_count)
        monitor_handler.stop()

    @patch('azurelinuxagent.common.errorstate.ErrorState.is_triggered', return_value=True)
    @patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_heartbeat")
    def test_failed_heartbeat_creates_telemetry(self, patch_report_heartbeat, _, *args):
        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_host_plugin_heartbeat = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.send_host_plugin_heartbeat()
        self.assertEqual(1, patch_report_heartbeat.call_count)
        self.assertEqual(1, args[5].call_count)
        self.assertEqual('HostPluginHeartbeatExtended', args[5].call_args[1]['op'])
        self.assertEqual(False, args[5].call_args[1]['is_success'])
        monitor_handler.stop()

    @patch('azurelinuxagent.common.logger.Logger.info')
    def test_reset_loggers(self, mock_info, *args):
        # Adding 100 different messages
        for i in range(100):
            event_message = "Test {0}".format(i)
            logger.periodic_info(logger.EVERY_DAY, event_message)

            self.assertIn(hash(event_message), logger.DEFAULT_LOGGER.periodic_messages)
            self.assertEqual(i + 1, mock_info.call_count)  # range starts from 0.

        self.assertEqual(100, len(logger.DEFAULT_LOGGER.periodic_messages))

        # Adding 1 message 100 times, but the same message. Mock Info should be called only once.
        for i in range(100):
            logger.periodic_info(logger.EVERY_DAY, "Test-Message")

        self.assertIn(hash("Test-Message"), logger.DEFAULT_LOGGER.periodic_messages)
        self.assertEqual(101, mock_info.call_count)  # 100 calls from the previous section. Adding only 1.
        self.assertEqual(101, len(logger.DEFAULT_LOGGER.periodic_messages))  # One new message in the hash map.

        # Resetting the logger time states.
        monitor_handler = get_monitor_handler()
        monitor_handler.last_reset_loggers_time = datetime.datetime.utcnow() - timedelta(hours=1)
        MonitorHandler.RESET_LOGGERS_PERIOD = timedelta(milliseconds=100)

        monitor_handler.reset_loggers()

        # The hash map got cleaned up by the reset_loggers method
        self.assertEqual(0, len(logger.DEFAULT_LOGGER.periodic_messages))

        monitor_handler.stop()

    @patch("azurelinuxagent.common.logger.reset_periodic", side_effect=Exception())
    def test_reset_loggers_ensuring_timestamp_gets_updated(self, *args):
        # Resetting the logger time states.
        monitor_handler = get_monitor_handler()
        initial_time = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_reset_loggers_time = initial_time
        MonitorHandler.RESET_LOGGERS_PERIOD = timedelta(milliseconds=100)

        # noinspection PyBroadException
        try:
            monitor_handler.reset_loggers()
        except:
            pass

        # The hash map got cleaned up by the reset_loggers method
        self.assertGreater(monitor_handler.last_reset_loggers_time, initial_time)
        monitor_handler.stop()


@patch('azurelinuxagent.common.osutil.get_osutil')
@patch("azurelinuxagent.common.protocol.healthservice.HealthService._report")
@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestEventMonitoring(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.lib_dir = tempfile.mkdtemp()

        self.event_logger = EventLogger()
        self.event_logger.event_dir = os.path.join(self.lib_dir, "events")

        self.mock_sysinfo = patch("azurelinuxagent.common.sysinfo.SysInfo.get_instance", return_value=SysInfoData)
        self.mock_sysinfo.start()

    def tearDown(self):
        self.mock_sysinfo.stop()
        fileutil.rm_dirs(self.lib_dir)

    def _create_mock(self, test_data, mock_http_get, MockCryptUtil, *args):
        """Test enable/disable/uninstall of an extension"""
        monitor_handler = get_monitor_handler()

        # Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol(restutil.KNOWN_WIRESERVER_IP)
        protocol.detect()
        protocol.report_ext_status = MagicMock()
        protocol.report_vm_status = MagicMock()

        protocol_util = get_protocol_util()
        protocol_util.get_protocol = Mock(return_value=protocol)
        monitor_handler.protocol_util = Mock(return_value=protocol_util)
        return monitor_handler, protocol

    @patch("azurelinuxagent.common.event.send_logs_to_telemetry", return_value=True)
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_should_send_all_events_with_the_same_schema(self, mock_lib_dir, _, *args):
        # Test collecting and sending both agent and extension events and ensure the telemetry schema is consistent
        # before the events are sent.
        mock_lib_dir.return_value = self.lib_dir

        test_data = WireProtocolData(DATA_FILE)
        monitor_handler, protocol = self._create_mock(test_data, *args)
        monitor_handler.init_protocols()

        # Add agent event file
        self.event_logger.add_event(name=AGENT_NAME,
                                    version=CURRENT_VERSION,
                                    op=WALAEventOperation.HeartBeat,
                                    is_success=True,
                                    message="Heartbeat",
                                    log_event=False)

        # Add extension event file the way extension do it, by dropping a .tld file in the events folder
        source_file = os.path.join(data_dir, "ext/dsc_event.json")
        dest_file = os.path.join(conf.get_lib_dir(), "events", "dsc_event.tld")
        shutil.copyfile(source_file, dest_file)

        # Collect these events and assert they are being sent with the same telemetry parameters present
        with patch.object(protocol, "report_event") as patch_report_event:
            monitor_handler.collect_and_send_events()

            telemetry_events_list = patch_report_event.call_args_list[0][0][0]
            self.assertEqual(len(telemetry_events_list.events), 2)

            telemetry_params_list = []

            for event in telemetry_events_list.events:
                # Save each event's parameter names in a set in order to compare them to each other later
                event_params_names = set()
                for param in event.parameters:
                    event_params_names.add(param.name)
                telemetry_params_list.append(event_params_names)

                # Do an explicit check for ContainerId and GAVersion, as these parameters are important for telemetry
                container_id_param = TelemetryEventParam("ContainerId", protocol.client.get_goal_state().container_id)
                self.assertTrue(container_id_param in event.parameters)

                gaversion_param = TelemetryEventParam("GAVersion", CURRENT_AGENT)
                self.assertTrue(gaversion_param in event.parameters)

            # The schema of events being sent should be consistent across agent and extension events
            self.assertEquals(telemetry_params_list[0], telemetry_params_list[1])
            self.assertEquals(28, len(telemetry_params_list[0]))

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events(self, mock_lib_dir, patch_send_event, *args):
        mock_lib_dir.return_value = self.lib_dir

        test_data = WireProtocolData(DATA_FILE)
        monitor_handler, protocol = self._create_mock(test_data, *args)
        monitor_handler.init_protocols()

        self.event_logger.save_event(create_dummy_event(message="Message-Test"))

        monitor_handler.last_event_collection = None
        test_mtime = 1000  # epoch time, in ms
        test_opcodename = datetime.datetime.fromtimestamp(test_mtime).strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')
        test_eventtid = 42
        test_eventpid = 24
        test_taskname = "TEST_TaskName"

        with patch("os.path.getmtime", return_value=test_mtime):
            with patch('os.getpid', return_value=test_eventpid):
                with patch("threading.Thread.ident", new_callable=PropertyMock(return_value=test_eventtid)):
                    with patch("threading.Thread.getName", return_value=test_taskname):
                        monitor_handler.collect_and_send_events()

        # Validating the crafted message by the collect_and_send_events call.
        self.assertEqual(1, patch_send_event.call_count)
        send_event_call_args = protocol.client.send_event.call_args[0]

        sample_message = '<Event id="1"><![CDATA[' \
                         '<Param Name="Name" Value="DummyExtension" T="mt:wstr" />' \
                         '<Param Name="Version" Value="{0}" T="mt:wstr" />' \
                         '<Param Name="Operation" Value="Unknown" T="mt:wstr" />' \
                         '<Param Name="OperationSuccess" Value="True" T="mt:bool" />' \
                         '<Param Name="Message" Value="Message-Test" T="mt:wstr" />' \
                         '<Param Name="Duration" Value="0" T="mt:uint64" />' \
                         '<Param Name="GAVersion" Value="{1}" T="mt:wstr" />' \
                         '<Param Name="ContainerId" Value="c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2" T="mt:wstr" />' \
                         '<Param Name="OpcodeName" Value="{2}" T="mt:wstr" />' \
                         '<Param Name="EventTid" Value="{3}" T="mt:uint64" />' \
                         '<Param Name="EventPid" Value="{4}" T="mt:uint64" />' \
                         '<Param Name="TaskName" Value="{5}" T="mt:wstr" />' \
                         '<Param Name="KeywordName" Value="" T="mt:wstr" />' \
                         '<Param Name="ExtensionType" Value="json" T="mt:wstr" />' \
                         '<Param Name="IsInternal" Value="False" T="mt:bool" />' \
                         '<Param Name="OSVersion" Value="TEST_OSVersion" T="mt:wstr" />' \
                         '<Param Name="ExecutionMode" Value="TEST_ExecutionMode" T="mt:wstr" />' \
                         '<Param Name="RAM" Value="512" T="mt:uint64" />' \
                         '<Param Name="Processors" Value="2" T="mt:uint64" />' \
                         '<Param Name="VMName" Value="TEST_VMName" T="mt:wstr" />' \
                         '<Param Name="TenantName" Value="TEST_TenantName" T="mt:wstr" />' \
                         '<Param Name="RoleName" Value="TEST_RoleName" T="mt:wstr" />' \
                         '<Param Name="RoleInstanceName" Value="TEST_RoleInstanceName" T="mt:wstr" />' \
                         '<Param Name="Location" Value="TEST_Location" T="mt:wstr" />' \
                         '<Param Name="SubscriptionId" Value="TEST_SubscriptionId" T="mt:wstr" />' \
                         '<Param Name="ResourceGroupName" Value="TEST_ResourceGroupName" T="mt:wstr" />' \
                         '<Param Name="VMId" Value="TEST_VMId" T="mt:wstr" />' \
                         '<Param Name="ImageOrigin" Value="1" T="mt:uint64" />' \
                         ']]></Event>'.format(AGENT_VERSION, CURRENT_AGENT, test_opcodename, test_eventtid,
                                              test_eventpid, test_taskname)

        self.maxDiff = None
        self.assertEqual(sample_message, send_event_call_args[1])

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_with_small_events(self, mock_lib_dir, patch_send_event, *args):
        mock_lib_dir.return_value = self.lib_dir

        test_data = WireProtocolData(DATA_FILE)
        monitor_handler, protocol = self._create_mock(test_data, *args)
        monitor_handler.init_protocols()

        sizes = [15, 15, 15, 15]  # get the powers of 2 - 2**16 is the limit

        for power in sizes:
            size = 2 ** power
            self.event_logger.save_event(create_dummy_event(size))
        monitor_handler.collect_and_send_events()

        # The send_event call would be called each time, as we are filling up the buffer up to the brim for each call.

        self.assertEqual(4, patch_send_event.call_count)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_with_large_events(self, mock_lib_dir, patch_send_event, *args):
        mock_lib_dir.return_value = self.lib_dir

        test_data = WireProtocolData(DATA_FILE)
        monitor_handler, protocol = self._create_mock(test_data, *args)
        monitor_handler.init_protocols()

        sizes = [17, 17, 17]  # get the powers of 2

        for power in sizes:
            size = 2 ** power
            self.event_logger.save_event(create_dummy_event(size))

        with patch("azurelinuxagent.common.logger.periodic_warn") as patch_periodic_warn:
            monitor_handler.collect_and_send_events()
            self.assertEqual(3, patch_periodic_warn.call_count)

        # The send_event call should never be called as the events are larger than 2**16.
        self.assertEqual(0, patch_send_event.call_count)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_with_invalid_events(self, mock_lib_dir, patch_send_event, *args):
        mock_lib_dir.return_value = self.lib_dir
        dummy_events_dir = os.path.join(data_dir, "events", "collect_and_send_events_invalid_data")
        fileutil.mkdir(self.event_logger.event_dir)

        test_data = WireProtocolData(DATA_FILE)
        monitor_handler, protocol = self._create_mock(test_data, *args)
        monitor_handler.init_protocols()

        for filename in os.listdir(dummy_events_dir):
            shutil.copy(os.path.join(dummy_events_dir, filename), self.event_logger.event_dir)

        monitor_handler.collect_and_send_events()

        # Invalid events
        self.assertEqual(0, patch_send_event.call_count)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_events_cannot_read_events(self, mock_lib_dir, patch_send_event, *args):
        mock_lib_dir.return_value = self.lib_dir
        dummy_events_dir = os.path.join(data_dir, "events", "collect_and_send_events_unreadable_data")
        fileutil.mkdir(self.event_logger.event_dir)

        test_data = WireProtocolData(DATA_FILE)
        monitor_handler, protocol = self._create_mock(test_data, *args)
        monitor_handler.init_protocols()

        for filename in os.listdir(dummy_events_dir):
            shutil.copy(os.path.join(dummy_events_dir, filename), self.event_logger.event_dir)

        def builtins_version():
            if sys.version_info[0] == 2:
                return "__builtin__"
            else:
                return "builtins"

        with patch("{0}.open".format(builtins_version())) as mock_open:
            mock_open.side_effect = IOError(13, "Permission denied")
            monitor_handler.collect_and_send_events()

            # Invalid events
            self.assertEqual(0, patch_send_event.call_count)

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_with_http_post_returning_503(self, mock_lib_dir, *args):
        mock_lib_dir.return_value = self.lib_dir
        fileutil.mkdir(self.event_logger.event_dir)

        test_data = WireProtocolData(DATA_FILE)
        monitor_handler, protocol = self._create_mock(test_data, *args)
        monitor_handler.init_protocols()

        sizes = [1, 2, 3]  # get the powers of 2, and multiple by 1024.

        for power in sizes:
            size = 2 ** power * 1024
            self.event_logger.save_event(create_dummy_event(size))

        with patch("azurelinuxagent.common.logger.error") as mock_error:
            with patch("azurelinuxagent.common.utils.restutil.http_post") as mock_http_post:
                mock_http_post.return_value = ResponseMock(
                    status=restutil.httpclient.SERVICE_UNAVAILABLE,
                    response="")
                monitor_handler.collect_and_send_events()
                self.assertEqual(1, mock_error.call_count)
                self.assertEqual("[ProtocolError] [Wireserver Exception] [ProtocolError] [Wireserver Failed] "
                                 "URI http://{0}/machine?comp=telemetrydata  [HTTP Failed] Status Code 503".format(protocol.get_endpoint()),
                                 mock_error.call_args[0][1])
                self.assertEqual(0, len(os.listdir(self.event_logger.event_dir)))

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_with_send_event_generating_exception(self, mock_lib_dir, *args):
        mock_lib_dir.return_value = self.lib_dir
        fileutil.mkdir(self.event_logger.event_dir)

        test_data = WireProtocolData(DATA_FILE)
        monitor_handler, protocol = self._create_mock(test_data, *args)
        monitor_handler.init_protocols()

        sizes = [1, 2, 3]  # get the powers of 2, and multiple by 1024.

        for power in sizes:
            size = 2 ** power * 1024
            self.event_logger.save_event(create_dummy_event(size))

        monitor_handler.last_event_collection = datetime.datetime.utcnow() - timedelta(hours=1)
        # This test validates that if we hit an issue while sending an event, we never send it again.
        with patch("azurelinuxagent.common.logger.warn") as mock_warn:
            with patch("azurelinuxagent.common.protocol.wire.WireClient.send_event") as patch_send_event:
                patch_send_event.side_effect = Exception()
                monitor_handler.collect_and_send_events()

                self.assertEqual(1, mock_warn.call_count)
                self.assertEqual(0, len(os.listdir(self.event_logger.event_dir)))

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_collect_and_send_with_call_wireserver_returns_http_error(self, mock_lib_dir, *args):
        mock_lib_dir.return_value = self.lib_dir
        fileutil.mkdir(self.event_logger.event_dir)

        test_data = WireProtocolData(DATA_FILE)
        monitor_handler, protocol = self._create_mock(test_data, *args)
        monitor_handler.init_protocols()

        sizes = [1, 2, 3]  # get the powers of 2, and multiple by 1024.

        for power in sizes:
            size = 2 ** power * 1024
            self.event_logger.save_event(create_dummy_event(size))

        monitor_handler.last_event_collection = datetime.datetime.utcnow() - timedelta(hours=1)
        with patch("azurelinuxagent.common.logger.error") as mock_error:
            with patch("azurelinuxagent.common.protocol.wire.WireClient.call_wireserver") as patch_call_wireserver:
                patch_call_wireserver.side_effect = HttpError
                monitor_handler.collect_and_send_events()

                self.assertEqual(1, mock_error.call_count)
                self.assertEqual(0, len(os.listdir(self.event_logger.event_dir)))


@patch('azurelinuxagent.common.osutil.get_osutil')
@patch('azurelinuxagent.common.protocol.util.get_protocol_util')
@patch("azurelinuxagent.common.protocol.healthservice.HealthService._report")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestExtensionMetricsDataTelemetry(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)
        event.init_event_logger(os.path.join(self.tmp_dir, "events"))
        CGroupsTelemetry.reset()
        clear_singleton_instances(ProtocolUtil)
        protocol = WireProtocol('endpoint')
        protocol.update_goal_state = MagicMock()
        self.get_protocol = patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol', return_value=protocol)
        self.get_protocol.start()

    def tearDown(self):
        AgentTestCase.tearDown(self)
        CGroupsTelemetry.reset()
        self.get_protocol.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.poll_all_tracked")
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.report_all_tracked")
    def test_send_extension_metrics_telemetry(self, patch_report_all_tracked, patch_poll_all_tracked, patch_add_event,
                                              patch_add_metric, *args):
        patch_poll_all_tracked.return_value = [MetricValue("Process", "% Processor Time", 1, 1),
                                               MetricValue("Memory", "Total Memory Usage", 1, 1),
                                               MetricValue("Memory", "Max Memory Usage", 1, 1)]

        patch_report_all_tracked.return_value = {
            "memory": {
                "cur_mem": [1, 1, 1, 1, 1, str(datetime.datetime.utcnow()), str(datetime.datetime.utcnow())],
                "max_mem": [1, 1, 1, 1, 1, str(datetime.datetime.utcnow()), str(datetime.datetime.utcnow())]
            },
            "cpu": {
                "cur_cpu": [1, 1, 1, 1, 1, str(datetime.datetime.utcnow()), str(datetime.datetime.utcnow())]
            }
        }

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        monitor_handler.send_telemetry_metrics()
        self.assertEqual(1, patch_poll_all_tracked.call_count)
        self.assertEqual(1, patch_report_all_tracked.call_count)
        self.assertEqual(1, patch_add_event.call_count)
        self.assertEqual(3, patch_add_metric.call_count)  # Three metrics being sent.
        monitor_handler.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.poll_all_tracked")
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.report_all_tracked", return_value={})
    def test_send_extension_metrics_telemetry_for_empty_cgroup(self, patch_report_all_tracked, patch_poll_all_tracked,
                                                               patch_add_event, patch_add_metric,*args):
        patch_report_all_tracked.return_value = {}
        patch_poll_all_tracked.return_value = []

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        monitor_handler.send_telemetry_metrics()
        self.assertEqual(1, patch_poll_all_tracked.call_count)
        self.assertEqual(1, patch_report_all_tracked.call_count)
        self.assertEqual(0, patch_add_event.call_count)
        self.assertEqual(0, patch_add_metric.call_count)
        monitor_handler.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage")
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_handling_memory_cgroup_exceptions_errno2(self, patch_periodic_warn,
                                                                                       patch_get_memory_usage,
                                                                                       patch_add_metric, *args):
        ioerror = IOError()
        ioerror.errno = 2
        patch_get_memory_usage.side_effect = ioerror

        CGroupsTelemetry._tracked.append(MemoryCgroup("cgroup_name", "/test/path"))

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        self.assertEqual(0, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.
        monitor_handler.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage")
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_handling_cpu_cgroup_exceptions_errno2(self, patch_periodic_warn,
                                                                                    patch_cpu_usage, patch_add_metric,
                                                                                    *args):
        ioerror = IOError()
        ioerror.errno = 2
        patch_cpu_usage.side_effect = ioerror

        CGroupsTelemetry._tracked.append(CpuCgroup("cgroup_name", "/test/path"))

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        self.assertEqual(0, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.
        monitor_handler.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch('azurelinuxagent.common.logger.Logger.periodic_warn')
    def test_send_extension_metrics_telemetry_for_unsupported_cgroup(self, patch_periodic_warn, patch_add_metric, *args):
        CGroupsTelemetry._tracked.append(CGroup("cgroup_name", "/test/path", "io"))

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        self.assertEqual(1, patch_periodic_warn.call_count)
        self.assertEqual(0, patch_add_metric.call_count)  # No metrics should be sent.

        monitor_handler.stop()

    @skip_if_predicate_true(lambda: True, "Skipping this test currently: We need two different tests - one for "
                                  "FileSystemCgroupAPI based test and one for SystemDCgroupAPI based test. @vrdmr will "
                                  "be splitting this test in subsequent PRs")
    @skip_if_predicate_false(are_cgroups_enabled, "Does not run when Cgroups are not enabled")
    @skip_if_predicate_true(is_trusty_in_travis, "Does not run on Trusty in Travis")
    @patch('azurelinuxagent.common.event.EventLogger.add_metric')
    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @attr('requires_sudo')
    def test_send_extension_metrics_telemetry_with_actual_cgroup(self, patch_add_event, patch_add_metric, *arg):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        # This test has some timing issues when systemd is managing cgroups, so we force the file system API
        # by creating a new instance of the CGroupConfigurator
        with patch("azurelinuxagent.common.cgroupapi.CGroupsApi._is_systemd", return_value=False):
            cgroup_configurator_instance = CGroupConfigurator._instance
            CGroupConfigurator._instance = None

            try:
                max_num_polls = 5
                time_to_wait = 3
                extn_name = "foobar-1.0.0"

                cgs = make_new_cgroup(extn_name)
                self.assertEqual(len(cgs), 2)

                ext_handler_properties = ExtHandlerProperties()
                ext_handler_properties.version = "1.0.0"
                ext_handler = ExtHandler(name='foobar')
                ext_handler.properties = ext_handler_properties
                ext_handler_instance = ExtHandlerInstance(ext_handler=ext_handler, protocol=None)
                ext_handler_instance.set_operation("Enable")

                monitor_handler = get_monitor_handler()
                monitor_handler.init_protocols()
                monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
                monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)

                command = self.create_script("keep_cpu_busy_and_consume_memory_for_{0}_seconds".format(time_to_wait), '''
nohup python -c "import time

for i in range(5):
    x = [1, 2, 3, 4, 5] * (i * 1000)
    time.sleep({0})
    x = [1, 2, 3, 4, 5] * (i * 1000)
    x *= 0
    print('Test loop')" &
'''.format(time_to_wait))

                self.log_dir = os.path.join(self.tmp_dir, "log")

                with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_base_dir", lambda *_: self.tmp_dir) as \
                        patch_get_base_dir:
                    with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_log_dir", lambda *_: self.log_dir) as \
                            patch_get_log_dir:
                        ext_handler_instance.launch_command(command)

                self.assertTrue(CGroupsTelemetry.is_tracked(os.path.join(
                    BASE_CGROUPS, "cpu", "walinuxagent.extensions", "foobar_1.0.0")))
                self.assertTrue(CGroupsTelemetry.is_tracked(os.path.join(
                    BASE_CGROUPS, "memory", "walinuxagent.extensions", "foobar_1.0.0")))

                for i in range(max_num_polls):
                    metrics = CGroupsTelemetry.poll_all_tracked()
                    self.assertEqual(len(metrics), 3)

                monitor_handler.poll_telemetry_metrics()
                self.assertEqual(3, patch_add_metric.call_count)

                for call_arg in patch_add_metric.call_args_list:
                    self.assertIn(call_arg[0][0], ["Process", "Memory"])
                    if call_arg[0][0] == "Process":
                        self.assertEqual(call_arg[0][1], "% Processor Time")
                    if call_arg[0][0] == "Memory":
                        self.assertIn(call_arg[0][1], ["Total Memory Usage", "Max Memory Usage"])
                    self.assertIsInstance(call_arg[0][3], float)

                    self.assertEqual(call_arg[0][2], extn_name)
                    self.assertFalse(call_arg[0][4])

                monitor_handler.send_telemetry_metrics()
                self.assertEqual(3, patch_add_event.call_count)     # 1 for launch command, 1 for extension metrics data
                                                                    # and 1 for Cgroups initialization
                name = patch_add_event.call_args[0][0]
                fields = patch_add_event.call_args[1]

                self.assertEqual(name, "WALinuxAgent")
                self.assertEqual(fields["op"], "ExtensionMetricsData")
                self.assertEqual(fields["is_success"], True)
                self.assertEqual(fields["log_event"], False)
                self.assertEqual(fields["is_internal"], False)
                self.assertIsInstance(fields["message"], ustr)
                monitor_handler.stop()
            finally:
                CGroupConfigurator._instance = cgroup_configurator_instance

    @skip_if_predicate_true(lambda: True, "Skipping this test currently: We need two different tests - one for "
                                  "FileSystemCgroupAPI based test and one for SystemDCgroupAPI based test. @vrdmr will "
                                  "be splitting this test in subsequent PRs")
    @skip_if_predicate_false(are_cgroups_enabled, "Does not run when Cgroups are not enabled")
    @skip_if_predicate_true(is_trusty_in_travis, "Does not run on Trusty in Travis")
    @patch("azurelinuxagent.common.cgroupconfigurator.get_osutil", return_value=DefaultOSUtil())
    @patch("azurelinuxagent.common.cgroupapi.CGroupsApi._is_systemd", return_value=False)
    @patch('azurelinuxagent.common.protocol.wire.WireClient.report_event')
    @attr('requires_sudo')
    def test_report_event_metrics_sent_for_actual_cgroup(self, patch_report_event, patch__is_systemd, patch_get_osutil,
                                                         http_get, patch_get_protocol, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")
        CGroupConfigurator._instance = None

        max_num_polls = 5
        time_to_wait = 1
        extn_name = "foobar-1.0.0"
        extn_folder_name = extn_name.replace("-", "_")

        cgs = make_new_cgroup(extn_name)
        self.assertEqual(len(cgs), 2)

        ext_handler_properties = ExtHandlerProperties()
        ext_handler_properties.version = "1.0.0"
        ext_handler = ExtHandler(name='foobar')
        ext_handler.properties = ext_handler_properties
        ext_handler_instance = ExtHandlerInstance(ext_handler=ext_handler, protocol=None)
        ext_handler_instance.set_operation("Enable")

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)

        command = self.create_script("keep_cpu_busy_and_consume_memory_for_{0}_seconds".format(time_to_wait), '''
nohup python -c "import time
import subprocess

for i in range(3):
    x = [1, 2, 3, 4, 5] * (i * 1000)
    time.sleep({0})
    x *= 0
    print('Test loop')

" &
'''.format(time_to_wait))

        self.log_dir = os.path.join(self.tmp_dir, "log")

        with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_base_dir", lambda *_: self.tmp_dir):
            with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_log_dir", lambda *_: self.log_dir):
                ext_handler_instance.launch_command(command)

        self.assertTrue(CGroupsTelemetry.is_tracked(os.path.join(BASE_CGROUPS, "cpu", "walinuxagent.extensions", extn_folder_name)))
        self.assertTrue(CGroupsTelemetry.is_tracked(os.path.join(BASE_CGROUPS, "memory", "walinuxagent.extensions", extn_folder_name)))

        for i in range(max_num_polls):
            metrics = CGroupsTelemetry.poll_all_tracked()
            # Currently there are 3 types of memory related metrics and 1 CPU related metric.
            # % Processor Time
            # Total Memory Usage
            # Max Memory Usage
            # Memory Used by Process - This can have multiple entries (for each process that gets created).
            self.assertEqual(len(metrics), 4)

        monitor_handler.poll_telemetry_metrics()
        monitor_handler.send_telemetry_metrics()
        monitor_handler.collect_and_send_events()

        telemetry_event_list = patch_report_event.call_args_list[0][0][0]

        for e in telemetry_event_list.events:
            print([(i.name, i.value) for i in e.parameters])
            details_of_event = [x for x in e.parameters if x.name in
                                ["Category", "Counter", "Instance", "Value"]]

            for i in details_of_event:
                if i.name == "Category":
                    self.assertIn(i.value, ["Memory", "Process"])
                if i.name == "Counter":
                    self.assertIn(i.value, ["Max Memory Usage", "Total Memory Usage", "% Processor Time",
                                            "Memory Used by Process"])
                if i.name == "Value":
                    self.assertTrue(isinstance(i.value, int) or isinstance(i.value, float))

        monitor_handler.stop()

    def test_generate_extension_metrics_telemetry_dictionary(self, *args):
        num_polls = 10
        num_extensions = 1
        num_summarization_values = 7

        cpu_percent_values = [random.randint(0, 100) for _ in range(num_polls)]

        # only verifying calculations and not validity of the values.
        memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]
        max_memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]

        # no need to initialize the CPU usage, since we mock get_cpu_usage() below
        with patch("azurelinuxagent.common.cgroup.CpuCgroup.initialize_cpu_usage"):
            for i in range(num_extensions):
                dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
                CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

                dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                    "dummy_extension_{0}".format(i))
                CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        self.assertEqual(2 * num_extensions, len(CGroupsTelemetry._tracked))

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_max_memory_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup.get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup.get_cpu_usage") as patch_get_cpu_usage:
                    with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                        for i in range(num_polls):
                            patch_is_active.return_value = True
                            patch_get_cpu_usage.return_value = cpu_percent_values[i]
                            patch_get_memory_usage.return_value = memory_usage_values[i]  # example 200 MB
                            patch_get_memory_max_usage.return_value = max_memory_usage_values[i]  # example 450 MB
                            CGroupsTelemetry.poll_all_tracked()

        performance_metrics = CGroupsTelemetry.report_all_tracked()

        message_json = generate_extension_metrics_telemetry_dictionary(schema_version=1.0,
                                                                       performance_metrics=performance_metrics)

        for i in range(num_extensions):
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_cpu_path_{0}".format(i)))
            self.assertTrue(CGroupsTelemetry.is_tracked("dummy_memory_path_{0}".format(i)))

        self.assertIn("SchemaVersion", message_json)
        self.assertIn("PerfMetrics", message_json)

        collected_metrics = message_json["PerfMetrics"]

        for i in range(num_extensions):
            extn_name = "dummy_extension_{0}".format(i)

            self.assertIn("memory", collected_metrics[extn_name])
            self.assertIn("cur_mem", collected_metrics[extn_name]["memory"])
            self.assertIn("max_mem", collected_metrics[extn_name]["memory"])
            self.assertEqual(len(collected_metrics[extn_name]["memory"]["cur_mem"]), num_summarization_values)
            self.assertEqual(len(collected_metrics[extn_name]["memory"]["max_mem"]), num_summarization_values)

            self.assertIsInstance(collected_metrics[extn_name]["memory"]["cur_mem"][5], str)
            self.assertIsInstance(collected_metrics[extn_name]["memory"]["cur_mem"][6], str)
            self.assertIsInstance(collected_metrics[extn_name]["memory"]["max_mem"][5], str)
            self.assertIsInstance(collected_metrics[extn_name]["memory"]["max_mem"][6], str)

            self.assertIn("cpu", collected_metrics[extn_name])
            self.assertIn("cur_cpu", collected_metrics[extn_name]["cpu"])
            self.assertEqual(len(collected_metrics[extn_name]["cpu"]["cur_cpu"]), num_summarization_values)

            self.assertIsInstance(collected_metrics[extn_name]["cpu"]["cur_cpu"][5], str)
            self.assertIsInstance(collected_metrics[extn_name]["cpu"]["cur_cpu"][6], str)

        message_json = generate_extension_metrics_telemetry_dictionary(schema_version=1.0,
                                                                       performance_metrics=None)
        self.assertIn("SchemaVersion", message_json)
        self.assertNotIn("PerfMetrics", message_json)

        message_json = generate_extension_metrics_telemetry_dictionary(schema_version=2.0,
                                                                       performance_metrics=None)
        self.assertEqual(message_json, None)

        message_json = generate_extension_metrics_telemetry_dictionary(schema_version="z",
                                                                       performance_metrics=None)
        self.assertEqual(message_json, None)


@patch("azurelinuxagent.common.utils.restutil.http_post")
@patch('azurelinuxagent.common.protocol.wire.WireClient.get_goal_state')
@patch('azurelinuxagent.common.event.EventLogger.add_event')
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestMonitorFailure(AgentTestCase):

    @patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_heartbeat")
    def test_error_heartbeat_creates_no_signal(self, patch_report_heartbeat, patch_http_get, patch_add_event, *args):

        monitor_handler = get_monitor_handler()
        protocol = WireProtocol('endpoint')
        protocol.update_goal_state = MagicMock()
        with patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol', return_value=protocol):
            monitor_handler.init_protocols()
            monitor_handler.last_host_plugin_heartbeat = datetime.datetime.utcnow() - timedelta(hours=1)

            patch_http_get.side_effect = IOError('client error')
            monitor_handler.send_host_plugin_heartbeat()

            # health report should not be made
            self.assertEqual(0, patch_report_heartbeat.call_count)

            # telemetry with failure details is sent
            self.assertEqual(1, patch_add_event.call_count)
            self.assertEqual('HostPluginHeartbeat', patch_add_event.call_args[1]['op'])
            self.assertTrue('client error' in patch_add_event.call_args[1]['message'])

            self.assertEqual(False, patch_add_event.call_args[1]['is_success'])
            monitor_handler.stop()
