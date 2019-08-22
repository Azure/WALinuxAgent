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
import random
import string
from datetime import timedelta

from azurelinuxagent.common.cgroup import CGroup
from azurelinuxagent.common.event import EventLogger
from azurelinuxagent.common.protocol.restapi import get_properties
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.utils import restutil
from azurelinuxagent.ga.monitor import *
from nose.plugins.attrib import attr
from tests.common.test_cgroupstelemetry import make_new_cgroup, consume_cpu_time, consume_memory
from tests.protocol.mockwiredata import WireProtocolData, DATA_FILE
from tests.tools import *


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


def create_event_message(size,
                         name="DummyExtension",
                         op=WALAEventOperation.Unknown,
                         is_success=True,
                         duration=0,
                         version=CURRENT_VERSION,
                         is_internal=False,
                         evt_type="",
                         invalid_chars=False):
    return get_event_message(name=size, op=op, is_success=is_success, duration=duration,
                             version=version, message=random_generator(size), evt_type=evt_type,
                             is_internal=is_internal)


def get_event_message(duration, evt_type, is_internal, is_success, message, name, op, version, eventId=1):
    event = TelemetryEvent(eventId, "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
    event.parameters.append(TelemetryEventParam('Name', name))
    event.parameters.append(TelemetryEventParam('Version', str(version)))
    event.parameters.append(TelemetryEventParam('IsInternal', is_internal))
    event.parameters.append(TelemetryEventParam('Operation', op))
    event.parameters.append(TelemetryEventParam('OperationSuccess', is_success))
    event.parameters.append(TelemetryEventParam('Message', message))
    event.parameters.append(TelemetryEventParam('Duration', duration))
    event.parameters.append(TelemetryEventParam('ExtensionType', evt_type))

    data = get_properties(event)
    return json.dumps(data)


@patch('azurelinuxagent.common.event.EventLogger.add_event')
@patch('azurelinuxagent.common.osutil.get_osutil')
@patch('azurelinuxagent.common.protocol.get_protocol_util')
@patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol')
@patch("azurelinuxagent.common.protocol.healthservice.HealthService._report")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestMonitor(AgentTestCase):
    def test_parse_xml_event(self, *args):
        data_str = load_data('ext/event.xml')
        event = parse_xml_event(data_str)
        self.assertNotEqual(None, event)
        self.assertNotEqual(0, event.parameters)
        self.assertNotEqual(None, event.parameters[0])

    def test_add_sysinfo(self, *args):
        data_str = load_data('ext/event.xml')
        event = parse_xml_event(data_str)
        monitor_handler = get_monitor_handler()

        vm_name = 'dummy_vm'
        tenant_name = 'dummy_tenant'
        role_name = 'dummy_role'
        role_instance_name = 'dummy_role_instance'
        container_id = 'dummy_container_id'

        vm_name_param = "VMName"
        tenant_name_param = "TenantName"
        role_name_param = "RoleName"
        role_instance_name_param = "RoleInstanceName"
        container_id_param = "ContainerId"

        sysinfo = [TelemetryEventParam(vm_name_param, vm_name),
                   TelemetryEventParam(tenant_name_param, tenant_name),
                   TelemetryEventParam(role_name_param, role_name),
                   TelemetryEventParam(role_instance_name_param, role_instance_name),
                   TelemetryEventParam(container_id_param, container_id)]
        monitor_handler.sysinfo = sysinfo
        monitor_handler.add_sysinfo(event)

        self.assertNotEqual(None, event)
        self.assertNotEqual(0, event.parameters)
        self.assertNotEqual(None, event.parameters[0])
        counter = 0
        for p in event.parameters:
            if p.name == vm_name_param:
                self.assertEqual(vm_name, p.value)
                counter += 1
            elif p.name == tenant_name_param:
                self.assertEqual(tenant_name, p.value)
                counter += 1
            elif p.name == role_name_param:
                self.assertEqual(role_name, p.value)
                counter += 1
            elif p.name == role_instance_name_param:
                self.assertEqual(role_instance_name, p.value)
                counter += 1
            elif p.name == container_id_param:
                self.assertEqual(container_id, p.value)
                counter += 1

        self.assertEqual(5, counter)

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


@patch('azurelinuxagent.common.event.EventLogger.add_event')
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

    def tearDown(self):
        fileutil.rm_dirs(self.lib_dir)

    def _create_mock(self, test_data, mock_http_get, MockCryptUtil, *args):
        """Test enable/disable/uninstall of an extension"""
        monitor_handler = get_monitor_handler()

        # Mock protocol to return test data
        mock_http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol("foo.bar")
        protocol.detect()
        protocol.report_ext_status = MagicMock()
        protocol.report_vm_status = MagicMock()

        monitor_handler.protocol_util.get_protocol = Mock(return_value=protocol)
        return monitor_handler, protocol

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
            self.event_logger.save_event(create_event_message(size))
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
            self.event_logger.save_event(create_event_message(size))

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
            mock_open.side_effect = OSError(13, "Permission denied")
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
            self.event_logger.save_event(create_event_message(size))

        with patch("azurelinuxagent.common.logger.error") as mock_error:
            with patch("azurelinuxagent.common.utils.restutil.http_post") as mock_http_post:
                mock_http_post.return_value = ResponseMock(
                    status=restutil.httpclient.SERVICE_UNAVAILABLE,
                    response="")
                monitor_handler.collect_and_send_events()
                self.assertEqual(1, mock_error.call_count)
                self.assertEqual("[ProtocolError] [Wireserver Exception] [ProtocolError] [Wireserver Failed] "
                                 "URI http://foo.bar/machine?comp=telemetrydata  [HTTP Failed] Status Code 503",
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
            self.event_logger.save_event(create_event_message(size))

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
            self.event_logger.save_event(create_event_message(size))

        monitor_handler.last_event_collection = datetime.datetime.utcnow() - timedelta(hours=1)
        with patch("azurelinuxagent.common.logger.error") as mock_error:
            with patch("azurelinuxagent.common.protocol.wire.WireClient.call_wireserver") as patch_call_wireserver:
                patch_call_wireserver.side_effect = HttpError
                monitor_handler.collect_and_send_events()

                self.assertEqual(1, mock_error.call_count)
                self.assertEqual(0, len(os.listdir(self.event_logger.event_dir)))


@patch('azurelinuxagent.common.osutil.get_osutil')
@patch('azurelinuxagent.common.protocol.get_protocol_util')
@patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol')
@patch("azurelinuxagent.common.protocol.healthservice.HealthService._report")
@patch("azurelinuxagent.common.utils.restutil.http_get")
class TestExtensionMetricsDataTelemetry(AgentTestCase):

    def setUp(self):
        AgentTestCase.setUp(self)
        CGroupsTelemetry.cleanup()

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.poll_all_tracked")
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.report_all_tracked")
    def test_send_extension_metrics_telemetry(self, patch_report_all_tracked, patch_poll_all_tracked, patch_add_event,
                                              *args):
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
        monitor_handler.stop()

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.poll_all_tracked")
    @patch("azurelinuxagent.common.cgroupstelemetry.CGroupsTelemetry.report_all_tracked", return_value={})
    def test_send_extension_metrics_telemetry_for_empty_cgroup(self, patch_report_all_tracked, patch_poll_all_tracked,
                                                               patch_add_event, *args):
        patch_report_all_tracked.return_value = {}

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        monitor_handler.send_telemetry_metrics()
        self.assertEqual(1, patch_poll_all_tracked.call_count)
        self.assertEqual(1, patch_report_all_tracked.call_count)
        self.assertEqual(0, patch_add_event.call_count)
        monitor_handler.stop()

    @skip_if_predicate_false(are_cgroups_enabled, "Does not run when Cgroups are not enabled")
    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @attr('requires_sudo')
    def test_send_extension_metrics_telemetry_with_actual_cgroup(self, patch_add_event, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        num_polls = 5
        name = "test-cgroup"

        cgs = make_new_cgroup(name)

        self.assertEqual(len(cgs), 2)

        for cgroup in cgs:
            CGroupsTelemetry.track_cgroup(cgroup)

        for i in range(num_polls):
            CGroupsTelemetry.poll_all_tracked()
            consume_cpu_time()  # Eat some CPU
            consume_memory()

        monitor_handler = get_monitor_handler()
        monitor_handler.init_protocols()
        monitor_handler.last_cgroup_polling_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.last_cgroup_report_telemetry = datetime.datetime.utcnow() - timedelta(hours=1)
        monitor_handler.poll_telemetry_metrics()
        monitor_handler.send_telemetry_metrics()
        self.assertEqual(1, patch_add_event.call_count)

        name = patch_add_event.call_args[0][0]
        fields = patch_add_event.call_args[1]

        self.assertEqual(name, "WALinuxAgent")
        self.assertEqual(fields["op"], "ExtensionMetricsData")
        self.assertEqual(fields["is_success"], True)
        self.assertEqual(fields["log_event"], False)
        self.assertEqual(fields["is_internal"], False)
        self.assertIsInstance(fields["message"], ustr)

        monitor_handler.stop()

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil._get_proc_stat")
    def test_generate_extension_metrics_telemetry_dictionary(self, *args):
        num_polls = 10
        num_extensions = 1
        num_summarization_values = 7

        cpu_percent_values = [random.randint(0, 100) for _ in range(num_polls)]

        # only verifying calculations and not validity of the values.
        memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]
        max_memory_usage_values = [random.randint(0, 8 * 1024 ** 3) for _ in range(num_polls)]

        for i in range(num_extensions):
            dummy_cpu_cgroup = CGroup.create("dummy_cpu_path_{0}".format(i), "cpu", "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_cpu_cgroup)

            dummy_memory_cgroup = CGroup.create("dummy_memory_path_{0}".format(i), "memory",
                                                "dummy_extension_{0}".format(i))
            CGroupsTelemetry.track_cgroup(dummy_memory_cgroup)

        self.assertEqual(2 * num_extensions, len(CGroupsTelemetry._tracked))

        with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_max_usage") as patch_get_memory_max_usage:
            with patch("azurelinuxagent.common.cgroup.MemoryCgroup._get_memory_usage") as patch_get_memory_usage:
                with patch("azurelinuxagent.common.cgroup.CpuCgroup._get_cpu_percent") as patch_get_cpu_percent:
                    with patch("azurelinuxagent.common.cgroup.CpuCgroup._update_cpu_data") as patch_update_cpu_data:
                        with patch("azurelinuxagent.common.cgroup.CGroup.is_active") as patch_is_active:
                            for i in range(num_polls):
                                patch_is_active.return_value = True
                                patch_get_cpu_percent.return_value = cpu_percent_values[i]
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


@patch('azurelinuxagent.common.event.EventLogger.add_event')
@patch("azurelinuxagent.common.utils.restutil.http_post")
@patch("azurelinuxagent.common.utils.restutil.http_get")
@patch('azurelinuxagent.common.protocol.wire.WireClient.get_goal_state')
@patch('azurelinuxagent.common.protocol.util.ProtocolUtil.get_protocol', return_value=WireProtocol('endpoint'))
class TestMonitorFailure(AgentTestCase):

    @patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_heartbeat")
    def test_error_heartbeat_creates_no_signal(self, patch_report_heartbeat, *args):
        patch_http_get = args[2]
        patch_add_event = args[4]

        monitor_handler = get_monitor_handler()
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
