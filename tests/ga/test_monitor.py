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
from datetime import timedelta

from tests.tools import *
from azurelinuxagent.ga.monitor import *


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
    @patch("azurelinuxagent.ga.monitor.MonitorHandler.send_cgroup_telemetry")
    @patch("azurelinuxagent.ga.monitor.MonitorHandler.send_imds_heartbeat")
    def test_heartbeats(self,
                        patch_imds_heartbeat,
                        patch_cgroup_telemetry,
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
        self.assertEqual(0, patch_cgroup_telemetry.call_count)

        monitor_handler.start()
        time.sleep(1)
        self.assertTrue(monitor_handler.is_alive())

        self.assertNotEqual(0, patch_hostplugin_heartbeat.call_count)
        self.assertNotEqual(0, patch_send_events.call_count)
        self.assertNotEqual(0, patch_telemetry_heartbeat.call_count)
        self.assertNotEqual(0, patch_imds_heartbeat.call_count)
        self.assertNotEqual(0, patch_cgroup_telemetry.call_count)

        monitor_handler.stop()

    @patch("azurelinuxagent.ga.monitor.MonitorHandler.send_cgroup_telemetry")
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

    @patch("azurelinuxagent.ga.monitor.MonitorHandler.send_cgroup_telemetry")
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
        monitor_handler.stop()
