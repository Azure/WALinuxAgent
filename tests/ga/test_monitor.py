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

from tests.tools import *
from azurelinuxagent.ga.monitor import *

class TestMonitor(AgentTestCase):
    def test_parse_xml_event(self):
        data_str = load_data('ext/event.xml')
        event = parse_xml_event(data_str)
        self.assertNotEquals(None, event)
        self.assertNotEquals(0, event.parameters)
        self.assertNotEquals(None, event.parameters[0])

    @patch('azurelinuxagent.common.osutil.get_osutil')
    @patch('azurelinuxagent.common.protocol.get_protocol_util')
    def test_add_sysinfo(self, _, __):
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

        self.assertNotEquals(None, event)
        self.assertNotEquals(0, event.parameters)
        self.assertNotEquals(None, event.parameters[0])
        counter = 0
        for p in event.parameters:
            if p.name == vm_name_param:
                self.assertEquals(vm_name, p.value)
                counter += 1
            elif p.name == tenant_name_param:
                self.assertEquals(tenant_name, p.value)
                counter += 1
            elif p.name == role_name_param:
                self.assertEquals(role_name, p.value)
                counter += 1
            elif p.name == role_instance_name_param:
                self.assertEquals(role_instance_name, p.value)
                counter += 1
            elif p.name == container_id_param:
                self.assertEquals(container_id, p.value)
                counter += 1

        self.assertEquals(5, counter)
