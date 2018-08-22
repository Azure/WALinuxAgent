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
import json

from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.protocol.healthservice import Observation, HealthService, ExtensionHealthObserver
from azurelinuxagent.common.utils import restutil
from azurelinuxagent.common.protocol.restapi import ExtHandlerStatus, \
                                                    ExtensionStatus, \
                                                    ExtensionSubStatus
from tests.protocol.test_hostplugin import MockResponse
from tests.tools import *


class TestHealthService(AgentTestCase):

    def assert_status_code(self, status_code, expected_healthy):
        response = MockResponse('response', status_code)
        is_healthy = not restutil.request_failed_at_hostplugin(response)
        self.assertEqual(expected_healthy, is_healthy)

    def assert_observation(self, call_args, name, is_healthy, value, description):
        endpoint = call_args[0][0]
        content = call_args[0][1]

        jo = json.loads(content)
        api = jo['Api']
        source = jo['Source']
        version = jo['Version']
        obs = jo['Observations']
        fo = obs[0]
        obs_name = fo['ObservationName']
        obs_healthy = fo['IsHealthy']
        obs_value = fo['Value']
        obs_description = fo['Description']

        self.assertEqual('application/json', call_args[1]['headers']['Content-Type'])
        self.assertEqual('http://endpoint:80/HealthService', endpoint)
        self.assertEqual('reporttargethealth', api)
        self.assertEqual('WALinuxAgent', source)
        self.assertEqual('1.0', version)

        self.assertEqual(name, obs_name)
        self.assertEqual(value, obs_value)
        self.assertEqual(is_healthy, obs_healthy)
        self.assertEqual(description, obs_description)

    def test_observation_validity(self):
        try:
            Observation(name=None, is_healthy=True)
            self.fail('Empty observation name should raise ValueError')
        except ValueError:
            pass

        try:
            Observation(name='Name', is_healthy=None)
            self.fail('Empty measurement should raise ValueError')
        except ValueError:
            pass

        o = Observation(name='Name', is_healthy=True, value=None, description=None)
        self.assertEqual('', o.value)
        self.assertEqual('', o.description)

        long_str = 's' * 200
        o = Observation(name=long_str, is_healthy=True, value=long_str, description=long_str)
        self.assertEqual(200, len(o.name))
        self.assertEqual(200, len(o.value))
        self.assertEqual(200, len(o.description))

        self.assertEqual(64, len(o.as_obj['ObservationName']))
        self.assertEqual(128, len(o.as_obj['Value']))
        self.assertEqual(128, len(o.as_obj['Description']))

    def test_observation_json(self):
        health_service = HealthService('endpoint')
        health_service.observations.append(Observation(name='name',
                                                       is_healthy=True,
                                                       value='value',
                                                       description='description'))
        expected_json = '{"Source": "WALinuxAgent", ' \
                         '"Api": "reporttargethealth", ' \
                         '"Version": "1.0", ' \
                         '"Observations": [{' \
                            '"Value": "value", ' \
                            '"ObservationName": "name", ' \
                            '"Description": "description", ' \
                            '"IsHealthy": true' \
                        '}]}'
        expected = sorted(json.loads(expected_json).items())
        actual = sorted(json.loads(health_service.as_json).items())
        self.assertEqual(expected, actual)

    @patch("azurelinuxagent.common.utils.restutil.http_post")
    def test_reporting(self, patch_post):
        health_service = HealthService('endpoint')
        health_service.report_host_plugin_status(is_healthy=True, response='response')
        self.assertEqual(1, patch_post.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_STATUS_OBSERVATION_NAME,
                                is_healthy=True,
                                value='response',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_status(is_healthy=False, response='error')
        self.assertEqual(2, patch_post.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_STATUS_OBSERVATION_NAME,
                                is_healthy=False,
                                value='error',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_extension_artifact(is_healthy=True, source='source', response='response')
        self.assertEqual(3, patch_post.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_ARTIFACT_OBSERVATION_NAME,
                                is_healthy=True,
                                value='response',
                                description='source')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_extension_artifact(is_healthy=False, source='source', response='response')
        self.assertEqual(4, patch_post.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_ARTIFACT_OBSERVATION_NAME,
                                is_healthy=False,
                                value='response',
                                description='source')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_heartbeat(is_healthy=True)
        self.assertEqual(5, patch_post.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME,
                                is_healthy=True,
                                value='',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_heartbeat(is_healthy=False)
        self.assertEqual(6, patch_post.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME,
                                is_healthy=False,
                                value='',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_versions(is_healthy=True, response='response')
        self.assertEqual(7, patch_post.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_VERSIONS_OBSERVATION_NAME,
                                is_healthy=True,
                                value='response',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_versions(is_healthy=False, response='response')
        self.assertEqual(8, patch_post.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_VERSIONS_OBSERVATION_NAME,
                                is_healthy=False,
                                value='response',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        patch_post.side_effect = HttpError()
        health_service.report_host_plugin_versions(is_healthy=True, response='')

        self.assertEqual(9, patch_post.call_count)
        self.assertEqual(0, len(health_service.observations))

    def test_observation_length(self):
        health_service = HealthService('endpoint')

        # make 100 observations
        for i in range(0, 100):
            health_service._observe(is_healthy=True, name='{0}'.format(i))

        # ensure we keep only 10
        self.assertEqual(10, len(health_service.observations))

        # ensure we keep the most recent 10
        self.assertEqual('90', health_service.observations[0].name)
        self.assertEqual('99', health_service.observations[9].name)

    def test_status_codes(self):
        # healthy
        self.assert_status_code(status_code=200, expected_healthy=True)
        self.assert_status_code(status_code=201, expected_healthy=True)
        self.assert_status_code(status_code=302, expected_healthy=True)
        self.assert_status_code(status_code=400, expected_healthy=True)
        self.assert_status_code(status_code=416, expected_healthy=True)
        self.assert_status_code(status_code=419, expected_healthy=True)
        self.assert_status_code(status_code=429, expected_healthy=True)
        self.assert_status_code(status_code=502, expected_healthy=True)

        # unhealthy
        self.assert_status_code(status_code=500, expected_healthy=False)
        self.assert_status_code(status_code=501, expected_healthy=False)
        self.assert_status_code(status_code=503, expected_healthy=False)
        self.assert_status_code(status_code=504, expected_healthy=False)


class TestExtensionHealthObserver(AgentTestCase):
    def test_report_vm_status(self):
        healthObserver = ExtensionHealthObserver()
        self.assertEqual(0, len(healthObserver.static_observations))
        self.assertEqual(0, len(healthObserver.partial_observations))
        self.assertEqual(0, len(healthObserver.latest_observations))

        vm_agent = Mock(version="1.0")
        vm_status = Mock(vm_agent=vm_agent)
        healthObserver.report_vm_status(vm_status)

        self.assertEqual(0, len(healthObserver.static_observations))
        self.assertEqual(0, len(healthObserver.partial_observations))
        self.assertEqual(2, len(healthObserver.latest_observations))

        self.assertEqual(ExtensionHealthObserver.AGENT_OBSERVATION_NAME, healthObserver.latest_observations[0].name)
        self.assertEqual(True, healthObserver.latest_observations[0].is_healthy)
        self.assertEqual(ExtensionHealthObserver.AGENT_OBSERVATION_VALUE, healthObserver.latest_observations[0].value)
        
        self.assertEqual(ExtensionHealthObserver.CONTEXT_OBSERVATION + ExtensionHealthObserver.AGENT_OBSERVATION_NAME, healthObserver.latest_observations[1].name)
        self.assertEqual(True, healthObserver.latest_observations[1].is_healthy)
        self.assertEqual(vm_status.vmAgent.version, healthObserver.latest_observations[1].value)

        self.assertEqual(2, len(healthObserver.get_observations()))

        healthObserver.static_observations.append(1)
        self.assertEqual(3, len(healthObserver.get_observations()))

        # validate that the partial observations are moved to commited after calling report_vm_status
        healthObserver.partial_observations.append(2)
        healthObserver.report_vm_status(vm_status)

        self.assertEqual(0, len(healthObserver.partial_observations))
        self.assertEqual(3, len(healthObserver.latest_observations))
        self.assertEqual(4, len(healthObserver.get_observations()))

    def test_add_extension_observation(self):
        handler_status = ExtHandlerStatus()
        handler_status.name = "Name"
        handler_status.version = "1.0"
        handler_status.code = 0
        handler_status.status = "Unresponsive"

        healthObserver = ExtensionHealthObserver()
        healthObserver.add_extension_observation(handler_status, [])
        
        # validate that 2 observations were made - one for the handler version, and one for the handler being in a failed state
        self.assertEqual(2, len(healthObserver.partial_observations))
        self.assertEqual(ExtensionHealthObserver.CONTEXT_OBSERVATION + handler_status.name, healthObserver.partial_observations[0].name)
        self.assertEqual(handler_status.version, healthObserver.partial_observations[0].value)
        self.assertEqual(True, healthObserver.partial_observations[0].is_healthy)

        # unhealthy handler
        self.assertEqual(handler_status.name, healthObserver.partial_observations[1].name)
        self.assertEqual(False, healthObserver.partial_observations[1].is_healthy)
        
        handler_status.status = "Ready"
        healthObserver = ExtensionHealthObserver()
        healthObserver.add_extension_observation(handler_status, [])
        
        # validate that 2 observations were made - one for the handler version, and one for the handler being in a failed state
        self.assertEqual(2, len(healthObserver.partial_observations))
        self.assertEqual(ExtensionHealthObserver.CONTEXT_OBSERVATION + handler_status.name, healthObserver.partial_observations[0].name)
        self.assertEqual(handler_status.version, healthObserver.partial_observations[0].value)
        self.assertEqual(True, healthObserver.partial_observations[0].is_healthy)

        # healthy handler
        self.assertEqual(handler_status.name, healthObserver.partial_observations[1].name)
        self.assertEqual(True, healthObserver.partial_observations[1].is_healthy)

        # add in an extension status
        ext_status = ExtensionStatus(seq_no=0)
        ext_status.status = "Error"
        ext_status.code = 0

        healthObserver = ExtensionHealthObserver()
        healthObserver.add_extension_observation(handler_status, [ext_status])

        # validate that 3 observations were made - one for the handler version, and one for the handler being in a success state, and one for
        # the extension
        self.assertEqual(3, len(healthObserver.partial_observations))

        # unhealthy extension
        self.assertEqual(handler_status.name + ExtensionHealthObserver.STATUS_SUFFIX, healthObserver.partial_observations[2].name)
        self.assertEqual(False, healthObserver.partial_observations[2].is_healthy)
        
        ext_status.status = "Succeeded"
        healthObserver = ExtensionHealthObserver()
        healthObserver.add_extension_observation(handler_status, [ext_status])

        # validate that 3 observations were made - one for the handler version, and one for the handler being in a success state, and one for
        # the extension
        self.assertEqual(3, len(healthObserver.partial_observations))

        # healthy extension
        self.assertEqual(handler_status.name + ExtensionHealthObserver.STATUS_SUFFIX, healthObserver.partial_observations[2].name)
        self.assertEqual(True, healthObserver.partial_observations[2].is_healthy)

        substatus = ExtensionSubStatus()
        substatus.code = 0
        substatus.status = "Error"
        ext_status.substatusList.append(substatus)

        healthObserver = ExtensionHealthObserver()
        healthObserver.add_extension_observation(handler_status, [ext_status])

        # validate that 4 observations were made - one for the handler version, and one for the handler being in a success state, and one for
        # the extension
        self.assertEqual(4, len(healthObserver.partial_observations))

        # unhealthy extension substatus
        self.assertEqual(handler_status.name + ExtensionHealthObserver.SUBSTATUS_SUFFIX, healthObserver.partial_observations[3].name)
        self.assertEqual(False, healthObserver.partial_observations[3].is_healthy)

        substatus.status = "Succeeded"
        ext_status.substatusList.append(substatus)
        
        healthObserver = ExtensionHealthObserver()
        healthObserver.add_extension_observation(handler_status, [ext_status])

        # validate that 4 observations were made - one for the handler version, and one for the handler being in a success state, and one for
        # the extension
        self.assertEqual(4, len(healthObserver.partial_observations))

        # unhealthy extension substatus
        self.assertEqual(handler_status.name + ExtensionHealthObserver.SUBSTATUS_SUFFIX, healthObserver.partial_observations[3].name)
        self.assertEqual(True, healthObserver.partial_observations[3].is_healthy)


        





        
