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
from azurelinuxagent.common.protocol.healthservice import Observation, HealthService
from azurelinuxagent.common.utils import restutil
from tests.protocol.test_hostplugin import MockResponse
from tests.tools import AgentTestCase, patch


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

    def assert_telemetry(self, call_args, response=''):
        args, kw_args = call_args  # pylint: disable=unused-variable
        self.assertFalse(kw_args['is_success'])
        self.assertEqual('HealthObservation', kw_args['op'])
        obs = json.loads(kw_args['message'])
        self.assertEqual(obs['Value'], response)

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

    @patch('azurelinuxagent.common.event.add_event')
    @patch("azurelinuxagent.common.utils.restutil.http_post")
    def test_reporting(self, patch_post, patch_add_event):
        health_service = HealthService('endpoint')
        health_service.report_host_plugin_status(is_healthy=True, response='response')
        self.assertEqual(1, patch_post.call_count)
        self.assertEqual(0, patch_add_event.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_STATUS_OBSERVATION_NAME,
                                is_healthy=True,
                                value='response',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_status(is_healthy=False, response='error')
        self.assertEqual(2, patch_post.call_count)
        self.assertEqual(1, patch_add_event.call_count)
        self.assert_telemetry(call_args=patch_add_event.call_args, response='error')
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_STATUS_OBSERVATION_NAME,
                                is_healthy=False,
                                value='error',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_extension_artifact(is_healthy=True, source='source', response='response')
        self.assertEqual(3, patch_post.call_count)
        self.assertEqual(1, patch_add_event.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_ARTIFACT_OBSERVATION_NAME,
                                is_healthy=True,
                                value='response',
                                description='source')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_extension_artifact(is_healthy=False, source='source', response='response')
        self.assertEqual(4, patch_post.call_count)
        self.assertEqual(2, patch_add_event.call_count)
        self.assert_telemetry(call_args=patch_add_event.call_args, response='response')
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_ARTIFACT_OBSERVATION_NAME,
                                is_healthy=False,
                                value='response',
                                description='source')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_heartbeat(is_healthy=True)
        self.assertEqual(5, patch_post.call_count)
        self.assertEqual(2, patch_add_event.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME,
                                is_healthy=True,
                                value='',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_heartbeat(is_healthy=False)
        self.assertEqual(3, patch_add_event.call_count)
        self.assert_telemetry(call_args=patch_add_event.call_args)
        self.assertEqual(6, patch_post.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME,
                                is_healthy=False,
                                value='',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_versions(is_healthy=True, response='response')
        self.assertEqual(7, patch_post.call_count)
        self.assertEqual(3, patch_add_event.call_count)
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_VERSIONS_OBSERVATION_NAME,
                                is_healthy=True,
                                value='response',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        health_service.report_host_plugin_versions(is_healthy=False, response='response')
        self.assertEqual(8, patch_post.call_count)
        self.assertEqual(4, patch_add_event.call_count)
        self.assert_telemetry(call_args=patch_add_event.call_args, response='response')
        self.assert_observation(call_args=patch_post.call_args,
                                name=HealthService.HOST_PLUGIN_VERSIONS_OBSERVATION_NAME,
                                is_healthy=False,
                                value='response',
                                description='')
        self.assertEqual(0, len(health_service.observations))

        patch_post.side_effect = HttpError()
        health_service.report_host_plugin_versions(is_healthy=True, response='')

        self.assertEqual(9, patch_post.call_count)
        self.assertEqual(4, patch_add_event.call_count)
        self.assertEqual(0, len(health_service.observations))

    def test_observation_length(self):
        health_service = HealthService('endpoint')

        # make 100 observations
        for i in range(0, 100):
            health_service._observe(is_healthy=True, name='{0}'.format(i))  # pylint: disable=protected-access

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
