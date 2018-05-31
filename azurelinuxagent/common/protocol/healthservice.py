# Microsoft Azure Linux Agent
#
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

import json

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import restutil


class Observation(object):
    def __init__(self, name, is_healthy, description='', value=''):
        self.name = name
        self.is_healthy = is_healthy
        self.description = description
        self.value = value

    @property
    def as_obj(self):
        return {
            "ObservationName": self.name,
            "IsHealthy": self.is_healthy,
            "Description": self.description,
            "Value": self.value
        }


class HealthService(object):

    ENDPOINT = 'http://{0}:80/HealthService'
    API = 'reporttargethealth'
    VERSION = "1.0"
    OBSERVER_NAME = 'WALinuxAgent'
    HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME = 'GuestAgentPluginHeartbeat'
    HOST_PLUGIN_STATUS_OBSERVATION_NAME = 'GuestAgentPluginStatus'
    HOST_PLUGIN_VERSIONS_OBSERVATION_NAME = 'GuestAgentPluginVersions'
    HOST_PLUGIN_ARTIFACT_OBSERVATION_NAME = 'GuestAgentPluginArtifact'

    def __init__(self, endpoint):
        self.endpoint = HealthService.ENDPOINT.format(endpoint)
        self.api = HealthService.API
        self.version = HealthService.VERSION
        self.source = HealthService.OBSERVER_NAME
        self.observations = list()

    @property
    def as_json(self):
        data = {
            "Api": self.api,
            "Version": self.version,
            "Source": self.source,
            "Observations": [o.as_obj for o in self.observations]
        }
        return json.dumps(data)

    def report_host_plugin_heartbeat(self, is_healthy):
        """
        Reports a signal for /health
        :param is_healthy: whether the call succeeded
        """
        self.observations.append(Observation(name=HealthService.HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME,
                                             is_healthy=is_healthy))
        self.report()

    def report_host_plugin_versions(self, is_healthy, response):
        """
        Reports a signal for /versions
        :param is_healthy: whether the api call succeeded
        :param response: debugging information for failures
        """
        self.observations.append(Observation(name=HealthService.HOST_PLUGIN_VERSIONS_OBSERVATION_NAME,
                                             is_healthy=is_healthy,
                                             value=response))
        self.report()

    def report_host_plugin_extension_artifact(self, is_healthy, source, response):
        """
        Reports a signal for /extensionArtifact
        :param is_healthy: whether the api call succeeded
        :param source: specifies the api caller for debugging failures
        :param response: debugging information for failures
        :return:
        """
        self.observations.append(Observation(name=HealthService.HOST_PLUGIN_ARTIFACT_OBSERVATION_NAME,
                                             is_healthy=is_healthy,
                                             description=source,
                                             value=response))
        self.report()

    def report_host_plugin_status(self, is_healthy, response):
        """
        Reports a signal for /status
        :param is_healthy: whether the api call succeeded
        :param response: debugging information for failures
        :return:
        """
        self.observations.append(Observation(name=HealthService.HOST_PLUGIN_STATUS_OBSERVATION_NAME,
                                             is_healthy=is_healthy,
                                             value=response))
        self.report()

    def report(self):
        logger.verbose('HealthService: report observations')
        try:
            restutil.http_post(self.endpoint, self.as_json, headers={'Content-Type': 'application/json'})
            logger.verbose('HealthService: Reported observations to {0}: {1}', self.endpoint, self.as_json)
        except HttpError as e:
            logger.warn("HealthService: could not report observations: {0}", ustr(e))

        # these signals are not timestamped, so there is no value in persisting data
        del self.observations[:]
