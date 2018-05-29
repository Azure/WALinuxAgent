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
    def __init__(self, name, is_healthy, description, value):
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
    HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME = 'HostPluginHeartbeat'

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

    def observe_host_plugin_heartbeat(self, is_healthy):
        self.observations.append(Observation(name=HealthService.HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME,
                                             is_healthy=is_healthy,
                                             description='',
                                             value=''))

    def report(self):
        logger.verbose('HealthService: report observations')
        try:
            # TODO: remove
            logger.info('Report observation to {0}: {1}', self.endpoint, self.as_json)

            restutil.http_post(self.endpoint, self.as_json)
            del self.observations[:]
        except HttpError as e:
            logger.warn("HealthService could not report observations: {0}", ustr(e))
