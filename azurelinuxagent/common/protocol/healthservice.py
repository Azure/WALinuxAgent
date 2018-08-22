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


class ExtensionHealthObserver(object):
    CONTEXT_OBSERVATION = '[Context]'

    AGENT_OBSERVATION_NAME = "WAAgent"
    AGENT_OBSERVATION_VALUE = "Running"
    HANDLER_UNRESPONSIVE_VALUE = 'Extension handler is unresponsive'
    HANDLER_FAILURE_VALUE = 'Extension handler is in a failed state'
    HANDLER_HEALTHY_VALUE = 'Extension handler is in a healthy state'
    EXTENSION_HEALTHY_VALUE = 'Extension is in a healthy state'
    EXTENSION_ERROR_VALUE = 'Extension is in a failed state'
    EXTENSION_WARNING_VALUE = 'Extension is in a warning state'
    HANDLER_FAILURE_DESCRIPTION = 'Failure code: '
    STATUS_SUFFIX = '_Cfg'
    SUBSTATUS_SUFFIX = '_Substatus'
    SUBSTATUS_HEALTHY_VALUE = 'Substatus is in a healthy state'
    SUBSTATUS_UNHEALTHY_VALUE = 'Substatus is in an unhealthy state'

    def __init__(self):
        # list of observations that shouldn't change over the lifetime of the process
        # e.g., OS, tenant, VMName
        self.static_observations = list()
        self.partial_observations = list()
        self.latest_observations = list()

    def add_extension_observation(self, handler_status, exts_status):
        """
        Adds observations for each extension:
           - Extension considered unhealthy if it is:
             - notready status and code is !PluginSuccess -or-
             - handler status is unresponsive -or-
             - runtime settings exist and they have a error/warning status
         - An observation for each extension that includes a substatus:
             - The set of substatuses will be aggregated into a single observation
         - An observation for the version of the extension

        Should be followed up by a call to report_vm_status to upload the observations
        """
        name = handler_status.name
        value = ExtensionHealthObserver.HANDLER_HEALTHY_VALUE
        description = ExtensionHealthObserver.HANDLER_HEALTHY_VALUE
        version = handler_status.version
        isHealthy = True
        statusObservation = None
        substatusObservation = None

        # check that the extension handler is healthy
        if (handler_status.status == "NotReady") and (handler_status.code != 0):
            isHealthy = False
            value = ExtensionHealthObserver.HANDLER_FAILURE_VALUE
            description = ExtensionHealthObserver.HANDLER_FAILURE_DESCRIPTION + str(handler_status.code)
        elif handler_status.status == "Unresponsive":
            isHealthy = False
            value = ExtensionHealthObserver.HANDLER_UNRESPONSIVE_VALUE
            description = ExtensionHealthObserver.HANDLER_UNRESPONSIVE_VALUE
        else:
            # check the state of each extension associated with the handler
            for ext_status in exts_status:
                if statusObservation is None:
                    statusObservation = Observation(
                        name=handler_status.name + ExtensionHealthObserver.STATUS_SUFFIX,
                        is_healthy=True,
                        value=ExtensionHealthObserver.EXTENSION_HEALTHY_VALUE)

                if ext_status.status == "Error":
                    statusObservation.is_healthy = False
                    statusObservation.value = ExtensionHealthObserver.EXTENSION_ERROR_VALUE
                    statusObservation.description = ExtensionHealthObserver.HANDLER_FAILURE_DESCRIPTION + str(ext_status.code)
                elif ext_status.status == "Warning":
                    statusObservation.is_healthy = False
                    statusObservation.value = ExtensionHealthObserver.EXTENSION_WARNING_VALUE
                    statusObservation.description = ExtensionHealthObserver.HANDLER_FAILURE_DESCRIPTION + str(ext_status.code)
                
                # if a list of substatuses are present, aggregate them into a single observation
                if ext_status.substatusList is not None and len(ext_status.substatusList) != 0:
                    if not substatusObservation:
                        substatusObservation = Observation(
                            name=handler_status.name + ExtensionHealthObserver.SUBSTATUS_SUFFIX,
                            is_healthy=True,
                            value=ExtensionHealthObserver.SUBSTATUS_HEALTHY_VALUE)
                    
                    for substatus in ext_status.substatusList:
                        if substatus is not None:
                            if (substatus.status == "Error") or (substatus.status == "Warning"):
                                substatusObservation.is_healthy = False
                                substatusObservation.value = ExtensionHealthObserver.SUBSTATUS_UNHEALTHY_VALUE
                                substatusObservation.description = ExtensionHealthObserver.HANDLER_FAILURE_DESCRIPTION + str(ext_status.code)
        
        self._observe(name=ExtensionHealthObserver.CONTEXT_OBSERVATION + name,
                      is_healthy=True,
                      description=ExtensionHealthObserver.CONTEXT_OBSERVATION,
                      value=version)

        self._observe(name=name,
                      is_healthy=isHealthy,
                      value=value,
                      description=description)
        
        if statusObservation is not None:
            self._observe(name=statusObservation.name,
                          is_healthy=statusObservation.is_healthy,
                          value=statusObservation.value,
                          description=statusObservation.description)

        if substatusObservation is not None:
            self._observe(name=substatusObservation.name,
                          is_healthy=substatusObservation.is_healthy,
                          value=substatusObservation.value,
                          description=substatusObservation.description)

    def report_vm_status(self, vm_status):
        """
        Commits all of the extension related observations that have been found
        since the last call to report_vm_status and adds observations for the vm agent.
        """
        self._observe(name=ExtensionHealthObserver.AGENT_OBSERVATION_NAME,
                      is_healthy=True,
                      value=ExtensionHealthObserver.AGENT_OBSERVATION_VALUE)
        self._observe(name=ExtensionHealthObserver.CONTEXT_OBSERVATION + ExtensionHealthObserver.AGENT_OBSERVATION_NAME,
                      is_healthy=True,
                      description=ExtensionHealthObserver.CONTEXT_OBSERVATION,
                      value=vm_status.vmAgent.version)
        self._commit_partial_observations()

    def get_observations(self):
        """
        Retrieves the combination of the latest extension observations and the static observations that do not
        change over the lifetime of the VM.
        """
        return self.latest_observations + self.static_observations
    
    def add_vminfo_observation(self, name, value):
        """
        Adds a static observation that will not change over the lifetime of the VM.
        """
        if value is not None:
            self.static_observations.append(Observation(name=ExtensionHealthObserver.CONTEXT_OBSERVATION + name,
                                                        is_healthy=True,
                                                        value=value,
                                                        description=ExtensionHealthObserver.CONTEXT_OBSERVATION))

    def _observe(self, name, is_healthy, value='', description=''):
        self.partial_observations.append(Observation(name=name,
                                             is_healthy=is_healthy,
                                             value=value,
                                             description=description))

    def _commit_partial_observations(self):
        self.latest_observations = self.partial_observations
        self.partial_observations = list()


__extension_health_observer__ = ExtensionHealthObserver()


def get_extension_health_observer():
    return __extension_health_observer__


class Observation(object):
    def __init__(self, name, is_healthy, description='', value=''):
        if name is None:
            raise ValueError("Observation name must be provided")

        if is_healthy is None:
            raise ValueError("Observation health must be provided")

        if value is None:
            value = ''

        if description is None:
            description = ''

        self.name = name
        self.is_healthy = is_healthy
        self.description = description
        self.value = value

    @property
    def as_obj(self):
        return {
            "ObservationName": self.name[:64],
            "IsHealthy": self.is_healthy,
            "Description": self.description[:128],
            "Value": self.value[:128]
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
    IMDS_OBSERVATION_NAME = 'InstanceMetadataHeartbeat'
    MAX_OBSERVATIONS = 10

    def __init__(self, endpoint, extension_health_observer=__extension_health_observer__):
        self.endpoint = HealthService.ENDPOINT.format(endpoint)
        self.api = HealthService.API
        self.version = HealthService.VERSION
        self.source = HealthService.OBSERVER_NAME
        self.observations = list()
        self.ext_health_observer = __extension_health_observer__

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
        self._observe(name=HealthService.HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME,
                      is_healthy=is_healthy)
        self._report()

    def report_host_plugin_versions(self, is_healthy, response):
        """
        Reports a signal for /versions
        :param is_healthy: whether the api call succeeded
        :param response: debugging information for failures
        """
        self._observe(name=HealthService.HOST_PLUGIN_VERSIONS_OBSERVATION_NAME,
                      is_healthy=is_healthy,
                      value=response)
        self._report()

    def report_host_plugin_extension_artifact(self, is_healthy, source, response):
        """
        Reports a signal for /extensionArtifact
        :param is_healthy: whether the api call succeeded
        :param source: specifies the api caller for debugging failures
        :param response: debugging information for failures
        """
        self._observe(name=HealthService.HOST_PLUGIN_ARTIFACT_OBSERVATION_NAME,
                      is_healthy=is_healthy,
                      description=source,
                      value=response)
        self._report()

    def report_host_plugin_status(self, is_healthy, response):
        """
        Reports a signal for /status
        :param is_healthy: whether the api call succeeded
        :param response: debugging information for failures
        """
        self._observe(name=HealthService.HOST_PLUGIN_STATUS_OBSERVATION_NAME,
                      is_healthy=is_healthy,
                      value=response)
        self._report()

    def report_imds_status(self, is_healthy, response):
        """
        Reports a signal for /metadata/instance
        :param is_healthy: whether the api call succeeded and returned valid data
        :param response: debugging information for failures
        """
        self._observe(name=HealthService.IMDS_OBSERVATION_NAME,
                      is_healthy=is_healthy,
                      value=response)
        self._report()

    def report_extension_health_observations(self):
        """
        Reports an observation for each of the extensions and their version, as well as information
        about the agent and the VM retrieved from the ExtensionHealthObserver helper
        """
        # clear all previous observations from the class,
        # and do not enforce constraints on the list size
        del self.observations[:]
        self.observations.extend(self.ext_health_observer.get_observations())
        if not self.observations:
            self._report()

    def _observe(self, name, is_healthy, value='', description=''):
        # ensure we keep the list size within bounds
        if len(self.observations) >= HealthService.MAX_OBSERVATIONS:
            del self.observations[:HealthService.MAX_OBSERVATIONS-1]
        self.observations.append(Observation(name=name,
                                             is_healthy=is_healthy,
                                             value=value,
                                             description=description))

    def _report(self):
        logger.verbose('HealthService: report observations')
        try:
            restutil.http_post(self.endpoint, self.as_json, headers={'Content-Type': 'application/json'})
            logger.verbose('HealthService: Reported observations to {0}: {1}', self.endpoint, self.as_json)
        except HttpError as e:
            logger.warn("HealthService: could not report observations: {0}", ustr(e))
        finally:
            # these signals are not timestamped, so there is no value in persisting data
            del self.observations[:]
