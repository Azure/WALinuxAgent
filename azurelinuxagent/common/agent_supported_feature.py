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


class SupportedFeatureNames(object):
    """
    Enum for defining the Feature Names for all features that we the agent supports
    """
    MultiConfig = "MultipleExtensionsPerHandler"
    ExtensionTelemetryPipeline = "ExtensionTelemetryPipeline"
    FastTrack = "FastTrack"
    GAVersioningGovernance = "VersioningGovernance"  # Guest Agent Versioning


class AgentSupportedFeature(object):
    """
    Interface for defining all features that the Linux Guest Agent supports and reports their if supported back to CRP
    """

    def __init__(self, name, version="1.0", supported=False):
        self.__name = name
        self.__version = version
        self.__supported = supported

    @property
    def name(self):
        return self.__name

    @property
    def version(self):
        return self.__version

    @property
    def is_supported(self):
        return self.__supported


class _MultiConfigFeature(AgentSupportedFeature):

    __NAME = SupportedFeatureNames.MultiConfig
    __VERSION = "1.0"
    __SUPPORTED = True

    def __init__(self):
        super(_MultiConfigFeature, self).__init__(name=_MultiConfigFeature.__NAME,
                                                  version=_MultiConfigFeature.__VERSION,
                                                  supported=_MultiConfigFeature.__SUPPORTED)


class _ETPFeature(AgentSupportedFeature):

    __NAME = SupportedFeatureNames.ExtensionTelemetryPipeline
    __VERSION = "1.0"
    __SUPPORTED = True

    def __init__(self):
        super(_ETPFeature, self).__init__(name=self.__NAME,
                                          version=self.__VERSION,
                                          supported=self.__SUPPORTED)


class _GAVersioningGovernanceFeature(AgentSupportedFeature):

    __NAME = SupportedFeatureNames.GAVersioningGovernance
    __VERSION = "1.0"
    __SUPPORTED = True

    def __init__(self):
        super(_GAVersioningGovernanceFeature, self).__init__(name=self.__NAME,
                                                             version=self.__VERSION,
                                                             supported=self.__SUPPORTED)


# This is the list of features that Agent supports and we advertise to CRP
__CRP_ADVERTISED_FEATURES = {
    SupportedFeatureNames.MultiConfig: _MultiConfigFeature(),
    SupportedFeatureNames.GAVersioningGovernance: _GAVersioningGovernanceFeature()
}


# This is the list of features that Agent supports and we advertise to Extensions
__EXTENSION_ADVERTISED_FEATURES = {
    SupportedFeatureNames.ExtensionTelemetryPipeline: _ETPFeature()
}


def get_supported_feature_by_name(feature_name):
    if feature_name in __CRP_ADVERTISED_FEATURES:
        return __CRP_ADVERTISED_FEATURES[feature_name]

    if feature_name in __EXTENSION_ADVERTISED_FEATURES:
        return __EXTENSION_ADVERTISED_FEATURES[feature_name]

    raise NotImplementedError("Feature with Name: {0} not found".format(feature_name))


def get_agent_supported_features_list_for_crp():
    """
    List of features that the GuestAgent currently supports (like FastTrack, MultiConfig, etc).
    We need to send this list as part of Status reporting to inform CRP of all the features the agent supports.
    :return: Dict containing all CRP supported features with the key as their names and the AgentFeature object as
             the value if they are supported by the Agent
        Eg: {
                MultipleExtensionsPerHandler: _MultiConfigFeature()
            }
    """

    return dict((name, feature) for name, feature in __CRP_ADVERTISED_FEATURES.items() if feature.is_supported)


def get_agent_supported_features_list_for_extensions():
    """
    List of features that the GuestAgent currently supports (like Extension Telemetry Pipeline, etc) needed by Extensions.
    We need to send this list as environment variables when calling extension commands to inform Extensions of all the
    features the agent supports.
    :return: Dict containing all Extension supported features with the key as their names and the AgentFeature object as
             the value if the feature is supported by the Agent.
        Eg: {
                CRPSupportedFeatureNames.ExtensionTelemetryPipeline: _ETPFeature()
            }
    """
    return dict((name, feature) for name, feature in __EXTENSION_ADVERTISED_FEATURES.items() if feature.is_supported)
