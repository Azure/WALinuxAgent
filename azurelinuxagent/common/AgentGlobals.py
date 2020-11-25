# Microsoft Azure Linux Agent  # pylint: disable=C0103
#
# Copyright 2020 Microsoft Corporation
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


class AgentFeature(object):
    """
    Interface for defining new features that the Linux Guest Agent supports
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


class _MultiConfigFeature(AgentFeature):

    __NAME = "MultipleExtensionsPerHandler"
    __VERSION = "1.0"
    __SUPPORTED = False

    def __init__(self):
        super(_MultiConfigFeature, self).__init__(name=_MultiConfigFeature.__NAME,
                                                  version=_MultiConfigFeature.__VERSION,
                                                  supported=_MultiConfigFeature.__SUPPORTED)


class AgentGlobals(object):
    """
    This class is used for setting AgentGlobals which can be used all throughout the Agent.
    """

    #
    # Some modules (e.g. telemetry) require an up-to-date container ID. We update this variable each time we
    # fetch the goal state.
    #
    _container_id = "00000000-0000-0000-0000-000000000000"

    # Feature List
    __multi_config_feature = _MultiConfigFeature()

    @staticmethod
    def get_multi_config_feature():
        return AgentGlobals.__multi_config_feature

    @staticmethod
    def get_supported_features():
        """
        List of features that the GuestAgent currently supports (like FastTrack, MultiConfig, etc).
        We need to send this list as part of Status reporting to inform CRP of all the features it supports.
        :return: Dict containing all supported features. Empty dict if no features supported
        Eg:
            {
                "MultipleExtensionsPerHandler": "1.0",
                "FastTrack": "1.0"
            }
        """

        supported_features = dict()

        multi_config = AgentGlobals.get_multi_config_feature()
        if multi_config.is_supported:
            supported_features[multi_config.name] = multi_config.version

        return supported_features

    @staticmethod
    def get_container_id():
        return AgentGlobals._container_id

    @staticmethod
    def update_container_id(container_id):
        AgentGlobals._container_id = container_id
