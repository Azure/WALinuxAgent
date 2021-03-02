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

from azurelinuxagent.common.agent_supported_feature import SupportedFeatureNames, \
    get_agent_supported_features_list_for_crp, get_supported_feature_by_name, \
    get_agent_supported_features_list_for_extensions
from tests.tools import AgentTestCase, patch


class TestAgentSupportedFeature(AgentTestCase):

    def test_it_should_return_features_properly(self):
        with patch("azurelinuxagent.common.agent_supported_feature._MultiConfigFeature.is_supported", True):
            self.assertIn(SupportedFeatureNames.MultiConfig, get_agent_supported_features_list_for_crp(),
                          "Multi-config should be fetched in crp_supported_features")

        with patch("azurelinuxagent.common.agent_supported_feature._MultiConfigFeature.is_supported", False):
            self.assertNotIn(SupportedFeatureNames.MultiConfig, get_agent_supported_features_list_for_crp(),
                             "Multi-config should not be fetched in crp_supported_features as not supported")

        self.assertEqual(SupportedFeatureNames.MultiConfig,
                         get_supported_feature_by_name(SupportedFeatureNames.MultiConfig).name,
                         "Invalid/Wrong feature returned")

        # Raise error if feature name not found
        with self.assertRaises(NotImplementedError):
            get_supported_feature_by_name("ABC")

    def test_it_should_return_extension_supported_features_properly(self):
        with patch("azurelinuxagent.common.agent_supported_feature._ETPFeature.is_supported", True):
            self.assertIn(SupportedFeatureNames.ExtensionTelemetryPipeline,
                          get_agent_supported_features_list_for_extensions(), "ETP should be in supported features list")

        with patch("azurelinuxagent.common.agent_supported_feature._ETPFeature.is_supported", False):
            self.assertNotIn(SupportedFeatureNames.ExtensionTelemetryPipeline,
                             get_agent_supported_features_list_for_extensions(),
                             "ETP should not be in supported features list")

        self.assertEqual(SupportedFeatureNames.ExtensionTelemetryPipeline,
                         get_supported_feature_by_name(SupportedFeatureNames.ExtensionTelemetryPipeline).name,
                         "Invalid/Wrong feature returned")
