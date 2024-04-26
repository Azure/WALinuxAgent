# Microsoft Azure Linux Agent
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


import regorus
import json
import os
from azurelinuxagent.common import logger
from azurelinuxagent.common.protocol.restapi import Extension, ExtHandlerStatus, ExtensionSettings


class PolicyEngine:
    """Base class for policy engine"""
    def __init__(self, policy_file=None, data_file=None):
        self._engine = regorus.Engine()
        if policy_file is not None:
            self._engine.add_policy_from_file(policy_file)
        if data_file is not None:
            # with open(data_file, 'r') as f:
            #     data = json.load(f)
            self.add_data(data_file)

    def add_policy(self, policy_file):
        """
        Add policy from file.
        Policy_file is expected to point to a valid Rego policy file.
        """
        self._engine.add_policy_from_file(policy_file)

    def add_data(self, data):
        """Add data based on input parameter type"""
        if os.path.isfile(data):
            data_file = json.load(open(data, 'r', encoding='utf-8'))
            self._engine.add_data(data_file)
        elif isinstance(data, dict):
            data_json = json.dumps(data)
            self._engine.add_data_json(data_json)
        elif isinstance(data, str):
            self._engine.add_data_json(data)
        else:
            logger.error("Unsupported data type: {0}".format(type(data)))

    def set_input(self, policy_input):
        """Set input"""
        if os.path.isfile(policy_input):
            input_file = json.load(open(policy_input, 'r', encoding='utf-8'))
            self._engine.set_input(input_file)
        elif isinstance(policy_input, dict):
            input_json = json.dumps(policy_input)
            self._engine.set_input_json(input_json)
        elif isinstance(policy_input, str):
            self._engine.set_input_json(policy_input)
        else:
            logger.error("Unsupported input type: {0}".format(type(policy_input)))

    def eval_query(self, query, return_json=True):
        """Evaluate query. If return_json is true,
        return results as json, else return as string."""
        if return_json:
            results = json.loads(self._engine.eval_query_as_json(query))
        else:
            results = self._engine.eval_query(query)
        return results


class ExtensionPolicyEngine(PolicyEngine):
    """Implement the policy engine for extension allow/disallow policy"""
    policy_path = None
    data_path = None
    allowed_list = None
    all_extensions = None

    def __init__(self, policy_path=None, data_path=None):
        self.policy_path = policy_path
        self.data_path = data_path
        super().__init__(self.policy_path, self.data_path)

    def get_allowed_list(self, all_extensions):
        """
        Get allowed list of extensions based on policy engine evaluation.
        If allowed_list is already set, return it.
        """
        # only query against the policy engine if the allowed list has
        # not been set OR if the input extensions have changed
        if self.allowed_list is not None and all_extensions == self.all_extensions:
            return self.allowed_list
        ext_json = self.__convert_list_to_json(all_extensions)
        super().set_input(ext_json)
        output = self.eval_query('data.extension_policy')
        if isinstance(output, str):
            output = json.loads(output)
        self.allowed_list = output["result"][0]["expressions"][0]["value"]["allowed_extensions"]
        return self.allowed_list

    def __convert_list_to_json(self, ext_list):
        """
        Convert a list of extensions to a json compatible with policy engine.
        Expects a list of tuples in the form (extension_setting, extension_handler).
        Returns json in the format:
        { "incoming":
            {
                "ext1:":
                    {
                        "name": "extname1"
                    ...
        """
        input_json = {
          "incoming": {}
        }
        for _, ext in ext_list:
            template = {
                "name": None
                # "version": None,
                # "state": None,
                # "settings": None,
                # "manifest_uris": None,
                # "supports_multi_config": None,
                # "is_invalid_setting": None,
                # "invalid_setting_reason": None
            }
            template["name"] = ext.name
            # template["version"] = ext.version
            # template["state"] = ext.state
            # template["settings"] = setting
            # template["manifest_uris"] = ext.manifest_uris
            # template["supports_multi_config"] = ext.supports_multi_config
            # template["is_invalid_setting"] = ext.is_invalid_setting
            # template["invalid_setting_reason"] = ext.invalid_setting_reason
            input_json["incoming"][ext.name] = template

        return json.dumps(input_json)
