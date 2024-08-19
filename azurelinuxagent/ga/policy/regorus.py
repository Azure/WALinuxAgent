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
# Requires Python 2.4+ and Openssl 1.0+
#

import json
import subprocess
import os
import tempfile


def get_regorus_path():
    """
    Returns path to Regorus executable. The executable is not yet officially released as part of the agent package.
    After release, executable will be placed at /var/lib/waagent/WALinuxAgent-x.x.x.x/bin/regorus.
    Currently, the executable is copied into the agent directory for unit testing, and this method is mocked.
    """
    regorus_exe = os.path.join(os.getcwd(), "bin", "regorus")
    return regorus_exe


class Engine:
    """
    This class implements the basic operations for the Regorus policy engine via subprocess.
    Any errors thrown in this class should be caught and handled by PolicyEngine.
    """

    def __init__(self):
        self._engine = None
        self._policy_file = None
        self._data_file = None
        self._input_json = None

    def add_policy(self, policy_path):
        """Policy_path is expected to point to a valid Regorus file."""
        if not os.path.exists(policy_path) or not policy_path.endswith('.rego'):
            raise Exception("Policy path {0} is not a valid .rego file.".format(policy_path))
        self._policy_file = policy_path

    def set_input(self, input_json):
        """Input_path is expected to point to a valid JSON object."""
        if isinstance(input_json, dict):
            self._input_json = input_json
        elif isinstance(input_json, str):
            self._input_json = json.loads(input_json)
        else:
            raise Exception("Input to policy engine is not a valid JSON object.")

    def add_data(self, data):
        """Data parameter is expected to point to a valid json file."""
        if not os.path.exists(data) or not data.endswith(".json"):
            raise Exception("Data path {0} is not a valid JSON file.".format(data))
        self._data_file = data

    def eval_query(self, query):
        missing_files = []
        if self._policy_file is None:
            missing_files.append("policy file")
        if self._input_json is None:
            missing_files.append("input")
        if self._data_file is None:
            missing_files.append("data file")
        if missing_files:
            raise Exception("Missing {0} to run query.".format(', '.join(missing_files)))

        # Write input JSON to a temp file, because Regorus requires input to be a file path.
        # Tempfile is automatically cleaned up at the end of with block
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as input_file:
            json.dump(self._input_json, input_file, indent=4)
            input_file.flush()

            regorus_exe = get_regorus_path()
            command = [regorus_exe, "eval", "-d", self._policy_file, "-d", self._data_file,
                       "-i", input_file.name, query]

            # use subprocess.Popen instead of subprocess.run for Python 2 compatibility
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                # Decode stdout to string if it is bytes (Python 3.x)
                stdout = stdout.decode('utf-8') if isinstance(stdout, bytes) else stdout
                json_output = json.loads(stdout)
                return json_output
            else:
                stderr = stderr.decode('utf-8') if isinstance(stderr, bytes) else stderr
                raise Exception("Subprocess error. {0}".format(stderr))
