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
import os
import tempfile
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.utils.shellutil import CommandError
from azurelinuxagent.common.exception import AgentError


def get_regorus_path():
    """
    Returns path to Regorus executable. The executable is not yet officially released as part of the agent package.
    After release, executable will be placed at /var/lib/waagent/WALinuxAgent-x.x.x.x/bin/regorus.
    Currently, the executable is copied into the agent directory for unit testing, and this method is mocked.
    """
    regorus_exe = os.path.join(os.getcwd(), "bin", "regorus")
    return regorus_exe


class PolicyError(AgentError):
    """
    Error raised during agent policy enforcement.
    """


class Engine:
    """
    This class implements the basic operations for the Regorus policy engine via subprocess.
    Any errors thrown in this class should be caught and handled by PolicyEngine.
    """

    def __init__(self, policy_file, rule_file):
        """
        Rule_file is expected to point to a valid Regorus file.

        Policy_file should be a path to a valid JSON policy (data) file.
        The expected file format is:
        {
            "azureGuestAgentPolicy": {
                "policyVersion": "0.1.0",
                "signingRules": {
                    "extensionSigned": <true, false>
                },
                "allowListOnly": <true, false>
            },
            "azureGuestExtensionsPolicy": {
                "allowed_ext_1": {
                    "signingRules": {
                        "extensionSigned": <true, false>
                    }
                }
        }
        """
        self._engine = None
        self._rule_file = rule_file
        self._policy_file = policy_file

    def eval_query(self, input_dict, query):
        """
        Input_dict should be type dict.
        Expected format:
        {
            "extensions": {
                "<extension_name_1>": {
                    "signingInfo": {
                        "extensionSigned": <true, false>
                    }
                },
                "<extension_name_2>": {
                    "signingInfo": {
                        "extensionSigned": <true, false>
                    }
                }, ...
        }

        In this method, we call the Regorus executable via run_command to query the policy engine.

        Command:
            regorus eval -d <rule_file.rego> -d <policy_file.json> -i <input_file.json> <QUERY>

        Parameters:
            -d, --data <rule.rego|policy.json> : Rego file or JSON file.
            -i, --input <input.json> : Input file in JSON format.
            <QUERY>  Query. Rego query block in the format "data.<optional_query>"

        Return Codes:
            0 - successful query. optional parameters may be missing
            1 - file error: unsupported file type, error parsing file, file not found
                ex: "Error: Unsupported data file <file>. Must be rego or json."
                ex: "Error: Failed to read <file>. No such file or directory."
            2 - usage error: missing query argument, unexpected or unlabeled parameter
                ex: "Error: the following required arguments were not provided: <QUERY>"
                ex: "Error: Unexpected argument <arg> found."
        """
        # Write input_dict to a temp file, because Regorus requires input to be a file path.
        # Tempfile is automatically cleaned up at the end of with block
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as input_file:
            json.dump(input_dict, input_file, indent=4)
            input_file.flush()

            regorus_exe = get_regorus_path()
            command = [regorus_exe, "eval", "-d", self._rule_file, "-d", self._policy_file,
                       "-i", input_file.name, query]

            try:
                stdout = shellutil.run_command(command)
            except CommandError as ex:
                code = ex.returncode
                if code == 1:
                    msg = "file error when using policy engine. {0}".format(ex)
                elif code == 2:
                    msg = "incorrect parameters passed to policy engine. {0}".format(ex)
                else:
                    msg = "error when using policy engine. {0}".format(ex)
                raise PolicyError(msg=msg)

            json_output = json.loads(stdout)
            return json_output
