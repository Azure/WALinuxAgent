import json
import subprocess
import os
from azurelinuxagent.common import logger


def get_regorus_path():
    """
    Returns path to Regorus executable. Currently, the executable is copied into ga/policy/regorus
    during testing. It is not yet officially released as part of the agent package.
    """
    regorus_exe = os.path.join(os.getcwd(), "azurelinuxagent", "ga", "policy", "regorus", "regorus")
    return regorus_exe


class Engine:

    def __init__(self):
        self._engine = None
        self._policy_file = None
        self._data_file = None
        self._input_file = None

    def add_policy(self, policy_path):
        """Policy_path is expected to point to a valid Regorus file."""
        if not os.path.exists(policy_path) or not policy_path.endswith('.rego'):
            raise Exception("Policy path {} is not a valid .rego file.".format(policy_path))
        self._policy_file = policy_path

    def set_input(self, input_path):
        if not os.path.exists(input_path) or not input_path.endswith(".json"):
            raise Exception("Input path {} is not a valid JSON file.".format(input_path))
        self._input_file = input_path

    def add_data(self, data):
        """Data parameter is expected to point to a valid json file."""
        if not os.path.exists(data) or not data.endswith(".json"):
            raise Exception("Data path {} is not a valid JSON file.".format(data))
        self._data_file = data

    def eval_query(self, query):
        regorus_exe = get_regorus_path()
        command = [regorus_exe, "eval", "-d", self._policy_file, "-d", self._data_file,
                   "-i", self._input_file, query]
        try:
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
                logger.error("Error when running Regorus executable: {}".format(stderr))
                return {}
        except Exception:
            raise Exception
