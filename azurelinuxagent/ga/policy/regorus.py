import json
import subprocess
import os


def get_regorus_path():
    # Returns path to Regorus executable. Currently, the executable is copied into ga/policy/regorus
    # during testing. It is not officially released as part of the agent package.
    regorus_exe = os.path.join(os.getcwd(), "azurelinuxagent", "ga", "policy", "regorus", "regorus")
    return regorus_exe

class Engine:
    _engine = None
    _policy_file = None
    _data_file = None
    _input_file = None


    def __init__(self):
        pass
        # self._engine = regorus.regorus_engine_new()
        # if not self._engine:
        #     raise Exception("Failed to create engine")

    def add_policy_from_file(self, file):
        self._policy_file = file

    def set_input_json(self, input_file):
        self._input_file = input_file

    def add_data_json(self, data):
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
                print(stdout)
                json_output = json.loads(stdout)
                return json_output
            else:
                stderr = stderr.decode('utf-8') if isinstance(stderr, bytes) else stderr
                print("Standard Error:", stderr)
                return {}
        except Exception:
            raise Exception
