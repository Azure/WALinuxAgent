import json
import subprocess
import os
# import azurelinuxagent.ga.policy.regorus.regorus_ffi as regorus


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

    def set_input_json(self, input):
        self._input_file = input

    def add_data_json(self, data):
        self._data_file = data

    def eval_query(self, query):
        from tests.lib.tools import data_dir
        regorus_path = os.path.join(data_dir, 'policy', 'regorus')

        command = [regorus_path, "eval", "-d", self._policy_file, "-d", self._data_file,
                   "-i", self._input_file, query]
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                stdout = result.stdout
                print(stdout)
                json_output = json.loads(stdout)
                return json_output
            else:
                return {}
        except Exception as e:
            raise Exception


    # def add_data_from_json_file(self, file):
    #     regorus.regorus_engine_add_data_from_json_file(self._engine, file)