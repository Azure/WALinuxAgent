import json
import azurelinuxagent.ga.policy.regorus.regorus_ctypes as regorus


class Engine:
    def __init__(self):
        self._engine = regorus.regorus_engine_new()
        if not self._engine:
            raise Exception("Failed to create engine")

    def add_policy_from_file(self, file):
        regorus.regorus_engine_add_policy_from_file(self._engine, file)

    def set_input_json(self, data):
        regorus.regorus_engine_set_input_json(self._engine, data)

    def add_data_json(self, data):
        regorus.regorus_engine_add_data_json(self._engine, data)

    def eval_query(self, data):
        result = regorus.regorus_engine_eval_query(self._engine, data)
        if result.output:
            try:
                json_output = json.loads(str(result.output))
            except json.JSONDecodeError as e:
                print("Failed to decode JSON: {}".format(e))
        else:
            json_output = "{}"
        return json_output

    def add_data_from_json_file(self, file):
        regorus.regorus_engine_add_data_from_json_file(self._engine, file)