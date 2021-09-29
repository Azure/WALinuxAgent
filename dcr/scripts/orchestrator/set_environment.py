import json
import logging
import os.path

from dcr.scenario_utils.common_utils import execute_command_and_raise_on_error
from dcr.scenario_utils.logging_utils import get_logger


def _check_if_file_in_scenario_and_set_variable(file_name: str, name: str, true_value: str, false_val: str = None):
    """
    We have certain scenarios in the tests where we determine what type of test to run based on the availability of the file.
    Check if file is present in the current scenario, and if so, set the variable name.
    Syntax for setting the variable : https://docs.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands?view=azure-devops&tabs=bash#setvariable-initialize-or-modify-the-value-of-a-variable
    Eg: echo "##vso[task.setvariable variable=<VariableName>;]<Variable value>"
    """
    file_path = os.path.join(scenario_path, file_name)
    if os.path.exists(file_path):
        logger.info(f"Found file: {file_path}, setting variable: {name}")
        execute_command_and_raise_on_error(command=add_variable_to_pipeline.format(name=name, value=true_value),
                                           shell=True)
    elif false_val is not None:
        execute_command_and_raise_on_error(command=add_variable_to_pipeline.format(name=name, value=false_val),
                                           shell=True)


def _override_config():
    """
    This function reads the config.json file present in the scenario and makes all the variables available to the whole
    job as environment variables.
    It also overrides existing variables with the same name if available.
    Note: This function expects config.json to be a flat JSON
    """
    config_path = os.path.join(scenario_path, "config.json")
    if not os.path.exists(config_path):
        logger.info(f"Config file: {config_path} not available")
        return

    with open(config_path, encoding="utf-8") as config_fh:
        config_data = json.load(config_fh)
        for key, val in config_data.items():
            execute_command_and_raise_on_error(command=add_variable_to_pipeline.format(name=key, value=val), shell=True)


if __name__ == '__main__':
    """
    This script sets the environment for the current job.
    It determines what files to run and what not.
    Eg: If we're supposed to run run.host.py or run.py 
    """
    logger = get_logger("SetEnvironment")
    __dcr_dir = os.path.join(os.environ.get("BUILD_SOURCESDIRECTORY"), "dcr")
    scenario_path = os.path.join(__dcr_dir, "scenario")
    template_dir = os.path.join(__dcr_dir, "templates")
    add_variable_to_pipeline = 'echo "##vso[task.setvariable variable={name};]{value}"'

    _check_if_file_in_scenario_and_set_variable(file_name="run.py", name="runPy", true_value="true")
    _check_if_file_in_scenario_and_set_variable(file_name="run.host.py", name="runHost", true_value="true")
    _check_if_file_in_scenario_and_set_variable(file_name="setup.sh", name="runScenarioSetup", true_value="true")
    _check_if_file_in_scenario_and_set_variable(file_name="template.json", name="templateFile",
                                                true_value=os.path.join(scenario_path, "template.json"),
                                                false_val=os.path.join(template_dir, "deploy-linux-vm.json"))
    _check_if_file_in_scenario_and_set_variable(file_name="parameters.json", name="parametersFile",
                                                true_value=os.path.join(scenario_path, "parameters.json"),
                                                false_val=os.path.join(template_dir, "deploy-linux-vm-params.json"))

    # Check if config.json exists and add to environment
    _override_config()
