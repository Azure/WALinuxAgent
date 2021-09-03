import uuid

import os

from dcr.scenario_utils.common_utils import get_vm_data_from_env
from dcr.scenario_utils.extensions.CustomScriptExtension import CustomScriptExtension
from dcr.scenario_utils.test_orchestrator import TestObj, TestOrchestrator


def add_cse(vm_data):
    settings = [
        {'commandToExecute': "echo \'Hello World! {0} \'".format(uuid.uuid4())},
        {'commandToExecute': "echo \'Hello again\'"}
    ]

    # Install and remove CSE
    cse = CustomScriptExtension(extension_name="testEtpCse", vm_data=vm_data)
    cse.run(settings=settings)


def main():
    vm_data = get_vm_data_from_env()
    tests = [
        TestObj("Add Cse", lambda: add_cse(vm_data), raise_on_error=True)
    ]

    test_orchestrator = TestOrchestrator("ETPTests-Host", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report(
        os.path.join(os.environ['BUILD_ARTIFACTSTAGINGDIRECTORY'], "test-results-etp-host.xml"))
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"


if __name__ == '__main__':
    main()
