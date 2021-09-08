import os

from dcr.scenario_utils.common_utils import get_vm_data_from_env, execute_py_command_on_vm
from dcr.scenario_utils.extensions.CustomScriptExtension import add_cse
from dcr.scenario_utils.extensions.VMAccessExtension import add_and_verify_vmaccess
from dcr.scenario_utils.test_orchestrator import TestOrchestrator, TestObj

if __name__ == '__main__':
    scenario_name = os.environ['SCENARIONAME']
    admin_username = os.environ['ADMINUSERNAME']

    # Execute run1.py first
    execute_py_command_on_vm(command="dcr/scenarios/agent-bvt-module/run1.py")

    # Add extensions from the Host
    vm_data = get_vm_data_from_env()
    tests = [
        TestObj("Add Cse", lambda: add_cse(vm_data), raise_on_error=True),
        TestObj("Add VMAccess", lambda: add_and_verify_vmaccess(vm_data), raise_on_error=True)
    ]

    test_orchestrator = TestOrchestrator("AgentBVT-Host", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report(
        os.path.join(os.environ['BUILD_ARTIFACTSTAGINGDIRECTORY'], "test-results-bvt-host.xml"))
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"

    # Execute run2.py finally
    execute_py_command_on_vm(command="dcr/scenarios/agent-bvt-module/run2.py")

