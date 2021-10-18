from dcr.scenario_utils.common_utils import execute_py_script_over_ssh_on_test_vms
from dcr.scenario_utils.extensions.CustomScriptExtension import add_cse
from dcr.scenario_utils.extensions.VMAccessExtension import add_and_verify_vmaccess
from dcr.scenario_utils.test_orchestrator import TestOrchestrator, TestFuncObj

if __name__ == '__main__':
    # Execute run1.py first
    execute_py_script_over_ssh_on_test_vms(command="dcr/scenarios/agent-bvt/run1.py")

    # Add extensions from the Host
    tests = [
        TestFuncObj("Add Cse", add_cse, raise_on_error=True),
        TestFuncObj("Add VMAccess", add_and_verify_vmaccess, raise_on_error=True)
    ]

    test_orchestrator = TestOrchestrator("AgentBVT-Host", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report_on_orchestrator("test-results-bvt-host.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"

    # Execute run2.py finally
    execute_py_script_over_ssh_on_test_vms(command="dcr/scenarios/agent-bvt/run2.py")

