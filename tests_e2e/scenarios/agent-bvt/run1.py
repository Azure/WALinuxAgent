from dcr.scenario_utils.test_orchestrator import TestFuncObj, TestOrchestrator
from test_agent_basics import test_agent_version, check_hostname, check_ns_lookup, check_root_login

if __name__ == '__main__':
    tests = [
        TestFuncObj("check_agent_version", test_agent_version),
        TestFuncObj("Check hostname", check_hostname),
        TestFuncObj("Check NSLookup", check_ns_lookup),
        TestFuncObj("Check Root Login", check_root_login)
    ]

    test_orchestrator = TestOrchestrator("AgentBVTs-VM", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report_on_vm("test-result-bvt-run1.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"

