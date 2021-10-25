from dcr.scenario_utils.check_waagent_log import check_waagent_log_for_errors
from dcr.scenario_utils.test_orchestrator import TestFuncObj, TestOrchestrator


if __name__ == '__main__':
    tests = [
        TestFuncObj("check agent log", check_waagent_log_for_errors)
    ]

    test_orchestrator = TestOrchestrator("ExtSeqDependency-VM", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report_on_vm("test-result-ext-seq-vm.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"
