from dcr.scenario_utils.extensions.CustomScriptExtension import add_cse
from dcr.scenario_utils.extensions.VMAccessExtension import add_and_verify_vmaccess
from dcr.scenario_utils.test_orchestrator import TestFuncObj, TestOrchestrator


def main():
    tests = [
        TestFuncObj("Add Cse", lambda: add_cse(), raise_on_error=True),
        TestFuncObj("Add VMAccess", lambda: add_and_verify_vmaccess(), raise_on_error=True)
    ]

    test_orchestrator = TestOrchestrator("ETPTests-Host", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report_on_orchestrator("test-results-etp-host.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"


if __name__ == '__main__':
    main()
