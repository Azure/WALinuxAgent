import os

from dotenv import load_dotenv

from dcr.scenario_utils.check_waagent_log import check_waagent_log_for_errors
from dcr.scenario_utils.models import get_vm_data_from_env
from dcr.scenario_utils.test_orchestrator import TestObj, TestOrchestrator


if __name__ == '__main__':
    load_dotenv()
    admin_username = get_vm_data_from_env().admin_username
    tests = [
        TestObj("check agent log", check_waagent_log_for_errors)
    ]

    test_orchestrator = TestOrchestrator("ExtSeqDependency-VM", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report(os.path.join("/home", admin_username, "test-result-ext-seq-vm.xml"))
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"
