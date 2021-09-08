import os

from dcr.scenario_utils.common_utils import get_vm_data_from_env
from dcr.scenario_utils.extensions.CustomScriptExtension import add_cse
from dcr.scenario_utils.extensions.VMAccessExtension import add_and_verify_vmaccess
from dcr.scenario_utils.test_orchestrator import TestObj, TestOrchestrator


def main():
    vm_data = get_vm_data_from_env()
    tests = [
        TestObj("Add Cse", lambda: add_cse(vm_data), raise_on_error=True),
        TestObj("Add VMAccess", lambda: add_and_verify_vmaccess(vm_data), raise_on_error=True)
    ]

    test_orchestrator = TestOrchestrator("ETPTests-Host", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report(
        os.path.join(os.environ['BUILD_ARTIFACTSTAGINGDIRECTORY'], "test-results-etp-host.xml"))
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"


if __name__ == '__main__':
    main()
