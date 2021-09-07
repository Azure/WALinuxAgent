import uuid

import os

from dcr.scenario_utils.common_utils import get_vm_data_from_env
from dcr.scenario_utils.extensions.CustomScriptExtension import CustomScriptExtension
from dcr.scenario_utils.extensions.VMAccessExtension import VMAccessExtension
from dcr.scenario_utils.test_orchestrator import TestObj, TestOrchestrator


def add_cse(vm_data):
    # Install and remove CSE
    cse = CustomScriptExtension(extension_name="testEtpCse", vm_data=vm_data)

    ext_props = [
        cse.get_ext_props(settings={'commandToExecute': f"echo \'Hello World! {uuid.uuid4()} \'"}),
        cse.get_ext_props(settings={'commandToExecute': "echo \'Hello again\'"})
    ]

    cse.run(ext_props=ext_props)


def add_and_verify_vmaccess(vm_data):
    vmaccess = VMAccessExtension(extension_name="testVmAccessExt", vm_data=vm_data)
    ext_props = [
        vmaccess.get_ext_props(protected_settings={'username': vmaccess.user_name, 'ssh_key': vmaccess.public_key,
                                                   'reset_ssh': 'false'})
    ]
    vmaccess.run(ext_props=ext_props)
    vmaccess.verify()


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
