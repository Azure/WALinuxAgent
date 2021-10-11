from check_extension_timing import verify_extension_timing
from check_firewall import check_firewall
from dcr.scenario_utils.check_waagent_log import check_waagent_log_for_errors
from dcr.scenario_utils.models import get_vm_data_from_env
from dcr.scenario_utils.test_orchestrator import TestFuncObj, TestOrchestrator
from get_blob_content import show_blob_content
from test_agent_basics import check_agent_processes, check_sudoers

if __name__ == '__main__':
    admin_username = get_vm_data_from_env().admin_username
    tests = [
        TestFuncObj("check agent processes", check_agent_processes),
        TestFuncObj("check agent log", check_waagent_log_for_errors),
        TestFuncObj("Verify status blob", lambda: show_blob_content('Status', 'StatusUploadBlob')),
        TestFuncObj("Verify status blob", lambda: show_blob_content('InVMArtifacts', 'InVMArtifactsProfileBlob')),
        TestFuncObj("verify extension timing", verify_extension_timing),
        TestFuncObj("Check Firewall", lambda: check_firewall(admin_username)),
        TestFuncObj("Check Sudoers", lambda: check_sudoers(admin_username))
    ]

    test_orchestrator = TestOrchestrator("AgentBVTs-VM", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report_on_vm("test-result-bvt-run2.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"
