import os

from dotenv import load_dotenv

from check_extension_timing import verify_extension_timing
from check_firewall import check_firewall
from dcr.scenario_utils.check_waagent_log import check_waagent_log_for_errors
from dcr.scenario_utils.test_orchestrator import TestObj, TestOrchestrator
from get_blob_content import show_blob_content
from test_agent_basics import check_agent_processes, check_sudoers

if __name__ == '__main__':
    load_dotenv()
    admin_username = os.environ['ADMINUSERNAME']
    tests = [
        TestObj("check agent processes", check_agent_processes),
        TestObj("check agent log", check_waagent_log_for_errors),
        TestObj("Verify status blob", lambda: show_blob_content('Status', 'StatusUploadBlob')),
        TestObj("Verify status blob", lambda: show_blob_content('InVMArtifacts', 'InVMArtifactsProfileBlob')),
        TestObj("verify extension timing", verify_extension_timing),
        TestObj("Check Firewall", lambda: check_firewall(admin_username)),
        TestObj("Check Sudoers", lambda: check_sudoers(admin_username))
    ]

    test_orchestrator = TestOrchestrator("AgentBVTs-VM", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report(os.path.join("/home", admin_username, "test-result-bvt-run2.xml"))
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"
