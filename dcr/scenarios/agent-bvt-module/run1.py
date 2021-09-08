import os

from dotenv import load_dotenv

from dcr.scenario_utils.test_orchestrator import TestObj, TestOrchestrator
from test_agent_basics import test_agent_version, check_hostname, check_ns_lookup, check_root_login

if __name__ == '__main__':
    load_dotenv()
    admin_username = os.environ['ADMINUSERNAME']
    tests = [
        TestObj("check_agent_version", test_agent_version),
        TestObj("Check hostname", check_hostname),
        TestObj("Check NSLookup", check_ns_lookup),
        TestObj("Check Root Login", check_root_login)
    ]

    test_orchestrator = TestOrchestrator("AgentBVTs-VM", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report(os.path.join("/home", admin_username, "test-result-bvt-run1.xml"))
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"

