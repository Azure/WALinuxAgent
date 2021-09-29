import os

from dotenv import load_dotenv

from dcr.scenario_utils.models import get_vm_data_from_env
from dcr.scenario_utils.test_orchestrator import TestObj, TestOrchestrator
from persist_firewall_helpers import verify_wire_ip_in_iptables

if __name__ == '__main__':
    load_dotenv()
    admin_username = get_vm_data_from_env().admin_username
    tests = [
        TestObj("Verify_Wire_IP_IPTables", verify_wire_ip_in_iptables)
    ]

    test_orchestrator = TestOrchestrator("PersistFirewall-VM1", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report(os.path.join("/home", admin_username, "test-result-pf-run1.xml"))
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"

