from dcr.scenario_utils.test_orchestrator import TestFuncObj, TestOrchestrator
from persist_firewall_helpers import verify_wire_ip_in_iptables

if __name__ == '__main__':
    tests = [
        TestFuncObj("Verify_Wire_IP_IPTables", verify_wire_ip_in_iptables)
    ]

    test_orchestrator = TestOrchestrator("PersistFirewall-VM1", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report_on_vm("test-result-pf-run1.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"

