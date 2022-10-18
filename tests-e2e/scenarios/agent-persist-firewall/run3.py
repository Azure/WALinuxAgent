from dcr.scenario_utils.check_waagent_log import check_waagent_log_for_errors
from dcr.scenario_utils.common_utils import get_current_agent_name
from dcr.scenario_utils.test_orchestrator import TestFuncObj, TestOrchestrator
from persist_firewall_helpers import verify_wire_ip_in_iptables, run_systemctl_command, verify_system_rebooted, \
    generate_svg, verify_wire_ip_unreachable_for_non_root, verify_wire_ip_reachable_for_root


def ensure_agent_not_running():
    print("Verifying agent not running")
    agent_service_name = "{0}.service".format(get_current_agent_name())
    ec, _, __ = run_systemctl_command(agent_service_name, "is-enabled")
    if ec == 0:
        raise Exception("{0} is enabled!".format(agent_service_name))

    ec, _, __ = run_systemctl_command(agent_service_name, "is-active")
    if ec == 0:
        raise Exception("{0} should not be active!".format(agent_service_name))


if __name__ == '__main__':
    tests = [
        TestFuncObj("Verify system rebooted", verify_system_rebooted, raise_on_error=True),
        TestFuncObj("Ensure agent not running", ensure_agent_not_running),
        TestFuncObj("Generate SVG", lambda: generate_svg(svg_name="agent_not_running.svg")),
        TestFuncObj("Verify wire IP unreachable for non-root", verify_wire_ip_unreachable_for_non_root),
        TestFuncObj("Verify wire IP reachable for root", verify_wire_ip_reachable_for_root),
        # Considering the rules should be set on reboot, not adding a retry check
        TestFuncObj("Verify wire IP in IPTables", lambda: verify_wire_ip_in_iptables(max_retry=1)),
        TestFuncObj("Check agent log", check_waagent_log_for_errors)
    ]

    test_orchestrator = TestOrchestrator("PersistFirewall-VM3", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report_on_vm("test-result-pf-run3.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"

