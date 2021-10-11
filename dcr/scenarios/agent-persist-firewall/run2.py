from dcr.scenario_utils.common_utils import get_current_agent_name
from dcr.scenario_utils.test_orchestrator import TestFuncObj, TestOrchestrator
from persist_firewall_helpers import verify_wire_ip_in_iptables, verify_system_rebooted, generate_svg, \
    verify_wire_ip_unreachable_for_non_root, verify_wire_ip_reachable_for_root, run_systemctl_command, \
    firewalld_service_enabled, print_stateful_debug_data


def check_external_service_status():
    agent_name = get_current_agent_name()
    # Check if firewall active on the Vm
    if firewalld_service_enabled():
        # If yes, then print its status
        ec, _, __ = run_systemctl_command("firewalld.service", command="status")
        if ec != 0:
            raise Exception("Something wrong with firewalld.service!")

    # Else print status of our custom service
    else:
        service_name = "{0}-network-setup.service".format(agent_name)

        # Check if enabled, if not then raise Error
        ec, stdout, stderr = run_systemctl_command(service_name, command="is-enabled")
        if ec != 0:
            raise Exception("Service should be enabled!")

        # Check if failed, if so then raise Error
        ec, stdout, stderr = run_systemctl_command(service_name, command="is-failed")
        if ec == 0:
            raise Exception("The service should not be in a failed state!")

        # Finally print the status of the service
        run_systemctl_command(service_name, command="status")

    print("\nDisable Guest Agent service for more verbose testing")
    ec, _, __ = run_systemctl_command(service_name="{0}.service".format(agent_name), command="disable")
    if ec != 0:
        raise Exception("Agent not disabled properly!")


if __name__ == '__main__':
    tests = [
        TestFuncObj("Verify system rebooted", verify_system_rebooted, raise_on_error=True),
        TestFuncObj("Generate SVG", lambda: generate_svg(svg_name="agent_running.svg")),
        TestFuncObj("Verify wireIP unreachable for non-root", verify_wire_ip_unreachable_for_non_root),
        TestFuncObj("Verify wireIP reachable for root", verify_wire_ip_reachable_for_root),
        TestFuncObj("Verify_Wire_IP_IPTables", lambda: verify_wire_ip_in_iptables(max_retry=1)),
        TestFuncObj("Verify External services", check_external_service_status)
    ]

    test_orchestrator = TestOrchestrator("PersistFirewall-VM2", tests=tests)
    test_orchestrator.run_tests()

    # Print stateful debug data before reboot because the state might be lost after
    print_stateful_debug_data()

    test_orchestrator.generate_report_on_vm("test-result-pf-run2.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"

