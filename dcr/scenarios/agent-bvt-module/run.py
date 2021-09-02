import os

from dotenv import load_dotenv
from junit_xml import TestSuite, to_xml_report_file

from check_extension_timing import verify_extension_timing
from check_firewall import check_firewall
from dcr.scenario_utils.check_waagent_log import check_waagent_log_for_errors
from dcr.scenario_utils.test_orchestrator import run_test_and_get_tc
from execute_extension_tests import execute_cse_tests
from get_blob_content import show_blob_content
from test_agent_basics import test_agent_version, check_hostname, check_ns_lookup, check_root_login, \
    check_agent_processes, check_sudoers

if __name__ == '__main__':
    # Environ vars
    load_dotenv()
    scenario_name = os.environ['SCENARIONAME']
    admin_username = os.environ['ADMINUSERNAME']

    test_cases = [run_test_and_get_tc("check_agent_version", test_agent_version),
                  run_test_and_get_tc("Check hostname", check_hostname),
                  run_test_and_get_tc("Check NSLookup", check_ns_lookup),
                  run_test_and_get_tc("Check Root Login", check_root_login),
                  run_test_and_get_tc("execute CSE", execute_cse_tests),
                  run_test_and_get_tc("check agent processes", check_agent_processes),
                  run_test_and_get_tc("check agent log", check_waagent_log_for_errors),
                  run_test_and_get_tc("Verify status blob", show_blob_content, 'Status', 'StatusUploadBlob'),
                  run_test_and_get_tc("verify artifact blob", show_blob_content, 'InVMArtifacts', 'InVMArtifactsProfileBlob'),
                  run_test_and_get_tc("verify extension timing", verify_extension_timing),
                  run_test_and_get_tc("Check Firewall", check_firewall, admin_username),
                  run_test_and_get_tc("Check Sudoers", check_sudoers, admin_username)]

    ts = TestSuite(scenario_name, test_cases=test_cases)
    output_file = os.path.join("/home", admin_username, "test-result-{0}.xml".format(scenario_name))
    with open(output_file, 'w') as f:
        to_xml_report_file(f, [ts])
