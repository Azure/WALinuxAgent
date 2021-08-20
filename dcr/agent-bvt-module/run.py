import os
import time

import traceback
from dotenv import load_dotenv
from junit_xml import TestCase, TestSuite, to_xml_report_file

from test_agent_basics import test_agent_version, check_hostname, check_ns_lookup, check_root_login
from execute_extension_tests import execute_cse_tests


def run_test_and_report(test_name, test_func, *args):
    stdout = ""
    tc = TestCase(test_name)
    start_time = time.time()
    print("---" * 20)
    print("TestName: {0}".format(test_name))
    try:
        stdout = test_func(*args)
        print("\tDebug Output: {0}".format(test_name, stdout))
    except Exception as err:
        print("\tError: {1}".format(test_name, err))
        tc.add_error_info(err, output=traceback.print_exc())

    tc.stdout = stdout
    tc.elapsed_sec = (time.time() - start_time)
    return tc


if __name__ == '__main__':
    # Environ vars
    load_dotenv()
    scenario_name = os.environ['SCENARIONAME']
    admin_username = os.environ['ADMINUSERNAME']

    test_cases = [run_test_and_report("check_agent_version", test_agent_version),
                  run_test_and_report("Check hostname", check_hostname),
                  run_test_and_report("Check NSLookup", check_ns_lookup),
                  run_test_and_report("Check Root Login", check_root_login),
                  run_test_and_report("execute CSE", execute_cse_tests)]

    ts = TestSuite(scenario_name, test_cases=test_cases)
    output_file = os.path.join("/home", admin_username, "test-result-{0}.xml".format(scenario_name))
    with open(output_file, 'w') as f:
        to_xml_report_file(f, [ts])
