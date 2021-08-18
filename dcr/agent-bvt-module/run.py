import os
import time

from dotenv import load_dotenv
from junit_xml import TestCase, TestSuite, to_xml_report_file

from test_agent_version import test_agent_version
from run_cse_tests import execute_cse_tests


def run_test_and_report(test_name, test_func, *args):
    stdout, stderr = "", ""
    tc = TestCase(test_name)
    start_time = time.time()
    try:
        stdout, stderr = test_func(*args)
    except Exception as err:
        tc.add_error_info(err)

    tc.stdout = stdout
    tc.stderr = stderr
    tc.elapsed_sec = (time.time() - start_time)
    return tc


if __name__ == '__main__':
    # Environ vars
    load_dotenv()
    scenario_name = os.environ['SCENARIONAME']
    admin_username = os.environ['ADMINUSERNAME']

    test_cases = [run_test_and_report("check_agent_version", test_agent_version),
                  run_test_and_report("execute CSE", execute_cse_tests)]

    ts = TestSuite(scenario_name, test_cases=test_cases)
    output_file = os.path.join("home", admin_username, "test-result-{0}.xml".format(scenario_name))
    with open(output_file, 'w') as f:
        to_xml_report_file(f, [ts])
