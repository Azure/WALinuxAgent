import os
import time
import traceback
from typing import List

from junit_xml import TestCase, TestSuite, to_xml_report_file


class TestObj:
    def __init__(self, test_name, test_func, raise_on_error=False):
        self.name = test_name
        self.func = test_func
        self.raise_on_error = raise_on_error


class TestOrchestrator:
    def __init__(self, tests: List[TestObj]):
        self.tests = tests
        self.test_cases = []

    def run_tests(self):
        skip_due_to = None
        for test in self.tests:
            if skip_due_to is not None:
                tc = TestCase(test.name, classname=os.environ['SCENARIONAME'])
                tc.add_skipped_info(message=f"Skipped due to failing test: {skip_due_to}")
            else:
                tc = run_test_and_get_tc(test.name, test.func)
                if test.raise_on_error and (tc.is_error() or tc.is_failure()):
                    print(f"Breaking test case failed: {test.name}; Skipping remaining tests")
                    skip_due_to = test.name
            self.test_cases.append(tc)

    def generate_report(self, suite_name, test_file_path):
        ts = TestSuite(suite_name, test_cases=self.test_cases)
        with open(test_file_path, 'w') as f:
            to_xml_report_file(f, [ts])


def run_test_and_get_tc(test_name, test_func, *args) -> TestCase:
    stdout = ""
    tc = TestCase(test_name, classname=os.environ['SCENARIONAME'])
    start_time = time.time()
    print("---" * 20)
    print("TestName: {0}".format(test_name))
    try:
        stdout = test_func(*args)
        print("\tDebug Output: {0}".format(test_name, stdout))
    except Exception as err:
        print("\tError: {1}".format(test_name, err))
        tc.add_failure_info(err, output=traceback.print_exc())

    tc.stdout = stdout
    tc.elapsed_sec = (time.time() - start_time)
    return tc