import logging
import os
import time
import traceback
from typing import List

from junit_xml import TestCase, TestSuite, to_xml_report_file


class TestObj:
    def __init__(self, test_name, test_func, raise_on_error=False, retry=1):
        self.name = test_name
        self.func = test_func
        self.raise_on_error = raise_on_error
        self.retry = retry


class TestOrchestrator:
    def __init__(self, name: str, tests: List[TestObj]):
        self.name = name
        self.tests: List[TestObj] = tests
        self.test_cases: List[TestCase] = []
        self.__logger = logging.getLogger(self.__name__)

    def run_tests(self):
        skip_due_to = None
        for test in self.tests:
            tc = TestCase(test.name, classname=os.environ['SCENARIONAME'])
            if skip_due_to is not None:
                tc.add_skipped_info(message=f"Skipped due to failing test: {skip_due_to}")
            else:
                attempt = 1
                while attempt <= test.retry:
                    tc = self.run_test_and_get_tc(test.name, test.func)
                    if tc.is_error() or tc.is_failure():
                        attempt += 1
                        if attempt > test.retry and test.raise_on_error:
                            self.__logger.warning(f"Breaking test case failed: {test.name}; Skipping remaining tests")
                            skip_due_to = test.name
                        else:
                            self.__logger.warning(f"(Attempt {attempt-1}/Total {test.retry}) Test {test.name} failed")
                            if attempt > test.retry:
                                self.__logger.warning("retrying in 10 secs")
                                time.sleep(10)
                    else:
                        break
            self.test_cases.append(tc)

    def generate_report(self, test_file_path):
        ts = TestSuite(self.name, test_cases=self.test_cases)
        with open(test_file_path, 'w') as f:
            to_xml_report_file(f, [ts])

    @property
    def failed(self) -> bool:
        return any(tc.is_error() or tc.is_failure() for tc in self.test_cases)

    def run_test_and_get_tc(self, test_name, test_func) -> TestCase:
        stdout = ""

        tc = TestCase(test_name, classname=os.environ['SCENARIONAME'])
        start_time = time.time()
        print("---" * 20)
        self.__logger.info("TestName: {0}".format(test_name))
        try:
            stdout = test_func()
            self.__logger.info("Debug Output: {0}".format(test_name, stdout))
        except Exception as err:
            self.__logger.exception("Error: {1}".format(test_name, err))
            tc.add_failure_info(f"Error: {err}; Stack: {traceback.format_exc()}")

        tc.stdout = stdout
        tc.elapsed_sec = (time.time() - start_time)
        return tc

