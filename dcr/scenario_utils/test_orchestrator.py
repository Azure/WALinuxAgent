import logging
import os
import time
import traceback
from typing import List

# from junit_xml import TestCase, TestSuite, to_xml_report_file
from junitparser import TestCase, Skipped, Failure, TestSuite, JUnitXml

from dcr.scenario_utils.logging_utils import LoggingHandler


class TestObj:
    def __init__(self, test_name, test_func, raise_on_error=False, retry=1):
        self.name = test_name
        self.func = test_func
        self.raise_on_error = raise_on_error
        self.retry = retry


class TestOrchestrator(LoggingHandler):
    def __init__(self, name: str, tests: List[TestObj]):
        super().__init__()
        self.name = name
        self.__tests: List[TestObj] = tests
        self.__test_cases: List[TestCase] = []

    def run_tests(self):
        skip_due_to = None
        for test in self.__tests:
            tc = TestCase(test.name, classname=os.environ['SCENARIONAME'])
            if skip_due_to is not None:
                tc.result = [Skipped(message=f"Skipped due to failing test: {skip_due_to}")]
                # tc.add_skipped_info(message=f"Skipped due to failing test: {skip_due_to}")
            else:
                attempt = 1
                while attempt <= test.retry:
                    print(f"##[group][{test.name}] - Attempts ({attempt}/{test.retry})")
                    tc = self.run_test_and_get_tc(test.name, test.func)
                    # if tc.is_error() or tc.is_failure():
                    if isinstance(tc.result, Failure):
                        attempt += 1
                        if attempt > test.retry and test.raise_on_error:
                            self.log.warning(f"Breaking test case failed: {test.name}; Skipping remaining tests")
                            skip_due_to = test.name
                        else:
                            self.log.warning(f"(Attempt {attempt-1}/Total {test.retry}) Test {test.name} failed")
                            if attempt <= test.retry:
                                self.log.warning("retrying in 10 secs")
                                time.sleep(10)
                        print("##[endgroup]")
                    else:
                        print("##[endgroup]")
                        break
            self.__test_cases.append(tc)

    def generate_report(self, test_file_path):
        # ts = TestSuite(self.name, test_cases=self.__test_cases)
        # with open(test_file_path, 'w') as f:
        #     to_xml_report_file(f, [ts])

        ts = TestSuite(self.name)
        for tc in self.__test_cases:
            ts.add_testcase(tc)

        xml_junit = JUnitXml()
        xml_junit.add_testsuite(ts)
        xml_junit.write(filepath=test_file_path, pretty=True)

    @property
    def failed(self) -> bool:
        return any(isinstance(tc.result, Failure) for tc in self.__test_cases)
        # return any(tc.is_error() or tc.is_failure() for tc in self.__test_cases)

    def run_test_and_get_tc(self, test_name, test_func) -> TestCase:
        stdout = ""

        tc = TestCase(test_name, classname=os.environ['SCENARIONAME'])
        start_time = time.time()
        self.log.info("Execute Test: {0}".format(test_name))
        try:
            stdout = test_func()
            self.log.debug("[{0}] Debug Output: {1}".format(test_name, stdout))
        except Exception as err:
            self.log.exception("Error: {1}".format(test_name, err))
            tc.result = [Failure(f"Failure: {err}", type_=f"Stack: {traceback.format_exc()}")]
            # tc.add_failure_info(f"Error: {err}", output=f"Stack: {traceback.format_exc()}")

        # tc.stdout = stdout
        # tc.elapsed_sec = (time.time() - start_time)
        tc.system_out = stdout
        tc.time = (time.time() - start_time)
        return tc

