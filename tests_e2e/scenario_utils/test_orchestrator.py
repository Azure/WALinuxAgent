import os
import time
import traceback
from typing import List

from dotenv import load_dotenv
from junitparser import TestCase, Skipped, Failure, TestSuite, JUnitXml

from dcr.scenario_utils.logging_utils import LoggingHandler
from dcr.scenario_utils.models import get_vm_data_from_env


class TestFuncObj:
    def __init__(self, test_name, test_func, raise_on_error=False, retry=1):
        self.name = test_name
        self.func = test_func
        self.raise_on_error = raise_on_error
        self.retry = retry


class TestOrchestrator(LoggingHandler):
    def __init__(self, name: str, tests: List[TestFuncObj]):
        super().__init__()
        self.name = name
        self.__tests: List[TestFuncObj] = tests
        self.__test_suite = TestSuite(name)

    def run_tests(self):
        load_dotenv()
        skip_due_to = None
        for test in self.__tests:
            tc = TestCase(test.name, classname=os.environ['SCENARIONAME'])
            if skip_due_to is not None:
                tc.result = [Skipped(message=f"Skipped due to failing test: {skip_due_to}")]
            else:
                attempt = 1
                while attempt <= test.retry:
                    print(f"##[group][{test.name}] - Attempts ({attempt}/{test.retry})")
                    tc = self.run_test_and_get_tc(test.name, test.func)
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
            self.__test_suite.add_testcase(tc)

    def __generate_report(self, test_file_path):
        xml_junit = JUnitXml()
        xml_junit.add_testsuite(self.__test_suite)
        xml_junit.write(filepath=test_file_path, pretty=True)

    def generate_report_on_orchestrator(self, file_name: str):
        """
        Use this function to generate Junit XML report on the orchestrator.
        The report is dropped in `$(Build.ArtifactStagingDirectory)/harvest` directory
        """
        assert file_name.startswith("test-result"), "File name is invalid, it should start with test-result*"
        self.__generate_report(os.path.join(os.environ['BUILD_ARTIFACTSTAGINGDIRECTORY'], file_name))

    def generate_report_on_vm(self, file_name):
        """
        Use this function to generate Junit XML report on the Test VM.
        The report is dropped in `/home/$(adminUsername)/` directory
        """
        assert file_name.startswith("test-result"), "File name is invalid, it should start with test-result*"
        admin_username = get_vm_data_from_env().admin_username
        self.__generate_report(os.path.join("/home", admin_username, file_name))

    @property
    def failed(self) -> bool:
        return (self.__test_suite.failures + self.__test_suite.errors) > 0

    def run_test_and_get_tc(self, test_name, test_func) -> TestCase:
        tc = TestCase(test_name, classname=os.environ['SCENARIONAME'])
        start_time = time.time()
        self.log.info("Execute Test: {0}".format(test_name))
        try:
            stdout = test_func()
            self.log.debug("[{0}] Debug Output: {1}".format(test_name, stdout))
        except Exception as err:
            self.log.exception("Error: {1}".format(test_name, err))
            stdout = str(err)
            tc.result = [Failure(f"Failure: {err}", type_=f"Stack: {traceback.format_exc()}")]

        tc.system_out = stdout
        tc.time = (time.time() - start_time)
        return tc

