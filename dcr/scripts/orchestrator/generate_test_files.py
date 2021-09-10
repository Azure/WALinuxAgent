import os
from junit_xml import to_xml_report_file, TestSuite, TestCase


def read_file(filepath, raise_error=True):
    if not os.path.exists(filepath):
        if raise_error:
            raise FileNotFoundError
        else:
            return None

    with open(filepath, 'r', encoding='utf-8') as in_file:
        return in_file.read()


def main():

    scenario_name = os.environ['SCENARIONAME']
    artifact_dir = os.environ['BUILD_ARTIFACTSTAGINGDIRECTORY']

    print("Scenario Name: {0}; Build Artifact Dir: {1}".format(scenario_name, artifact_dir))

    tests_log_dir = os.path.join(artifact_dir, "tests")
    if not os.path.exists(tests_log_dir) or not any(os.listdir(tests_log_dir)):
        raise FileNotFoundError("Log Dir {0} not found".format(tests_log_dir))

    test_cases = []
    for test in os.listdir(tests_log_dir):
        stdout = read_file(os.path.join(tests_log_dir, test, "stdout"), raise_error=False)
        stderr = read_file(os.path.join(tests_log_dir, test, "stderr"), raise_error=False)
        tc = TestCase(test, stdout=stdout, stderr=stderr)

        if os.path.exists(os.path.join(tests_log_dir, test, "returncode")):
            tc.add_error_info("ExitCode: {0}\nSTDOUT: {1}\nSTDERR: {2}".format(
                read_file(os.path.join(tests_log_dir, test, "returncode")), stdout, stderr))
        test_cases.append(tc)

    ts = TestSuite(scenario_name, test_cases)

    output_file = os.path.join(artifact_dir, "test-result-{0}.xml".format(scenario_name))
    with open(output_file, 'w') as f:
        to_xml_report_file(f, [ts])


if __name__ == "__main__":
    main()
