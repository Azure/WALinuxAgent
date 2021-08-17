from test_agent_version import test_agent_version
from run_cse_tests import execute_cse_tests

if __name__ == '__main__':
    # Test 1
    stdout, stderr = test_agent_version()
    print("Stdout: {0}\nStderr: {1}".format(stdout, stderr))

    # Test 2
    execute_cse_tests()
    print("CSE Tests ran fine!")
