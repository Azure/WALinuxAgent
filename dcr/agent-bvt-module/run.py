from test_agent_version import test_agent_version

if __name__ == 'main':
    stdout, stderr = test_agent_version()
    print("Stdout: {0}\nStderr: {1}".format(stdout, stderr))
