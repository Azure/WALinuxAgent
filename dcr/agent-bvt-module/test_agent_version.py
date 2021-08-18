import os
import subprocess


def test_agent_version():
    pipe = subprocess.Popen(['waagent', '-version'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout, stderr = pipe.communicate(timeout=30)

    print("STDOUT:\n{0}".format(stdout.decode()))
    print("STDERR:\n{0}".format(stderr.decode()))
    if pipe.returncode != 0:
        raise Exception("Unexpected error when fetching agent version")

    # release_file contains:
    # AGENT_VERSION = 'x.y.z'
    expected_version = 'unknown'
    release_file = '/etc/agent-release'
    release_pattern = "AGENT_VERSION = '(.*)'\n"
    if os.path.exists(release_file):
        with open(release_file, 'r') as rfh:
            expected_version = rfh.read().strip()

    if "Goal state agent: {0}".format(expected_version) not in stdout.decode():
        raise Exception("expected version {0} not found".format(expected_version))

    return stdout, stderr
