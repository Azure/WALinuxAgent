import subprocess

import os
import sys

from dcr.scenario_utils.common_utils import execute_command_and_raise_on_error

if __name__ == '__main__':
    print(os.environ["HOME"])
    username = os.environ["ADMINUSERNAME"]
    host = os.environ["ARMDEPLOYMENTOUTPUT_HOSTNAME_VALUE"]
    pypy_path = os.environ["AGENTZIP_PYPYPATH"]

    stdout, stderr = execute_command_and_raise_on_error('ssh -o StrictHostKeyChecking=no {0}@{1} "sudo bash /home/{0}/dcr/scripts/run_pytest.sh /home/{0}/ {2}"'.format(username, host, pypy_path), shell=True)
