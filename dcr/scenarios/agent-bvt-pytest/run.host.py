import subprocess

import os

if __name__ == '__main__':
    username = os.environ["ADMINUSERNAME"]
    host = os.environ["ARMDEPLOYMENTOUTPUT_HOSTNAME_VALUE"]
    popen = subprocess.Popen('ssh -o StrictHostKeyChecking=no {0}@{1} "sudo bash /home/{0}/dcr/scripts/run_pytest.sh /home/{0}/test_results"'.format(username, host), shell=True)
    stdout, stderr = popen.communicate(timeout=5 * 60)

    print("RC: {0}\n\tSTDOUT: {1}\n\tSTDERR: {2}".format(popen.returncode, stdout, stderr))
