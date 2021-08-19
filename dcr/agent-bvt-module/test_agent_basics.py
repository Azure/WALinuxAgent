import os
import socket

from dcr.scenario_utils.common_utils import execute_command_and_raise_on_error


def test_agent_version():
    stdout, stderr = execute_command_and_raise_on_error(['waagent', '-version'], timeout=30)

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


def check_hostname():
    vm_name = os.environ['VMNAME']
    stdout, stderr = execute_command_and_raise_on_error(['hostname'], timeout=30)

    if vm_name.lower() != stdout.lower():
        raise Exception("Hostname does not match! Expected: {0}, found: {1}".format(vm_name, stdout.strip()))

    return stdout, stderr


def check_ns_lookup():
    hostname, stderr = execute_command_and_raise_on_error(['hostname'], timeout=30)

    try:
        ip = socket.gethostbyname(hostname)
        msg = "Resolved IP: {0}".format(ip)
        print(msg)
    except Exception as e:
        err = "[ERROR] Ran into exception: {0}".format(e)
        print(err)
        return "", err

    return msg, ""


def check_root_login():
    stdout, stderr = execute_command_and_raise_on_error(['cat', '/etc/shadow'], timeout=30)
    root_passwd = [line for line in stdout if 'root' in line][0].split(":")[1]

    if "!" in root_passwd or "*" in root_passwd:
        return 'root login disabled', ""
    else:
        raise Exception('root login appears to be enabled: {0}'.format(root_passwd))
