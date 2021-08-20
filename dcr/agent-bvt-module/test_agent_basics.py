import os
import socket

from dcr.scenario_utils.common_utils import execute_command_and_raise_on_error


def test_agent_version():
    stdout, _ = execute_command_and_raise_on_error(['waagent', '-version'], timeout=30)

    # release_file contains:
    # AGENT_VERSION = 'x.y.z'
    expected_version = 'unknown'
    release_file = '/etc/agent-release'

    if os.path.exists(release_file):
        with open(release_file, 'r') as rfh:
            expected_version = rfh.read().strip()

    if "Goal state agent: {0}".format(expected_version) not in stdout:
        raise Exception("expected version {0} not found".format(expected_version))

    return stdout


def check_hostname():
    vm_name = os.environ['VMNAME']
    stdout, _ = execute_command_and_raise_on_error(['hostname'], timeout=30)

    if vm_name.lower() != stdout.lower():
        raise Exception("Hostname does not match! Expected: {0}, found: {1}".format(vm_name, stdout.strip()))

    return stdout


def check_ns_lookup():
    hostname, _ = execute_command_and_raise_on_error(['hostname'], timeout=30)

    ip = socket.gethostbyname(hostname)
    msg = "Resolved IP: {0}".format(ip)
    print(msg)

    return msg


def check_root_login():
    stdout, _ = execute_command_and_raise_on_error(['cat', '/etc/shadow'], timeout=30)
    root_passwd_line = next(line for line in stdout.splitlines() if 'root' in line)
    print(root_passwd_line)
    root_passwd = root_passwd_line.split(":")[1]

    if "!" in root_passwd or "*" in root_passwd:
        return 'root login disabled'
    else:
        raise Exception('root login appears to be enabled: {0}'.format(root_passwd))
