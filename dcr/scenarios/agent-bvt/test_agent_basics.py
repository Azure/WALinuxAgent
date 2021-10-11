import os
import re
import socket

from dotenv import load_dotenv

from dcr.scenario_utils.common_utils import execute_command_and_raise_on_error
from dcr.scenario_utils.models import get_vm_data_from_env


def test_agent_version():
    stdout, _ = execute_command_and_raise_on_error(['waagent', '-version'], timeout=30)

    # release_file contains:
    # AGENT_VERSION = 'x.y.z'
    load_dotenv()
    expected_version = os.environ.get("AGENTVERSION")

    if "Goal state agent: {0}".format(expected_version) not in stdout:
        raise Exception("expected version {0} not found".format(expected_version))

    return stdout


def check_hostname():
    vm_name = get_vm_data_from_env().name
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


def check_agent_processes():
    daemon_pattern = r'.*python.*waagent -daemon$'
    handler_pattern = r'.*python.*-run-exthandlers'
    status_pattern = r'^(\S+)\s+'

    std_out, _ = execute_command_and_raise_on_error(['ps', 'axo', 'stat,args'], timeout=30)

    daemon = False
    ext_handler = False
    agent_processes = [line for line in std_out.splitlines() if 'python' in line]

    for process in agent_processes:
        if re.match(daemon_pattern, process):
            daemon = True
        elif re.match(handler_pattern, process):
            ext_handler = True
        else:
            continue

        status = re.match(status_pattern, process).groups(1)[0]
        if not(status.startswith('S') or status.startswith('R')):
            raise Exception('process is not running: {0}'.format(process))

    if not daemon:
        raise Exception('daemon process not found:\n\n{0}'.format(std_out))
    if not ext_handler:
        raise Exception('extension handler process not found:\n\n{0}'.format(std_out))

    return 'expected processes found running'


def check_sudoers(user):
    found = False
    root = '/etc/sudoers.d/'

    for f in os.listdir(root):
        sudoers = os.path.join(root, f)
        with open(sudoers) as fh:
            for entry in fh.readlines():
                if entry.startswith(user) and 'ALL=(ALL)' in entry:
                    print('entry found: {0}'.format(entry))
                    found = True

    if not found:
        raise Exception('user {0} not found'.format(user))

    return "Found user {0} in list of sudoers".format(user)
