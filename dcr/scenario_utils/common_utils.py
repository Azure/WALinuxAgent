import math
import os
import subprocess

import secrets

from dcr.scenario_utils.models import VMMetaData


def execute_command_and_raise_on_error(command, shell=False, timeout=None, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE):
    pipe = subprocess.Popen(command, shell=shell, stdout=stdout, stderr=stderr)
    stdout, stderr = pipe.communicate(timeout=timeout)

    print("STDOUT:\n{0}".format(stdout.decode()))
    print("STDERR:\n{0}".format(stderr.decode()))
    if pipe.returncode != 0:
        raise Exception("non-0 exit code: {0} for command: {1}".format(pipe.returncode, command))

    return stdout.decode().strip(), stderr.decode().strip()


def execute_py_command_on_vm(command: str, username: str = None, host: str = None):
    username = os.environ['ADMINUSERNAME'] if username is None else username
    host = os.environ['ARMDEPLOYMENTOUTPUT_HOSTNAME_VALUE'] if host is None else host
    ssh_cmd = f"ssh -o StrictHostKeyChecking=no {username}@{host} sudo PYTHONPATH=. {os.environ['PYPYPATH']} {command}"
    execute_command_and_raise_on_error(command=ssh_cmd, shell=True)


def get_vm_data_from_env() -> VMMetaData:
    rg_name = "{0}-{1}-{2}".format(os.environ['RGNAME'], os.environ['SCENARIONAME'], os.environ['DISTRONAME'])
    return VMMetaData(vm_name=os.environ["VMNAME"],
                      rg_name=rg_name,
                      sub_id=os.environ["SUBID"],
                      location=os.environ['LOCATION'])


def random_alphanum(length: int) -> str:
    if length == 0:
        return ''
    elif length < 0:
        raise ValueError('negative argument not allowed')
    else:
        text = secrets.token_hex(nbytes=math.ceil(length / 2))
        is_length_even = length % 2 == 0
        return text if is_length_even else text[1:]
