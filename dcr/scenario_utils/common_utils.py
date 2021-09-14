import asyncio
import logging
import math
import os
import secrets
import subprocess
from typing import List

from dcr.scenario_utils.models import get_vm_data_from_env

logger = logging.getLogger(__name__)


def execute_command_and_raise_on_error(command, shell=False, timeout=None, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE):
    pipe = subprocess.Popen(command, shell=shell, stdout=stdout, stderr=stderr)
    stdout, stderr = pipe.communicate(timeout=timeout)

    print("STDOUT:\n{0}".format(stdout.decode()))
    print("STDERR:\n{0}".format(stderr.decode()))
    if pipe.returncode != 0:
        raise Exception("non-0 exit code: {0} for command: {1}".format(pipe.returncode, command))

    return stdout.decode().strip(), stderr.decode().strip()


def execute_py_script_over_ssh_on_test_vms(command: str):
    """
    Execute a python script over SSH on test VMs. If there are multiple VMs, this will execute the script on all VMs concurrently.
    The script should be relative to the dcr/ directory.
    Prints the stdout/stderr of the script
    raises: Exception if any script exits with non-0 exit code.
    """
    ssh_cmd = f"ssh -o StrictHostKeyChecking=no {{username}}@{{ip}} sudo PYTHONPATH=. {os.environ['PYPYPATH']} /home/{{username}}/{command}"
    print(asyncio.run(execute_commands_concurrently_on_test_vms([ssh_cmd])))


def random_alphanum(length: int) -> str:
    if length == 0:
        return ''
    elif length < 0:
        raise ValueError('negative argument not allowed')
    else:
        text = secrets.token_hex(nbytes=math.ceil(length / 2))
        is_length_even = length % 2 == 0
        return text if is_length_even else text[1:]


async def execute_commands_concurrently_on_test_vms(commands: List[str], timeout: int = 5):
    vm_data = get_vm_data_from_env()
    tasks = [
        asyncio.create_task(_execute_commands_on_vm_async(commands=commands, username=vm_data.admin_username, ip=ip_))
        for ip_ in vm_data.ips]
    return await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=False), timeout=timeout * 60)


async def _execute_commands_on_vm_async(commands: List[str], username: str, ip: str, max_retry: int = 5):
    """
    Execute the list of commands synchronously on the VM. This runs as an async operation.
    The code also replaces the {username} and {ip} in the command string with their actual values before executing the command.
    """
    attempt = 0

    for command in commands:
        cmd = command.format(ip=ip, username=username)
        while attempt < max_retry:
            try:
                proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE,
                                                             stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await proc.communicate()
                if proc.returncode != 0:
                    raise Exception(
                        f"Command {cmd} failed with exit code: {proc.returncode}.\n\tStdout: {stdout}\n\tStderr: {stderr}")

                print(f"Command: {cmd}\n\tSTDOUT: {stdout}\n\tSTDERR: {stderr}")
                break

            except asyncio.CancelledError as err:
                logger.warning(f"Task was cancelled: {cmd}; {err}")
                try:
                    proc.terminate()
                except:
                    # Eat all exceptions when trying to terminate a process that has been Cancelled
                    pass
                finally:
                    return
            except Exception as err:
                attempt += 1
                if attempt < max_retry:
                    logger.warning(f"({attempt}/{max_retry}) Failed to execute command: {err}. Retrying in 3 secs",
                                   exc_info=True)
                    await asyncio.sleep(3)
                else:
                    raise
