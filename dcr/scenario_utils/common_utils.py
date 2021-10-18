import asyncio
import math
import os
import secrets
import subprocess
import time
from datetime import datetime
from typing import List

from dcr.scenario_utils.distro import get_distro
from dcr.scenario_utils.logging_utils import get_logger
from dcr.scenario_utils.models import get_vm_data_from_env

logger = get_logger("dcr.scenario_utils.common_utils")


def get_current_agent_name(distro_name=None):
    """
    Only Ubuntu and Debian used walinuxagent, everyone else uses waagent.
    Note: If distro_name is not specified, we will search the distro in the VM itself
    :return: walinuxagent or waagent
    """

    if distro_name is None:
        distro_name = get_distro()[0]

    walinuxagent_distros = ["ubuntu", "debian"]
    if any(dist.lower() in distro_name.lower() for dist in walinuxagent_distros):
        return "walinuxagent"

    return "waagent"


def execute_command_and_raise_on_error(command, shell=False, timeout=None, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE):
    pipe = subprocess.Popen(command, shell=shell, stdout=stdout, stderr=stderr)
    stdout, stderr = pipe.communicate(timeout=timeout)

    logger.info("STDOUT:\n{0}".format(stdout.decode()))
    logger.info("STDERR:\n{0}".format(stderr.decode()))
    if pipe.returncode != 0:
        raise Exception("non-0 exit code: {0} for command: {1}".format(pipe.returncode, command))

    return stdout.decode().strip(), stderr.decode().strip()


def execute_py_script_over_ssh_on_test_vms(command: str):
    """
    Execute a python script over SSH on test VMs. If there are multiple VMs, this will execute the script on all VMs concurrently.
    The script should be relative to the dcr/ directory. It uses the PyPy interpreter to execute the script and
    logs the stdout/stderr of the script
    raises: Exception if any script exits with non-0 exit code.
    """
    ssh_cmd = f"ssh -o StrictHostKeyChecking=no {{username}}@{{ip}} sudo PYTHONPATH=. {os.environ['PYPYPATH']} /home/{{username}}/{command}"
    asyncio.run(execute_commands_concurrently_on_test_vms([ssh_cmd]))
    logger.info(f"Finished executing SSH command: {ssh_cmd}")


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
        stdout, stderr = "", ""
        # ToDo: Separate out retries due to network error vs retries due to test failures.
        #  The latter should be only once (or as specified by the test author).
        #  https://msazure.visualstudio.com/One/_workitems/edit/12377120
        while attempt < max_retry:
            try:
                proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE,
                                                             stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await proc.communicate()
                stdout = stdout.decode('utf-8')
                stderr = stderr.decode('utf-8')
                if proc.returncode != 0:
                    raise Exception(f"Failed command: {cmd}. Exit Code: {proc.returncode}")
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
                    logger.warning(f"[{username}/{ip}] ({attempt}/{max_retry}) Failed to execute command {cmd}: {err}. Retrying in 3 secs",
                                   exc_info=True)
                    await asyncio.sleep(3)
                else:
                    raise

            finally:
                print(f"##[group][{username}/{ip}] - Attempts ({attempt}/{max_retry})")
                print(f"##[command]{cmd}")
                if stdout:
                    logger.info(f"Stdout: {stdout}")
                if stderr:
                    logger.warning(f"Stderr: {stderr}")
                print("##[endgroup]")


def execute_with_retry(func, max_retry=3, sleep=5):
    retry = 0
    while retry < max_retry:
        try:
            func()
            return
        except Exception as error:
            print("{0} Op failed with error: {1}. Retry: {2}, total attempts: {3}".format(datetime.utcnow().isoformat(),
                                                                                          error, retry + 1, max_retry))
            retry += 1
            if retry < max_retry:
                time.sleep(sleep)
                continue
            raise


def read_file(log_file):
    if not os.path.exists(log_file):
        raise Exception("{0} file not found!".format(log_file))

    with open(log_file) as f:
        lines = list(map(lambda _: _.strip(), f.readlines()))

    return lines
