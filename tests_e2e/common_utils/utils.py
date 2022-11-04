import subprocess
import time
from typing import List

from tests_e2e.common_utils.logging_utils import get_logger
from tests_e2e.scenario_utils.models import get_vm_data_from_env

logger = get_logger("tests_e2e.common_utils.utils")


def execute_commands_on_test_vms(commands: List[str]):
    vm_data = get_vm_data_from_env()
    for ip_ in vm_data.ips:
        _execute_commands_on_vm(commands=commands, username=vm_data.admin_username, ip=ip_)


def _execute_commands_on_vm(commands: List[str], username: str, ip: str, max_retry: int = 2):
    """
    Execute the list of commands on the VM.
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
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                stdout, stderr = proc.communicate()
                stdout = stdout.decode('utf-8')
                stderr = stderr.decode('utf-8')
                if proc.returncode != 0:
                    raise Exception(f"Failed command: {cmd}. Exit Code: {proc.returncode}")
                break

            except Exception as err:
                attempt += 1
                if attempt < max_retry:
                    logger.warning(f"[{username}/{ip}] ({attempt}/{max_retry}) Failed to execute command {cmd}: {err}. Retrying in 3 secs",
                                   exc_info=True)
                    time.sleep(3)
                else:
                    raise

            finally:
                logger.info(f"##[group][{username}/{ip}] - Attempts ({attempt}/{max_retry})")
                logger.info(f"##[command]{cmd}")
                if stdout:
                    logger.info(f"Stdout: {stdout}")
                if stderr:
                    logger.warning(f"Stderr: {stderr}")
                logger.info("##[endgroup]")
