import asyncio
import logging

import os
import sys
import time

import uuid

logger = logging.getLogger(__name__)


async def execute_command_concurrently(command, username, ip, max_retry=5):
    ssh_cmd = f'ssh -o StrictHostKeyChecking=no {username}@{ip} "{command}"'
    attempt = 0
    while attempt < max_retry:
        try:
            proc = await asyncio.create_subprocess_shell(ssh_cmd, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise Exception(
                    f"Command {ssh_cmd} failed with exit code: {proc.returncode}.\n\tStdout: {stdout}\n\tStderr: {stderr}")
            return stdout, stderr
        except Exception as err:
            attempt += 1
            if attempt < max_retry:
                logger.warning(f"({attempt}/{max_retry}) Failed to execute command: {err}. Retrying in 3 secs",
                               exc_info=True)
                await asyncio.sleep(3)
            else:
                raise


async def run_tasks(username, ips):
    tasks = [asyncio.create_task(
        execute_command_concurrently(username=username, command=f"echo yolo-{uuid.uuid4()}", ip=ip_)) for ip_ in
        ips.split(",")]

    return await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == '__main__':
    admin_username = os.environ['ADMINUSERNAME']
    vm_ips = os.environ['ARMDEPLOYMENTOUTPUT_HOSTNAME_VALUE']
    print(sys.argv)
    start_time = time.time()
    print(f"Start Time: {start_time}")
    print(asyncio.run(run_tasks(admin_username, ",".join([vm_ips, vm_ips, vm_ips]))))
    print(f"End time: {time.time()}; Duration: {time.time() - start_time} secs")
