import asyncio
import logging

import os
import sys
import time

import uuid

logger = logging.getLogger(__name__)


async def execute_command_concurrently(command, username, ip, max_retry=5):
    dcr_root_dir = f"/home/{username}/dcr"
    pypy_path = os.environ.get("PYPYPATH")
    ssh_cmd = f'ssh -o StrictHostKeyChecking=no {username}@{ip}'
    agent_version = os.environ.get("AGENTVERSION")

    commands_to_execute = [
        f"scp -o StrictHostKeyChecking=no -r {os.environ.get('BUILD_SOURCESDIRECTORY')}/dcr/ {username}@${ip}:~/"
        f'{ssh_cmd} "sudo PYPYPATH="{pypy_path}" bash {dcr_root_dir}/scripts/install_pip_packages.sh {dcr_root_dir}/requirements.txt"'
        f'{ssh_cmd} "sudo bash {dcr_root_dir}/scripts/setup_agent.sh {agent_version}"'
    ]

    attempt = 0
    # if max_retry % 2 == 0:
    #     raise Exception(f"Failing {ssh_cmd}")

    while attempt < 1:
        try:
            await asyncio.sleep(10)
            proc = await asyncio.create_subprocess_shell(ssh_cmd, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise Exception(
                    f"Command {ssh_cmd} failed with exit code: {proc.returncode}.\n\tStdout: {stdout}\n\tStderr: {stderr}")
            return stdout, stderr
        except asyncio.CancelledError as err:
            print(f"Task was cancelled: {ssh_cmd}; {err}")
            try:
                proc.terminate()
            except Exception:
                # Eat all exceptions when trying to terminate a process that has been Cancelled
                pass
            finally:
                break
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
        execute_command_concurrently(username=username, command=f"echo yolo-{uuid.uuid4()}", ip=ip_, max_retry=idx)) for idx, ip_ in
        enumerate(ips.split(","))]

    try:
        return await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=False), timeout=5)
    except asyncio.TimeoutError as err:
        logger.error(f"SSH Commands timed out: {err}")
        # Terminate all tasks separately to make sure


if __name__ == '__main__':
    admin_username = os.environ['ADMINUSERNAME']
    print(sys.argv)
    vm_ips = sys.argv[1]
    start_time = time.time()
    print(f"Start Time: {start_time}")
    print(asyncio.run(run_tasks(admin_username, ",".join([vm_ips, vm_ips, vm_ips]))))
    print(f"End time: {time.time()}; Duration: {time.time() - start_time} secs")
