import asyncio
import logging

import os
import sys
import time


from typing import List

logger = logging.getLogger(__name__)


async def execute_command_concurrently(commands: List[str], ip: str, max_retry: int = 5):
    attempt = 0

    for command in commands:
        cmd = command.format(ip=ip)
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
                print(f"Task was cancelled: {cmd}; {err}")
                try:
                    proc.terminate()
                except Exception:
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


def get_ips() -> list:

    if os.path.exists(f"{os.environ['BUILD_SOURCESDIRECTORY']}/dcr/.vm_ips"):
        with open(f"{os.environ['BUILD_SOURCESDIRECTORY']}/dcr/.vm_ips", 'r') as vm_ips:
            vms = [ip.strip() for ip in vm_ips.readlines()]
            logger.info(f"VMIps: {', '.join(vms)}")

    if os.path.exists(f"{os.environ['BUILD_SOURCESDIRECTORY']}/dcr/.vmss_ips"):
        with open(f"{os.environ['BUILD_SOURCESDIRECTORY']}/dcr/.vmss_ips", 'r') as vmss_ips:
            vmss = [ip.strip() for ip in vmss_ips.readlines()]
            logger.info(f"VMSSIps: {', '.join(vmss)}")

    return vms + vmss


async def run_tasks(username, command):
    ips = get_ips()
    ssh_cmd = f'ssh -o StrictHostKeyChecking=no {username}@{{ip}}'

    if command == "setup_vm":
        dcr_root_dir = f"/home/{username}/dcr"
        pypy_path = os.environ.get("PYPYPATH")
        agent_version = os.environ.get("AGENTVERSION")

        setup_commands = [
            f"scp -o StrictHostKeyChecking=no -r {os.environ.get('BUILD_SOURCESDIRECTORY')}/dcr/ {username}@${{ip}}:~/",
            f'{ssh_cmd} "sudo PYPYPATH="{pypy_path}" bash {dcr_root_dir}/scripts/install_pip_packages.sh {dcr_root_dir}/requirements.txt"',
            f'{ssh_cmd} "sudo bash {dcr_root_dir}/scripts/setup_agent.sh {agent_version}"'
        ]
        tasks = [asyncio.create_task(execute_command_concurrently(commands=setup_commands, ip=ip_)) for ip_ in ips]
    else:
        cmd = f'{ssh_cmd} "{command}"'
        tasks = [asyncio.create_task(execute_command_concurrently(commands=[cmd], ip=ip_)) for ip_ in ips]

    return await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=False), timeout=10 * 60)


if __name__ == '__main__':
    admin_username = os.environ['ADMINUSERNAME']
    print(sys.argv)
    start_time = time.time()
    print(f"Start Time: {start_time}")
    try:
        print(asyncio.run(run_tasks(admin_username, sys.argv[1])))
    finally:
        print(f"End time: {time.time()}; Duration: {time.time() - start_time} secs")
