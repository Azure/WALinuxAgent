import asyncio
import os
import sys
import time

from enum import Enum

from dcr.scenario_utils.common_utils import execute_commands_concurrently_on_test_vms
from dcr.scenario_utils.logging_utils import get_logger

logger = get_logger("dcr.scripts.orchestrator.execute_ssh_on_vm")


class SetupCommands:
    setup_vm = "setup_vm"
    fetch_results = "fetch_results"
    harvest = "harvest"


async def run_tasks(command: str):
    ssh_cmd = f'ssh -o StrictHostKeyChecking=no {{username}}@{{ip}}'
    sources_dir = os.environ.get('BUILD_SOURCESDIRECTORY')
    artifact_dir = os.environ.get('BUILD_ARTIFACTSTAGINGDIRECTORY')

    if command == SetupCommands.setup_vm:
        dcr_root_dir = f"/home/{{username}}/dcr"
        pypy_path = os.environ.get("PYPYPATH")
        agent_version = os.environ.get("AGENTVERSION")

        setup_commands = [
            f"scp -o StrictHostKeyChecking=no -r {sources_dir}/dcr/ {{username}}@{{ip}}:~/",
            f'{ssh_cmd} "sudo PYPYPATH={pypy_path} bash {dcr_root_dir}/scripts/install_pip_packages.sh {dcr_root_dir}/requirements.txt"',
            f'{ssh_cmd} "sudo bash {dcr_root_dir}/scripts/setup_agent.sh {agent_version}"'
        ]
        return await execute_commands_concurrently_on_test_vms(commands=setup_commands, timeout=15)
    elif command == SetupCommands.fetch_results:
        commands = [
            f"scp -o StrictHostKeyChecking=no {{username}}@{{ip}}:~/test-result*.xml {artifact_dir}"
        ]
        try:
            # Try fetching test results in a best effort scenario, if unable to fetch, dont throw an error
            return await execute_commands_concurrently_on_test_vms(commands=commands, timeout=15)
        except Exception as err:
            logger.warning(f"Unable to fetch test results; Error: {err}", exc_info=True)
    elif command == SetupCommands.harvest:
        commands = [
            f"bash {sources_dir}/dcr/scripts/test-vm/harvest.sh {{username}} {{ip}} {artifact_dir}/harvest"
        ]
        return await execute_commands_concurrently_on_test_vms(commands=commands, timeout=15)
    else:
        cmd = f'{ssh_cmd} "{command}"'
        return await execute_commands_concurrently_on_test_vms(commands=[cmd], timeout=15)


if __name__ == '__main__':
    start_time = time.time()
    print(f"Start Time: {start_time}")
    try:
        print(asyncio.run(run_tasks(command=sys.argv[1])))
    finally:
        print(f"End time: {time.time()}; Duration: {time.time() - start_time} secs")
