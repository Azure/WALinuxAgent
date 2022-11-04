import os
import time

from tests_e2e.common_utils.utils import execute_commands_on_test_vms
from tests_e2e.common_utils.logging_utils import get_logger

logger = get_logger("tests_e2e.common_utils.execute_ssh_on_vm")


class Tasks:
    harvest = "harvest"


def run_tasks(task: str):
    sources_dir = os.environ.get('BUILD_SOURCESDIRECTORY')
    artifact_dir = os.environ.get('BUILD_ARTIFACTSTAGINGDIRECTORY')
    identity_file = os.environ.get('SSHKEY_SECUREFILEPATH')
    ssh_cmd = f'ssh -i {identity_file} -o StrictHostKeyChecking=no {{username}}@{{ip}}'
    if task == Tasks.harvest:
        commands = [
            f"bash {sources_dir}/tests_e2e/scripts/harvest.sh {{username}} {{ip}} {artifact_dir}/harvest"
        ]
        execute_commands_on_test_vms(commands=commands)
    else:
        cmd = f'{ssh_cmd} "{task}"'
        execute_commands_on_test_vms(commands=[cmd])


def execute_run(task):
    start_time = time.time()
    logger.info(f"Start Time: {start_time}")
    try:
        run_tasks(task)
    finally:
        logger.info(f"End time: {time.time()}; Duration: {time.time() - start_time} secs")
