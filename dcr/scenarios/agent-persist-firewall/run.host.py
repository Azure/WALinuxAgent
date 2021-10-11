import asyncio
import os
import time

from dcr.scenario_utils.azure_models import ComputeManager
from dcr.scenario_utils.common_utils import execute_py_script_over_ssh_on_test_vms, \
    execute_commands_concurrently_on_test_vms

from persist_firewall_helpers import SVG_DIR


def get_svg_files():
    harvest_dir = os.path.join(os.environ['BUILD_ARTIFACTSTAGINGDIRECTORY'], "harvest")
    scp_cmd = f"scp -o StrictHostKeyChecking=no {{username}}@{{ip}}:{SVG_DIR} {harvest_dir}"
    asyncio.run(execute_commands_concurrently_on_test_vms([scp_cmd]))


if __name__ == '__main__':
    # Execute run1.py first
    try:
        execute_py_script_over_ssh_on_test_vms(command="dcr/scenarios/agent-persist-firewall/run1.py")

        compute_manager = ComputeManager().compute_manager
        # Restart VM and wait for it to come back up
        compute_manager.restart()

        # Execute suite 2
        # Since the VM just restarted, wait for 10 secs before executing the script
        time.sleep(10)
        execute_py_script_over_ssh_on_test_vms(command="dcr/scenarios/agent-persist-firewall/run2.py")

        compute_manager.restart()

        # Execute suite 3
        # Since the VM just restarted, wait for 10 secs before executing the script
        time.sleep(10)
        execute_py_script_over_ssh_on_test_vms(command="dcr/scenarios/agent-persist-firewall/run3.py")
    finally:
        # Always try to fetch svg files off of the VM
        get_svg_files()

