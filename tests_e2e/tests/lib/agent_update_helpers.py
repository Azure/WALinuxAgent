#
# Copyright 2018 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import json
import shutil
from pathlib import Path
from threading import RLock

from assertpy import fail

import azurelinuxagent
import requests
from azure.mgmt.compute.models import VirtualMachine

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false
from tests_e2e.tests.lib.shell import run_command
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient

# Helper methods for agent update/publish tests


def verify_agent_update_flag_enabled(vm: VirtualMachineClient) -> bool:
    result: VirtualMachine = vm.get_model()
    flag: bool = result.os_profile.linux_configuration.enable_vm_agent_platform_updates
    if flag is None:
        return False
    return flag


def enable_agent_update_flag(vm: VirtualMachineClient) -> None:
    osprofile = {
        "location": vm.location,  # location is required field
        "properties": {
            "osProfile": {
                "linuxConfiguration": {
                    "enableVMAgentPlatformUpdates": True
                }
            }
        }
    }
    log.info("updating the vm with osProfile property:\n%s", osprofile)
    vm.update(osprofile)


def request_rsm_update(requested_version: str, vm: VirtualMachineClient, arch_type: str, is_downgrade: bool, downgrade_from: str = "9.9.9.9") -> None:
    """
    This method is to simulate the rsm request.
    First we ensure the PlatformUpdates enabled in the vm and then make a request using rest api
    """
    if not verify_agent_update_flag_enabled(vm):
        # enable the flag
        log.info("Attempting vm update to set the enableVMAgentPlatformUpdates flag")
        enable_agent_update_flag(vm)
        log.info("Updated the enableVMAgentPlatformUpdates flag to True")
    else:
        log.info("Already enableVMAgentPlatformUpdates flag set to True")

    if arch_type == "aarch64":
        data = {
            "target": "Microsoft.OSTCLinuxAgent.ARM64Test",
            "targetVersion": requested_version
        }
    else:
        data = {
            "target": "Microsoft.OSTCLinuxAgent.Test",
            "targetVersion": requested_version
        }

    if is_downgrade:
        data.update({"isEmergencyRollbackRequest": True})
        data.update({"badVersion": downgrade_from})

    log.info("Attempting rsm upgrade post request with data: {0}".format(data))
    request = vm.create_resource_manager_request(requests.post, 'UpgradeVMAgent?api-version=2022-08-01')  # Later this api call will be replaced by azure-python-sdk wrapper
    response = request(data=json.dumps(data), timeout=300)
    if response.status_code == 202:
        log.info("RSM upgrade request accepted")
    else:
        raise Exception("Error occurred while making RSM upgrade request. Status code : {0} and msg: {1}".format(
            response.status_code, response.content))


def verify_current_agent_version(ssh_client: SshClient, requested_version: str) -> None:
    """
    Verify current agent version running on requested version
    """

    def _check_agent_version(version: str) -> bool:
        waagent_version: str = ssh_client.run_command("waagent-version", use_sudo=True)
        expected_version = f"Goal state agent: {version}"
        if expected_version in waagent_version:
            return True
        else:
            return False

    waagent_version: str = ""
    log.info("Verifying agent updated to published version: {0}".format(requested_version))
    success: bool = retry_if_false(lambda: _check_agent_version(requested_version), delay=50)
    if not success:
        fail("Guest agent didn't update to published version {0} but found \n {1}. \n ".format(
            requested_version, waagent_version))
    waagent_version: str = ssh_client.run_command("waagent-version", use_sudo=True)
    log.info(
        f"Successfully verified agent updated to published version. Current agent version running:\n {waagent_version}")

def verify_agent_reported_supported_feature_flag(ssh_client: SshClient) -> None:
    """
    RSM update relies on the supported feature flag reported by the agent to CRP. This check ensures the Guest Agent correctly reports the feature flag in its status.
    """
    log.info("Running remote script agent_update-verify_versioning_supported_feature.py to verify that the agent reports the supported feature flag required for CRP to send RSM update requests")
    ssh_client.run_command("agent_update-verify_versioning_supported_feature.py --supported True", use_sudo=True)
    log.info("Successfully verified that Agent reported VersioningGovernance supported feature flag")


_build_lock = RLock()


def build_agent_package(working_directory: Path, version: str, ssh_client, vm) -> str:
    """
    Builds a custom agent package from source with the specified version, then copies
    the resulting zip to the test VM. Returns the package file name.
    """
    pkg_name = f"WALinuxAgent-{version}.zip"
    with _build_lock:
        agent_source_path: Path = working_directory / "source"
        source_pkg_path: Path = agent_source_path / "eggs" / pkg_name
        if source_pkg_path.exists():
            log.info("The test pkg already exists at %s, skipping build", source_pkg_path)
        else:
            if agent_source_path.exists():
                shutil.rmtree(agent_source_path)
            source_directory: Path = Path(azurelinuxagent.__path__[0]).parent
            copy_cmd: str = f"cp -r {source_directory} {agent_source_path}"
            log.info("Copying agent source %s to %s", source_directory, agent_source_path)
            run_command(copy_cmd, shell=True)
            if not agent_source_path.exists():
                raise Exception(f"The agent source was not copied to the expected path {agent_source_path}")
            version_file: Path = agent_source_path / "azurelinuxagent" / "common" / "version.py"
            version_cmd = rf"""sed -E -i "s/^AGENT_VERSION\s+=\s+'[0-9.]+'/AGENT_VERSION = '{version}'/g" {version_file}"""
            log.info("Setting agent version to %s to build new pkg", version)
            run_command(version_cmd, shell=True)
            makepkg_file: Path = agent_source_path / "makepkg.py"
            build_cmd: str = f"env PYTHONPATH={agent_source_path} python3 {makepkg_file} -o {agent_source_path}"
            log.info("Building custom test agent pkg version %s", version)
            run_command(build_cmd, shell=True)
            if not source_pkg_path.exists():
                raise Exception(f"The test pkg was not created at the expected path {source_pkg_path}")
        target_path: Path = Path("~") / "tmp"
        log.info("Copying %s to %s:%s", source_pkg_path, vm, target_path)
        ssh_client.copy_to_node(source_pkg_path, target_path)
    return pkg_name
