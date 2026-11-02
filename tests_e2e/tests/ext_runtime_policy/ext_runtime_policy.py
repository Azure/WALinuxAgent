#!/usr/bin/env python3

# Microsoft Azure Linux Agent
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
import os
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List

from assertpy import assert_that, fail

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIdentifier


class ExtRuntimePolicy(AgentVmTest):
    """
    Validates the runtime policy feature for VM extensions:

    1. A policy-capable CSE receives a matching AllowedCommandToExecute policy and enables successfully.
    2. The agent refreshes the policy before re-enable, causing CSE to reject a command that is no longer allowed.
    3. Omitting runtimePolicy writes an empty policy, while removing the agent policy deletes the runtime policy file.
    4. Production CSE 2.0, which does not declare supportsPolicy, is blocked when runtime policy is configured.
    5. Production CSE 2.0, which does not declare supportsPolicy, is allowed when runtime policy is not configured.
    """
    _POLICY_FILE = "/etc/waagent_policy.json"
    _UNSUPPORTED_EXTENSION_OUTPUT = "/tmp/unsupported-extension-executed"

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def _create_policy_file(self, policy):
        """
        Create policy json file and copy to /etc/waagent_policy.json on test machine.
        """
        unique_id = uuid.uuid4()
        file_path = f"/tmp/waagent_policy_{unique_id}.json"
        with open(file_path, mode="w") as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            log.info(f"Policy file contents: {json.dumps(policy, indent=4)}")

            remote_path = "/tmp/waagent_policy.json"
            local_path = policy_file.name
            self._ssh_client.copy_to_node(local_path=local_path, remote_path=remote_path)
            log.info("Copying policy file to test VM [%s]", self._context.vm.name)
            self._ssh_client.run_command(f"mv {remote_path} {self._POLICY_FILE}", use_sudo=True)
        os.remove(file_path)

    def _set_runtime_policy(self, extension_name, runtime_policy=None):
        """
        Create an agent policy containing the given extension runtime policy. Pass None when the extension's
        runtimePolicy property should not be created.
        """
        extension_policy = {}
        if runtime_policy is not None:
            extension_policy["runtimePolicy"] = runtime_policy

        self._create_policy_file({
            "policyVersion": "0.1.0",
            "extensionPolicies": {
                "allowListedExtensionsOnly": False,
                "extensions": {
                    extension_name: extension_policy
                }
            }
        })

    def _enable_cse(self, extension, timeout=None):
        """
        Enable CSE, using force_update=True to ensure the extension is processed again even if settings haven't changed.
        """
        arguments = {
            "settings": {"commandToExecute": "echo 'Hello, world!'"},
            "auto_upgrade_minor_version": True,
            "force_update": True
        }
        if timeout is not None:
            arguments["timeout"] = timeout
        extension.enable(**arguments)

    def _assert_runtime_policy_file_contents(self, runtime_policy_file_path, expected_policy):
        """
        Assert that the agent copied the expected extension policy into CSE's config directory.
        """
        actual_policy = json.loads(self._ssh_client.run_command(f"cat {runtime_policy_file_path}", use_sudo=True))
        assert_that(actual_policy).described_as("Extension runtime policy").is_equal_to(expected_policy)

    def _assert_cse_loaded_policy(self, after_timestamp, extension_name):
        """
        Assert that CSE loaded its extension policy after the given enable operation started.
        """
        command_execution_log = "/var/log/azure/{0}/CommandExecution.log".format(extension_name)
        log_contents = self._ssh_client.run_command("cat {0}".format(command_execution_log), use_sudo=True)
        expected_message = "successfully loaded extension policy settings"
        matching_lines = []
        for line in log_contents.splitlines():
            timestamp_match = re.match(r"^time=(?P<timestamp>\S+)", line)
            if timestamp_match is not None and expected_message in line:
                timestamp = datetime.fromisoformat(timestamp_match.group("timestamp").replace("Z", "+00:00"))
                if timestamp >= after_timestamp:
                    matching_lines.append(line)

        assert_that(matching_lines) \
            .described_as(
                "Expected CommandExecution.log to contain '{0}' after {1}. Log contents:\n{2}".format(
                    expected_message,
                    after_timestamp,
                    log_contents)) \
            .is_not_empty()

    def run(self):
        # TODO: Only the Test CSE Extension 2.8.0+ supports 'AllowedCommandToExecute' policy right now. Once the Prod CSE
        #  Extension supports this policy, the publisher/type/version should be updated to use Prod
        cse_supports_policy = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIdentifier(publisher="Microsoft.Azure.Extensions.Edp", ext_type="CustomScript", version="2.8"),
            resource_name="CustomScriptRuntimePolicy")

        # CSE 2.0 does not declare supportsPolicy and is used to validate that the agent does not attempt to use policy
        # with an extension that does not support it.
        cse_does_not_support_policy = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIdentifier(publisher="Microsoft.Azure.Extensions", ext_type="CustomScript", version="2.0"),
            resource_name="UnsupportedCustomScriptRuntimePolicy")

        try:
            log.info("Enabling Debug.EnableExtensionPolicy in waagent.conf...")
            self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=y", use_sudo=True)
            log.info("Debug.EnableExtensionPolicy successfully enabled")
            log.info("")

            log.info("***Test Case 1 - CSE which supports policy should successfully enable when the requested commandToExecute is allowed")
            log.info("Creating agent policy which allows \"echo 'Hello, world!'\" command...")
            allowed_command = "echo 'Hello, world!'"
            cse_runtime_policy = {"AllowedCommandToExecute": [allowed_command]}
            self._set_runtime_policy("{0}.{1}".format(cse_supports_policy.extension_id.publisher, cse_supports_policy.extension_id.type), cse_runtime_policy)
            log.info("Successfully updated agent policy with allowed command. Policy file contents: \n{0}".format(json.loads(self._ssh_client.run_command("cat {0}".format(self._POLICY_FILE), use_sudo=True))))
            log.info("")

            log.info("Enabling CSE which supports policy...")
            enable_timestamp = self._ssh_client.get_time().replace(microsecond=0) # CSE log timestamps have second precision, so discard microseconds before comparing
            self._enable_cse(cse_supports_policy)
            cse_supports_policy.assert_instance_view(expected_message="Hello, world!")
            log.info("Successfully enabled CSE with the allowed command.")
            log.info("")

            log.info("Validating that CSE logs show the runtime policy was loaded successfully...")
            cse_version = cse_supports_policy.get_instance_view().type_handler_version
            runtime_policy_file_path = ("/var/lib/waagent/{0}.{1}-{2}/config/waagent_runtime_policy.json".format(
                cse_supports_policy.extension_id.publisher,
                cse_supports_policy.extension_id.type,
                cse_version)
            )
            self._assert_cse_loaded_policy(enable_timestamp, "{0}.{1}".format(cse_supports_policy.extension_id.publisher, cse_supports_policy.extension_id.type))
            log.info("Successfully validated the runtime policy was loaded by CSE.")
            log.info("")

            log.info("Validating that the runtime policy config file for the extension has the expected content...")
            self._assert_runtime_policy_file_contents(runtime_policy_file_path, cse_runtime_policy)
            log.info("Successfully validated the runtime policy config file has the expected content.")
            log.info("")

            log.info("***Test Case 2 - CSE which supports policy should fail to enable when the requested commandToExecute is not allowed")
            log.info("Refreshing agent policy to allow only 'date' command in CSE runtime policy...")
            cse_disallow_policy = {"AllowedCommandToExecute": ["date"]}
            self._set_runtime_policy("{0}.{1}".format(cse_supports_policy.extension_id.publisher, cse_supports_policy.extension_id.type), cse_disallow_policy)
            log.info("Successfully updated agent policy with allowed command. Policy file contents: \n{0}".format(json.loads(self._ssh_client.run_command("cat {0}".format(self._POLICY_FILE), use_sudo=True))))
            log.info("")

            log.info("Re-enabling CSE with \"echo 'Hello, world!'\" commandToExecute, which is expected to fail...")
            enable_timestamp = self._ssh_client.get_time().replace(microsecond=0)
            try:
                self._enable_cse(cse_supports_policy, timeout=6 * 60)
                fail("CSE enable should have failed because \"echo 'Hello, world!'\" is not in the runtime-policy allowlist")
            except Exception as error:
                expected_error = r"item is not in the allowlist"
                assert_that(re.search(expected_error, str(error))) \
                    .described_as("CSE enable error should contain '{0}', but the actual error was: {1}".format(expected_error,error)).is_not_none()
            log.info("CSE failed to enable, as expected.")
            log.info("")

            log.info("Validating that CSE logs show the runtime policy was loaded successfully...")
            self._assert_cse_loaded_policy(enable_timestamp, "{0}.{1}".format(cse_supports_policy.extension_id.publisher, cse_supports_policy.extension_id.type))
            log.info("Successfully validated the runtime policy was loaded by CSE.")
            log.info("")

            log.info("Validating that the runtime policy config file for the extension has the expected content...")
            self._assert_runtime_policy_file_contents(runtime_policy_file_path, cse_disallow_policy)
            log.info("Successfully validated the runtime policy config file has the expected content.")
            log.info("")

            log.info("***Test Case 3 - CSE which supports policy should succeed when extension specific runtime policy is removed")
            log.info("Refreshing agent policy to remove the runtime policy property for CSE...")
            self._set_runtime_policy("{0}.{1}".format(cse_supports_policy.extension_id.publisher, cse_supports_policy.extension_id.type))
            log.info("Successfully updated agent policy with allowed command. Policy file contents: \n{0}".format(json.loads(self._ssh_client.run_command("cat {0}".format(self._POLICY_FILE), use_sudo=True))))
            log.info("")

            log.info("Re-enabling CSE with \"echo 'Hello, world!'\" commandToExecute, which is expected to succeed...")
            enable_timestamp = self._ssh_client.get_time().replace(microsecond=0)
            self._enable_cse(cse_supports_policy)
            cse_supports_policy.assert_instance_view(expected_message="Hello, world!")
            log.info("Successfully enabled CSE after removing runtime policy.")
            log.info("")

            log.info("Validating that CSE logs show the runtime policy was loaded successfully...")
            self._assert_cse_loaded_policy(enable_timestamp, "{0}.{1}".format(cse_supports_policy.extension_id.publisher, cse_supports_policy.extension_id.type))
            log.info("Successfully validated the runtime policy was loaded by CSE.")
            log.info("")

            log.info("Validating that the runtime policy config file for the extension has the expected content...")
            self._assert_runtime_policy_file_contents(runtime_policy_file_path, {})
            log.info("Successfully validated the runtime policy config file has the expected content.")
            log.info("")

            log.info("***Test Case 4 - CSE which supports policy should succeed when the agent policy is removed")
            log.info("Removing agent policy file...")
            self._ssh_client.run_command(f"rm -f {self._POLICY_FILE}", use_sudo=True)
            log.info("Successfully removed agent policy file.")
            log.info("")

            log.info("Re-enabling CSE with \"echo 'Hello, world!'\" commandToExecute, which is expected to succeed...")
            self._enable_cse(cse_supports_policy)
            cse_supports_policy.assert_instance_view(expected_message="Hello, world!")
            log.info("Successfully enabled CSE after removing agent policy file.")

            log.info("Validating that the runtime policy config file for the extension doesn't exist after removing policy file...")
            self._ssh_client.run_command(f"test ! -e {runtime_policy_file_path}", use_sudo=True)
            log.info("Successfully validated that the runtime policy config file for the extension doesn't exist after removing policy file.")
            log.info("")

            log.info("***Test Case 5 - Agent fails CSE request when runtime policy configured if this version of CSE doesn't support runtime policy")
            log.info("Removing the policy-capable extension before testing an unsupported extension...")
            cse_supports_policy.delete()
            log.info("Successfully removed the version of CSE which supports runtime policy.")
            log.info("")

            command_to_create_file = "touch {0}".format(self._UNSUPPORTED_EXTENSION_OUTPUT)
            log.info("Updating agent policy file to include a runtime policy for CSE which allows command '{0}'...".format(command_to_create_file))
            self._set_runtime_policy("{0}.{1}".format(cse_does_not_support_policy.extension_id.publisher, cse_does_not_support_policy.extension_id.type), {"AllowedCommandToExecute": [command_to_create_file]})
            log.info("Successfully updated agent policy with allowed command. Policy file contents: \n{0}".format(json.loads(self._ssh_client.run_command("cat {0}".format(self._POLICY_FILE), use_sudo=True))))
            log.info("")

            log.info("Enabling CSE which does not support policy, expected to fail...")
            try:
                cse_does_not_support_policy.enable(
                    settings={"commandToExecute": command_to_create_file},
                    auto_upgrade_minor_version=False,
                    force_update=True,
                    timeout=6 * 60)
                fail("CSE enable should have failed because the extension does not support runtime policy")
            except Exception as error:
                expected_error = r"does not support runtime policy enforcement"
                assert_that(re.search(expected_error, str(error))) \
                    .described_as(
                        "CSE enable error should contain '{0}', but the actual error was: {1}".format(
                            expected_error,
                            error)) \
                    .is_not_none()
            log.info("CSE failed to enable, as expected.")
            log.info("")

            cse_version = cse_does_not_support_policy.get_instance_view().type_handler_version
            runtime_policy_file_path = ("/var/lib/waagent/{0}.{1}-{2}/config/waagent_runtime_policy.json".format(
                cse_does_not_support_policy.extension_id.publisher,
                cse_does_not_support_policy.extension_id.type,
                cse_version)
            )
            log.info("Validating that the tmp file was not created, since the agent should have failed the extension before enable was called...")
            self._ssh_client.run_command("test ! -e {0}".format(self._UNSUPPORTED_EXTENSION_OUTPUT), use_sudo=True)
            log.info("Successfully validated that the tmp file was not created.")
            log.info("")

            log.info("Validating that the runtime policy config file for the extension doesn't exist when the extension does not support policy...")
            self._ssh_client.run_command(f"test ! -e {runtime_policy_file_path}", use_sudo=True)
            log.info("Successfully validated that the runtime policy config file for the extension doesn't exist when the extension doesn't support runtime policy.")
            log.info("")

            log.info("***Test Case 6 - CSE which doesn't support policy should successfully be enabled when no runtime policy is configured for the extension")
            log.info("Verifying an extension that does not support policy is allowed without runtime policy")
            self._set_runtime_policy("{0}.{1}".format(cse_does_not_support_policy.extension_id.publisher, cse_does_not_support_policy.extension_id.type))
            log.info("Successfully updated agent policy to remove CSE runtime policy. Policy file contents: \n{0}".format(json.loads(self._ssh_client.run_command("cat {0}".format(self._POLICY_FILE), use_sudo=True))))
            log.info("")

            log.info("Re-enabling CSE, which is expected to succeed...")
            cse_does_not_support_policy.enable(
                settings={"commandToExecute": command_to_create_file},
                auto_upgrade_minor_version=False,
                force_update=True)
            cse_does_not_support_policy.assert_instance_view()
            log.info("Successfully enabled CSE after removing the CSE runtime policy.")

            log.info("Validating that the tmp file was created when no runtime policy is configured for the extension...")
            self._ssh_client.run_command("test -e {0}".format(self._UNSUPPORTED_EXTENSION_OUTPUT), use_sudo=True)
            log.info("Successfully validated that the tmp file was created.")
            log.info("")

            log.info("Validating that the runtime policy config file for the extension doesn't exist when the extension does not support policy...")
            self._ssh_client.run_command(f"test ! -e {runtime_policy_file_path}", use_sudo=True)
            log.info("Successfully validated that the runtime policy config file for the extension doesn't exist when the extension doesn't support runtime policy.")
            log.info("")

            # TODO: Add multi-config coverage when an extension that supports runtime policy is available.
        finally:
            log.info("Cleaning up the runtime-policy E2E test...")

            log.info("Removing the policy file and tmp file created by CSE...")
            self._ssh_client.run_command("rm -f {0} {1}".format(self._POLICY_FILE, self._UNSUPPORTED_EXTENSION_OUTPUT), use_sudo=True)
            log.info("Successfully cleaned up files.")

            log.info("Removing extensions added by this test...")
            extension_names = {item.name for item in self._context.vm.get_extensions().value}
            for extension_to_remove in [cse_supports_policy, cse_does_not_support_policy]:
                if extension_to_remove._resource_name in extension_names:
                    extension_to_remove.delete()
            log.info("Successfully removed extension.")

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return [
            # CSE is expected to have failures when it rejects the command due to policy.
            {
                "message": r"item is not in the allowlist"
            },
            {
                "message": (
                    r"name=Microsoft.Azure.Extensions.Edp.CustomScript, op=Enable, "
                    r"message=\[ExtensionOperationError\] Non-zero exit code"
                )
            },
            # Runtime policy on an unsupported extension is intentionally rejected by the agent.
            {
                "message": (
                    r"Runtime policy is specified for extension .* "
                    r"but this extension does not support runtime policy enforcement"
                )
            }
        ]


if __name__ == "__main__":
    ExtRuntimePolicy.run_from_command_line()
