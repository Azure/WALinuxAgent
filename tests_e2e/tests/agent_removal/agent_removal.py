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
import json
import os
from time import sleep
from assertpy import fail, assert_that

from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import _CaseFoldedDict
from azurelinuxagent.common.utils.archive import _EXT_CONF_FILE_NAME, _VM_SETTINGS_FILE_NAME
from azurelinuxagent.common.utils.textutil import parse_doc, find, findall, findtext, gettext
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient


class AgentRemoval(AgentVmTest):
    """
    This test verifies the manifest contents after agent removal from PIR.
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()
        self._expected_versions = None
        self._removed_version = None
        if hasattr(context, "expected_versions") and hasattr(context, "removed_version"):
            fail("Only one of the following arguments should be provided, but both were: expected_versions, removed_version")
        elif not hasattr(context, "expected_versions") and not hasattr(context, "removed_version"):
            fail("Exactly one of the following arguments should be provided: expected_versions, removed_version")
        elif hasattr(context, "expected_versions"):
            self._expected_versions = context.expected_versions.split(';')
        elif hasattr(context, "removed_version"):
            self._removed_version = context.removed_version
        self._GAFamily = context.GAFamily if hasattr(context, "GAFamily") else "Prod"

    def run(self):
        log.info("Retrieving agent manifests for {0} GAFamily...".format(self._GAFamily))

        manifest_uris = self._get_manifest_uris()

        log.info("")
        log.info("Checking agent versions in manifest URIs from goal state...")
        for uri in manifest_uris:
            log.info("")
            log.info("URI: {0}".format(uri))
            agent_versions = self._ssh_client.run_command("curl -s {0} | grep -oP '(?<=<Version>).*?(?=</Version>)'".format(uri)).splitlines()
            log.info("Agent versions in manifest: {0}".format(agent_versions))
            if self._expected_versions is not None:
                log.info("Expected versions: {0}".format(self._expected_versions))
                assert_that(self._expected_versions).described_as("Expected agent versions in manifest does not match actual agent versions in manifest. Expected={0}, Actual={1}".format(self._expected_versions, agent_versions)).is_equal_to(agent_versions)
                log.info("Expected versions match actual agent versions in manifest")
            else:
                log.info("Agent version which was deleted: {0}".format(self._removed_version))
                assert_that(agent_versions).described_as("Removed version {0} is still in manifest. Manifest versions: {1}".format(self._removed_version, agent_versions)).does_not_contain(self._removed_version)
                log.info("Agent version which was deleted is not in manifest")

        log.info("")
        log.info("Validated all manifests successfully.")

    def _get_manifest_uris(self):    #pylint: disable=R1710 (inconsistent-return-statements)
        # Try to get manifest URIs from current goal state, allowing several retries in case current goal state hasn't
        # been written to history folder yet.
        manifest_uris = []
        for _ in range(4):
            current_gs_history_path = self._ssh_client.run_command("find /var/lib/waagent/history -mindepth 1 -type d", use_sudo=True).rstrip()

            # Try to get extensions config for current goal state
            ext_config_path = os.path.join(current_gs_history_path, _EXT_CONF_FILE_NAME)
            try:
                ext_config_text = self._ssh_client.run_command("cat {0}".format(ext_config_path), use_sudo=True)
                xml_doc = parse_doc(ext_config_text)
                ga_families_list = find(xml_doc, "GAFamilies")
                ga_families = findall(ga_families_list, "GAFamily")
                for ga_family in ga_families:
                    if findtext(ga_family, "Name") == self._GAFamily:
                        log.info("Found {0} GAFamily from {1}".format(self._GAFamily, ext_config_path))
                        uris_list = find(ga_family, "Uris")
                        uris = findall(uris_list, "Uri")
                        for uri in uris:
                            manifest_uris.append(gettext(uri))
                        return manifest_uris
            except Exception:
                log.info("Unable to find extension config goal state from history folder.")

            # Try to get vm settings for current goal state if ext config doesn't exist
            vm_settings_path = os.path.join(current_gs_history_path, _VM_SETTINGS_FILE_NAME)
            try:
                vm_settings_text = self._ssh_client.run_command("cat {0}".format(vm_settings_path), use_sudo=True)
                vm_settings = _CaseFoldedDict.from_dict(json.loads(vm_settings_text))
                families = vm_settings.get("gaFamilies")
                for family in families:
                    if family["name"] == self._GAFamily:
                        log.info("Found {0} GAFamily from {1}".format(self._GAFamily, vm_settings_path))
                        for u in family.get("uris"):
                            manifest_uris.append(u)
                        return manifest_uris
            except Exception:
                log.info("Unable to find vm settings goal state from history folder.")

            log.info("Unable to retrieve manifest uris, retry in 45 seconds...")
            sleep(45)

        fail("Unable to get manifest uris from history folder.")
