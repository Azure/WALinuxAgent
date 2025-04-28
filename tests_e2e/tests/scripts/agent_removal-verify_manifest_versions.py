#!/usr/bin/env pypy3

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
# Validates that the versions in the agent manifests are expected.
#
import argparse
from typing import List

from assertpy import assert_that

from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.protocol.goal_state import GoalStateProperties, ExtensionManifest
from azurelinuxagent.common.protocol.wire import WireProtocol
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
from tests_e2e.tests.lib.retry import retry
from tests_e2e.tests.lib.shell import run_command


def _get_manifest_uris(wire_protocol: WireProtocol, family: str) -> List[str]:
    retry(lambda: wire_protocol.client.update_goal_state)
    goal_state = wire_protocol.client.get_goal_state()
    manifest_uris = next((gs_family.uris for gs_family in goal_state.extensions_goal_state.agent_families if gs_family.name == family), [])
    if len(manifest_uris) == 0:
        raise Exception("Unable to retrieve agent manifest uris from goal state. GS Agent Families: {0}".format(goal_state.extensions_goal_state.agent_families))
    return manifest_uris


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected_versions', required=False)
    parser.add_argument('--removed_version', required=False)
    parser.add_argument('--ga_family', required=True)
    args = parser.parse_args()

    expected_versions = args.expected_versions.split(';') if args.expected_versions is not None else None
    removed_version = args.removed_version
    ga_family = args.ga_family

    log.info("")
    log.info("Retrieving agent manifest uris for {0} GAFamily...".format(ga_family))
    protocol = get_protocol_util().get_protocol(init_goal_state=False)
    retry(lambda: protocol.client.reset_goal_state(goal_state_properties=GoalStateProperties.ExtensionsGoalState))
    manifest_uris = _get_manifest_uris(protocol, ga_family)
    log.info("Successfully retrieved manifest uris from goal state.")

    log.info("")
    log.info("Validating agent versions in manifest URIs from goal state...")
    for uri in manifest_uris:
        log.info("")
        log.info("URI: {0}".format(uri))
        # xml_text = run_command(["curl", "-s", "{0}".format(uri)])
        xml_text = run_command(["http_get.py", "{0}".format(uri)])
        manifest = ExtensionManifest(xml_text)
        agent_versions = [pkg.version for pkg in manifest.pkg_list.versions]
        log.info("Agent versions in manifest: {0}".format(agent_versions))
        if expected_versions is not None:
            log.info("Expected versions: {0}".format(expected_versions))
            assert_that(expected_versions).described_as("Expected agent versions in manifest does not match actual agent versions in manifest. Expected={0}, Actual={1}".format(expected_versions, agent_versions)).is_equal_to(agent_versions)
            log.info("Expected versions match actual agent versions in manifest")
        else:
            log.info("Agent version which was deleted: {0}".format(removed_version))
            assert_that(agent_versions).described_as("Removed version {0} is still in manifest. Manifest versions: {1}".format(removed_version, agent_versions)).does_not_contain(removed_version)
            log.info("Agent version which was deleted is not in manifest")

    log.info("")
    log.info("Validated all manifests successfully.")


run_remote_test(main)
