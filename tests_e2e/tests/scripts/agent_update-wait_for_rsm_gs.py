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
# Verify the latest goal state included rsm requested version and if not, retry
#
import argparse
import sys
import logging

from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.protocol.goal_state import GoalState, GoalStateProperties
from azurelinuxagent.common.protocol.wire import WireProtocol
from tests_e2e.tests.lib.retry import retry_if_false


def get_requested_version(gs: GoalState) -> str:
    agent_families = gs.extensions_goal_state.agent_families
    agent_family_manifests = [m for m in agent_families if m.name == "Test" and len(m.uris) > 0]
    if len(agent_family_manifests) == 0:
        raise Exception(
            u"No manifest links found for agent family Test, skipping agent update verification")
    manifest = agent_family_manifests[0]
    if manifest.is_requested_version_specified and manifest.requested_version is not None:
        return str(manifest.requested_version)
    return ""


def verify_rsm_requested_version(wire_protocol: WireProtocol, expected_version: str) -> bool:
    wire_protocol.client.update_goal_state()
    goal_state = wire_protocol.client.get_goal_state()
    requested_version = get_requested_version(goal_state)
    if requested_version == expected_version:
        return True
    else:
        return False


try:
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', required=True)
    args = parser.parse_args()

    protocol = get_protocol_util().get_protocol(init_goal_state=False)
    protocol.client.reset_goal_state(
        goal_state_properties=GoalStateProperties.ExtensionsGoalState)

    found: bool = retry_if_false(lambda: verify_rsm_requested_version(protocol, args.version))

    if not found:
        raise Exception("Latest GS does not include rsm requested version : {0}.".format(args.version))
    else:
        logging.info("Latest GS includes rsm requested version : %s", args.version)


except Exception as e:
    print(f"{e}", file=sys.stderr)
    sys.exit(1)

sys.exit(0)
