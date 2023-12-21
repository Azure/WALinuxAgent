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
# returns the agent latest version published
#

from azurelinuxagent.common.protocol.goal_state import GoalStateProperties
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from tests_e2e.tests.lib.retry import retry


def get_agent_family_manifest(goal_state):
    """
    Get the agent_family from last GS for Test Family
    """
    agent_families = goal_state.extensions_goal_state.agent_families
    agent_family_manifests = []
    for m in agent_families:
        if m.name == 'Test':
            if len(m.uris) > 0:
                agent_family_manifests.append(m)
    return agent_family_manifests[0]


def get_largest_version(agent_manifest):
    """
    Get the largest version from the agent manifest
    """
    largest_version = FlexibleVersion("0.0.0.0")
    for pkg in agent_manifest.pkg_list.versions:
        pkg_version = FlexibleVersion(pkg.version)
        if pkg_version > largest_version:
            largest_version = pkg_version
    return largest_version


def main():

    try:
        protocol = get_protocol_util().get_protocol(init_goal_state=False)
        retry(lambda: protocol.client.reset_goal_state(
            goal_state_properties=GoalStateProperties.ExtensionsGoalState))
        goal_state = protocol.client.get_goal_state()
        agent_family = get_agent_family_manifest(goal_state)
        agent_manifest = goal_state.fetch_agent_manifest(agent_family.name, agent_family.uris)
        largest_version = get_largest_version(agent_manifest)
        print(str(largest_version))
    except Exception as e:
        raise Exception("Unable to verify agent updated to latest version since test failed to get the which is the latest version from the agent manifest: {0}".format(e))


if __name__ == "__main__":
    main()
