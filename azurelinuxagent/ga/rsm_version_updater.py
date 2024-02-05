# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+

import glob
import os

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, AgentUpdateError
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import CURRENT_VERSION, AGENT_NAME
from azurelinuxagent.ga.ga_version_updater import GAVersionUpdater
from azurelinuxagent.ga.guestagent import GuestAgent


class RSMVersionUpdater(GAVersionUpdater):
    def __init__(self, gs_id, daemon_version):
        super(RSMVersionUpdater, self).__init__(gs_id)
        self._daemon_version = daemon_version

    @staticmethod
    def _get_all_agents_on_disk():
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))
        return [GuestAgent.from_installed_agent(path=agent_dir) for agent_dir in glob.iglob(path) if
                os.path.isdir(agent_dir)]

    def _get_available_agents_on_disk(self):
        available_agents = [agent for agent in self._get_all_agents_on_disk() if agent.is_available]
        return sorted(available_agents, key=lambda agent: agent.version, reverse=True)

    def is_update_allowed_this_time(self, ext_gs_updated):
        """
        RSM update allowed if we have a new goal state
        """
        return ext_gs_updated

    def is_rsm_update_enabled(self, agent_family, ext_gs_updated):
        """
        Checks if there is a new goal state and decide if we need to continue with rsm update or switch to self-update.
        Firstly it checks agent supports GA versioning or not. If not, we return false to switch to self-update.
        if vm is enabled for RSM updates and continue with rsm update, otherwise we return false to switch to self-update.
        if either isVersionFromRSM or isVMEnabledForRSMUpgrades or version is missing in the goal state, we ignore the update as we consider it as invalid goal state.
        """
        if ext_gs_updated:
            if not conf.get_enable_ga_versioning():
                return False

            if agent_family.is_vm_enabled_for_rsm_upgrades is None:
                raise AgentUpdateError(
                    "Received invalid goal state:{0}, missing isVMEnabledForRSMUpgrades property. So, skipping agent update".format(
                        self._gs_id))
            elif not agent_family.is_vm_enabled_for_rsm_upgrades:
                return False
            else:
                if agent_family.is_version_from_rsm is None:
                    raise AgentUpdateError(
                        "Received invalid goal state:{0}, missing isVersionFromRSM property. So, skipping agent update".format(
                            self._gs_id))
                if agent_family.version is None:
                    raise AgentUpdateError(
                        "Received invalid goal state:{0}, missing version property. So, skipping agent update".format(
                            self._gs_id))

        return True

    def retrieve_agent_version(self, agent_family, goal_state):
        """
        Get the agent version from the goal state
        """
        self._version = FlexibleVersion(agent_family.version)

    def is_retrieved_version_allowed_to_update(self, agent_family):
        """
        Once version retrieved from goal state, we check if we allowed to update for that version
        allow update If new version not same as current version, not below than daemon version and if version is from rsm request
        """

        if not agent_family.is_version_from_rsm or self._version < self._daemon_version or self._version == CURRENT_VERSION:
            return False

        return True

    def log_new_agent_update_message(self):
        """
        This function logs the update message after we check version allowed to update.
        """
        msg = "New agent version:{0} requested by RSM in Goal state {1}, will update the agent before processing the goal state.".format(
            str(self._version), self._gs_id)
        logger.info(msg)
        add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False)

    def purge_extra_agents_from_disk(self):
        """
        Remove the agents( including rsm version if exists) from disk except current version. There is a chance that rsm version could exist and/or blacklisted
        on previous update attempts. So we should remove it from disk in order to honor current rsm version update.
        """
        known_agents = [CURRENT_VERSION]
        self._purge_unknown_agents_from_disk(known_agents)

    def proceed_with_update(self):
        """
        upgrade/downgrade to the new version.
        Raises: AgentUpgradeExitException
        """
        if self._version < CURRENT_VERSION:
            # In case of a downgrade, we mark the current agent as bad version to avoid starting it back up ever again
            # (the expectation here being that if we get request to a downgrade,
            # there's a good reason for not wanting the current version).
            prefix = "downgrade"
            try:
                # We should always have an agent directory for the CURRENT_VERSION
                agents_on_disk = self._get_available_agents_on_disk()
                current_agent = next(agent for agent in agents_on_disk if agent.version == CURRENT_VERSION)
                msg = "Marking the agent {0} as bad version since a downgrade was requested in the GoalState, " \
                      "suggesting that we really don't want to execute any extensions using this version".format(
                    CURRENT_VERSION)
                logger.info(msg)
                add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False)
                current_agent.mark_failure(is_fatal=True, reason=msg)
            except StopIteration:
                logger.warn(
                    "Could not find a matching agent with current version {0} to blacklist, skipping it".format(
                        CURRENT_VERSION))
        else:
            # In case of an upgrade, we don't need to exclude anything as the daemon will automatically
            # start the next available highest version which would be the target version
            prefix = "upgrade"
        raise AgentUpgradeExitException(
            "Current Agent {0} completed all update checks, exiting current process to {1} to the new Agent version {2}".format(CURRENT_VERSION,
                prefix, self._version))
