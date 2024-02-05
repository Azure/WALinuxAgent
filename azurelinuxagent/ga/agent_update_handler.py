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
import os

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, AgentUpdateError, AgentFamilyMissingError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import VMAgentUpdateStatuses, VMAgentUpdateStatus, VERSION_0
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import get_daemon_version
from azurelinuxagent.ga.rsm_version_updater import RSMVersionUpdater
from azurelinuxagent.ga.self_update_version_updater import SelfUpdateVersionUpdater


def get_agent_update_handler(protocol):
    return AgentUpdateHandler(protocol)


class AgentUpdateHandler(object):
    """
    This class handles two type of agent updates. Handler initializes the updater to SelfUpdateVersionUpdater and switch to appropriate updater based on below conditions:
        RSM update: This is the update requested by RSM. The contract between CRP and agent is we get following properties in the goal state:
                    version: it will have what version to update
                    isVersionFromRSM: True if the version is from RSM deployment.
                    isVMEnabledForRSMUpgrades: True if the VM is enabled for RSM upgrades.
                    if vm enabled for RSM upgrades, we use RSM update path. But if requested update is not by rsm deployment
                    we ignore the update.
        Self update: We fallback to this if above is condition not met. This update to the largest version available in the manifest
                    Note: Self-update don't support downgrade.

    Handler keeps the rsm state of last update is with RSM or not on every new goal state. Once handler decides which updater to use, then
    does following steps:
        1. Retrieve the agent version from the goal state.
        2. Check if we allowed to update for that version.
        3. Log the update message.
        4. Purge the extra agents from disk.
        5. Download the new agent.
        6. Proceed with update.

    [Note: 1.0.8.147 is the minimum supported version of HGPA which will have the isVersionFromRSM and isVMEnabledForRSMUpgrades properties in vmsettings.]
    """
    def __init__(self, protocol):
        self._protocol = protocol
        self._gs_id = "unknown"
        self._ga_family_type = conf.get_autoupdate_gafamily()
        self._daemon_version = self._get_daemon_version_for_update()
        self._last_attempted_update_error_msg = ""

        # restore the state of rsm update. Default to self-update if last update is not with RSM.
        if not self._get_is_last_update_with_rsm():
            self._updater = SelfUpdateVersionUpdater(self._gs_id)
        else:
            self._updater = RSMVersionUpdater(self._gs_id, self._daemon_version)

    @staticmethod
    def _get_daemon_version_for_update():
        daemon_version = get_daemon_version()
        if daemon_version != FlexibleVersion(VERSION_0):
            return daemon_version
        # We return 0.0.0.0 if daemon version is not specified. In that case,
        # use the min version as 2.2.53 as we started setting the daemon version starting 2.2.53.
        return FlexibleVersion("2.2.53")

    @staticmethod
    def _get_rsm_update_state_file():
        """
        This file keeps if last attempted update is rsm or not.
        """
        return os.path.join(conf.get_lib_dir(), "rsm_update.json")

    def _save_rsm_update_state(self):
        """
        Save the rsm state empty file when we switch to RSM
        """
        try:
            with open(self._get_rsm_update_state_file(), "w"):
                pass
        except Exception as e:
            logger.warn("Error creating the RSM state ({0}): {1}", self._get_rsm_update_state_file(), ustr(e))

    def _remove_rsm_update_state(self):
        """
        Remove the rsm state file when we switch to self-update
        """
        try:
            if os.path.exists(self._get_rsm_update_state_file()):
                os.remove(self._get_rsm_update_state_file())
        except Exception as e:
            logger.warn("Error removing the RSM state ({0}): {1}", self._get_rsm_update_state_file(), ustr(e))

    def _get_is_last_update_with_rsm(self):
        """
        Returns True if state file exists as this consider as last update with RSM is true
        """
        return os.path.exists(self._get_rsm_update_state_file())

    def _get_agent_family_manifest(self, goal_state):
        """
        Get the agent_family from last GS for the given family
        Returns: first entry of Manifest
                 Exception if no manifests found in the last GS and log it only on new goal state
        """
        family = self._ga_family_type
        agent_families = goal_state.extensions_goal_state.agent_families
        family_found = False
        agent_family_manifests = []
        for m in agent_families:
            if m.name == family:
                family_found = True
                if len(m.uris) > 0:
                    agent_family_manifests.append(m)

        if not family_found:
            raise AgentFamilyMissingError(u"Agent family: {0} not found in the goal state: {1}, skipping agent update \n"
                                          u"[Note: This error is permanent for this goal state and Will not log same error until we receive new goal state]".format(family, self._gs_id))

        if len(agent_family_manifests) == 0:
            raise AgentFamilyMissingError(
                u"No manifest links found for agent family: {0} for goal state: {1}, skipping agent update \n"
                u"[Note: This error is permanent for this goal state and will not log same error until we receive new goal state]".format(
                    family, self._gs_id))
        return agent_family_manifests[0]

    def run(self, goal_state, ext_gs_updated):

        try:
            # Ignore new agents if update is disabled. The latter flag only used in e2e tests.
            if not conf.get_autoupdate_enabled() or not conf.get_download_new_agents():
                return

            # Update the state only on new goal state
            if ext_gs_updated:
                self._gs_id = goal_state.extensions_goal_state.id
                self._updater.sync_new_gs_id(self._gs_id)

            agent_family = self._get_agent_family_manifest(goal_state)

            # Updater will return True or False if we need to switch the updater
            # If self-updater receives RSM update enabled, it will switch to RSM updater
            # If RSM updater receives RSM update disabled, it will switch to self-update
            # No change in updater if GS not updated
            is_rsm_update_enabled = self._updater.is_rsm_update_enabled(agent_family, ext_gs_updated)

            if not is_rsm_update_enabled and isinstance(self._updater, RSMVersionUpdater):
                msg = "VM not enabled for RSM updates, switching to self-update mode"
                logger.info(msg)
                add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False)
                self._updater = SelfUpdateVersionUpdater(self._gs_id)
                self._remove_rsm_update_state()

            if is_rsm_update_enabled and isinstance(self._updater, SelfUpdateVersionUpdater):
                msg = "VM enabled for RSM updates, switching to RSM update mode"
                logger.info(msg)
                add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False)
                self._updater = RSMVersionUpdater(self._gs_id, self._daemon_version)
                self._save_rsm_update_state()

            # If updater is changed in previous step, we allow update as it consider as first attempt. If not, it checks below condition
            # RSM checks new goal state; self-update checks manifest download interval
            if not self._updater.is_update_allowed_this_time(ext_gs_updated):
                return

            self._updater.retrieve_agent_version(agent_family, goal_state)

            if not self._updater.is_retrieved_version_allowed_to_update(agent_family):
                return
            self._updater.log_new_agent_update_message()
            self._updater.purge_extra_agents_from_disk()
            agent = self._updater.download_and_get_new_agent(self._protocol, agent_family, goal_state)
            if agent.is_blacklisted or not agent.is_downloaded:
                msg = "Downloaded agent version is in bad state : {0} , skipping agent update".format(
                    str(agent.version))
                raise AgentUpdateError(msg)
            self._updater.proceed_with_update()

        except Exception as err:
            log_error = True
            if isinstance(err, AgentUpgradeExitException):
                raise err
            elif isinstance(err, AgentUpdateError):
                error_msg = ustr(err)
            elif isinstance(err, AgentFamilyMissingError):
                error_msg = ustr(err)
                # Agent family missing error is permanent in the given goal state, so we don't want to log it on every iteration of main loop if there is no new goal state
                log_error = ext_gs_updated
            else:
                error_msg = "Unable to update Agent: {0}".format(textutil.format_exception(err))
            if log_error:
                logger.warn(error_msg)
                add_event(op=WALAEventOperation.AgentUpgrade, is_success=False, message=error_msg, log_event=False)
            self._last_attempted_update_error_msg = error_msg

    def get_vmagent_update_status(self):
        """
        This function gets the VMAgent update status as per the last attempted update.
        Returns: None if fail to report or update never attempted with rsm version specified in GS
        Note: We send the status regardless of updater type. Since we call this main loop, want to avoid fetching agent family to decide and send only if
        vm enabled for rsm updates.
        """
        try:
            if conf.get_enable_ga_versioning():
                if not self._last_attempted_update_error_msg:
                    status = VMAgentUpdateStatuses.Success
                    code = 0
                else:
                    status = VMAgentUpdateStatuses.Error
                    code = 1
                return VMAgentUpdateStatus(expected_version=str(self._updater.version), status=status, code=code, message=self._last_attempted_update_error_msg)
        except Exception as err:
            msg = "Unable to report agent update status: {0}".format(textutil.format_exception(err))
            logger.warn(msg)
            add_event(op=WALAEventOperation.AgentUpgrade, is_success=False, message=msg, log_event=True)
        return None
