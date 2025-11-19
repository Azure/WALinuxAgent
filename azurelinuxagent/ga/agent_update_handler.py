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

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, AgentUpdateError, AgentFamilyMissingError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import VMAgentUpdateStatuses, VMAgentUpdateStatus, VERSION_0
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import get_daemon_version, CURRENT_VERSION
from azurelinuxagent.ga.guestagent import GuestAgentUpdateUtil
from azurelinuxagent.ga.rsm_version_updater import RSMVersionUpdater
from azurelinuxagent.ga.self_update_version_updater import SelfUpdateVersionUpdater


class UpdateMode(object):
    """
    Enum for Update modes
    """
    RSM = "RSM"
    SelfUpdate = "SelfUpdate"


def get_agent_update_handler(protocol):
    return AgentUpdateHandler(protocol)


class AgentUpdateHandler(object):
    """
    This class handles two type of agent updates. Handler initializes the updater to SelfUpdateVersionUpdater and switch to appropriate updater based on below conditions:
        RSM update: This update requested by RSM and contract between CRP and agent is we get following properties in the goal state:
                    version: it will have what version to update
                    isVersionFromRSM: True if the version is from RSM deployment.
                    isVMEnabledForRSMUpgrades: True if the VM is enabled for RSM upgrades.
                    fromVersion: This property specifies the version to update from. It is populated only for downgrade requests and subsequent goal states thereafter, until an upgrade request.
                    if vm enabled for RSM upgrades, we use RSM update path. But if requested update is not by rsm deployment( if isVersionFromRSM:False)
                    we ignore the update.
        Self update: We fallback to this if above condition not met. This update to the largest version available in the manifest.
                     Also, we use self-update for initial update due to [1][2]
                    Note: Self-update don't support downgrade.

    [1] New vms that are enrolled into RSM, they get isVMEnabledForRSMUpgrades as True and isVersionFromRSM as False in first goal state. As per RSM update flow mentioned above,
    we don't apply the update if isVersionFromRSM is false. Consequently, new vms remain on pre-installed agent until RSM drives a new version update. In the meantime, agent may process the extensions with the baked version.
    This can potentially lead to issues due to incompatibility.
    [2] If current version is N, and we are deploying N+1. We find an issue on N+1 and remove N+1 from PIR. If CRP created the initial goal state for a new vm
    before the delete, the version in the goal state would be N+1; If the agent starts processing the goal state after the deleting, it won't find N+1 and update will fail and
    the vm will use baked version.

    Handler updates the state if current update mode is changed from last update mode(RSM or Self-Update) on new goal state. Once handler decides which updater to use, then
    updater does following steps:
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

        # Restore the state of rsm update. Default to self-update if last update is not with RSM or if agent doing initial update
        if not GuestAgentUpdateUtil.is_last_update_with_rsm() or GuestAgentUpdateUtil.is_initial_update():
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

    def get_current_update_mode(self):
        """
        Returns current update mode whether RSM or Self-Update
        """
        if isinstance(self._updater, RSMVersionUpdater):
            return UpdateMode.RSM
        else:
            return UpdateMode.SelfUpdate

    def run(self, goal_state, ext_gs_updated):

        try:
            # If auto update is disabled, we don't proceed with update
            if not conf.get_auto_update_to_latest_version():
                self._last_attempted_update_error_msg = "Auto update is disabled, skipping agent update"
                return

            # Update the state only on new goal state
            if ext_gs_updated:
                # Reset the last reported update state on new goal state before we attempt update otherwise we keep reporting the last update error if any
                self._last_attempted_update_error_msg = ""
                self._gs_id = goal_state.extensions_goal_state.id
                self._updater.sync_new_gs_id(self._gs_id)

            agent_family = self._get_agent_family_manifest(goal_state)

            # Always agent uses self-update for initial update regardless vm enrolled into RSM or not
            # So ignoring the check for updater switch for the initial goal state/update
            if not GuestAgentUpdateUtil.is_initial_update():
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
                    GuestAgentUpdateUtil.remove_rsm_update_state_file()

                if is_rsm_update_enabled and isinstance(self._updater, SelfUpdateVersionUpdater):
                    msg = "VM enabled for RSM updates, switching to RSM update mode"
                    logger.info(msg)
                    add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False)
                    self._updater = RSMVersionUpdater(self._gs_id, self._daemon_version)
                    GuestAgentUpdateUtil.save_rsm_update_state_file()

            # If updater is changed in previous step, we allow update as it consider as first attempt. If not, it checks below condition
            # RSM checks new goal state; self-update checks manifest download interval
            if not self._updater.is_update_allowed_this_time(ext_gs_updated):
                return

            self._updater.retrieve_agent_version(agent_family, goal_state)

            if not self._updater.is_retrieved_version_allowed_to_update(agent_family):
                return
            self._updater.log_new_agent_update_message()
            agent = self._updater.download_and_get_new_agent(self._protocol, agent_family, goal_state)

            # Below condition is to break the update loop if new agent is in bad state in previous attempts
            # If the bad agent update already attempted 3 times, we don't want to continue with update anymore.
            # Otherewise we allow the update by increment the update attempt count and clear the bad state to make good agent
            # [Note: As a result, it is breaking contract between RSM and agent, we may NOT honor the RSM retries for that version]
            if agent.get_update_attempt_count() >= 3:
                msg = "Attempted enough update retries for version: {0} but still agent not recovered from bad state. So, we stop updating to this version".format(str(agent.version))
                raise AgentUpdateError(msg)
            else:
                agent.clear_error()
                agent.inc_update_attempt_count()
                msg = "Agent update attempt count: {0} for version: {1}".format(agent.get_update_attempt_count(), str(agent.version))
                logger.info(msg)
                add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False)

            self._updater.purge_extra_agents_from_disk()
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
                error_msg = "[{0}]{1}".format(self.get_current_update_mode(), error_msg)
                logger.warn(error_msg)
                add_event(op=WALAEventOperation.AgentUpgrade, is_success=False, message=error_msg, log_event=False)
            self._last_attempted_update_error_msg = error_msg

        # save initial update state when agent is doing first update
        finally:
            if GuestAgentUpdateUtil.is_initial_update():
                GuestAgentUpdateUtil.save_initial_update_state_file()

    def get_vmagent_update_status(self):
        """
        This function gets the VMAgent update status as per the last attempted update.
        Returns: None if fail to report or update never attempted with rsm version specified in GS
        Note: We report the status only when vm enrolled into RSM
        """
        try:
            if self.get_current_update_mode() == UpdateMode.RSM:
                if not self._last_attempted_update_error_msg:
                    status = VMAgentUpdateStatuses.Success
                    code = 0
                else:
                    status = VMAgentUpdateStatuses.Error
                    code = 1
                return VMAgentUpdateStatus(expected_version=str(CURRENT_VERSION), status=status, code=code, message=self._last_attempted_update_error_msg)
        except Exception as err:
            msg = "Unable to report agent update status: {0}".format(textutil.format_exception(err))
            logger.warn(msg)
            add_event(op=WALAEventOperation.AgentUpgrade, is_success=False, message=msg, log_event=True)
        return None