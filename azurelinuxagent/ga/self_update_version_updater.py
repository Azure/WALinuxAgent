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

import datetime

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, AgentUpdateError
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import CURRENT_VERSION
from azurelinuxagent.ga.ga_version_updater import GAVersionUpdater


class SelfUpdateType(object):
    """
    Enum for different modes of Self updates
    """
    Hotfix = "Hotfix"
    Regular = "Regular"


class SelfUpdateVersionUpdater(GAVersionUpdater):
    def __init__(self, gs_id):
        super(SelfUpdateVersionUpdater, self).__init__(gs_id)
        self._last_attempted_manifest_download_time = datetime.datetime.min
        self._last_attempted_self_update_time = datetime.datetime.min

    @staticmethod
    def _get_largest_version(agent_manifest):
        """
        Get the largest version from the agent manifest
        """
        largest_version = FlexibleVersion("0.0.0.0")
        for pkg in agent_manifest.pkg_list.versions:
            pkg_version = FlexibleVersion(pkg.version)
            if pkg_version > largest_version:
                largest_version = pkg_version
        return largest_version

    @staticmethod
    def _get_agent_upgrade_type(version):
        # We follow semantic versioning for the agent, if <Major>.<Minor>.<Patch> is same, then <Build> has changed.
        # In this case, we consider it as a Hotfix upgrade. Else we consider it a Regular upgrade.
        if version.major == CURRENT_VERSION.major and version.minor == CURRENT_VERSION.minor and version.patch == CURRENT_VERSION.patch:
            return SelfUpdateType.Hotfix
        return SelfUpdateType.Regular

    @staticmethod
    def _get_next_process_time(last_val, frequency, now):
        """
        Get the next upgrade time
        """
        return now if last_val == datetime.datetime.min else last_val + datetime.timedelta(seconds=frequency)

    def _is_new_agent_allowed_update(self):
        """
        This method ensure that update is allowed only once per (hotfix/Regular) upgrade frequency
        """
        now = datetime.datetime.utcnow()
        upgrade_type = self._get_agent_upgrade_type(self._version)
        if upgrade_type == SelfUpdateType.Hotfix:
            next_update_time = self._get_next_process_time(self._last_attempted_self_update_time,
                                                           conf.get_self_update_hotfix_frequency(), now)
        else:
            next_update_time = self._get_next_process_time(self._last_attempted_self_update_time,
                                                           conf.get_self_update_regular_frequency(), now)

        if self._version > CURRENT_VERSION:
            message = "Self-update discovered new {0} upgrade WALinuxAgent-{1}; Will upgrade on or after {2}".format(
                upgrade_type, str(self._version), next_update_time.strftime(logger.Logger.LogTimeFormatInUTC))
            logger.info(message)
            add_event(op=WALAEventOperation.AgentUpgrade, message=message, log_event=False)

        if next_update_time <= now:
            # Update the last upgrade check time even if no new agent is available for upgrade
            self._last_attempted_self_update_time = now
            return True
        return False

    def _should_agent_attempt_manifest_download(self):
        """
        The agent should attempt to download the manifest if
        the agent has not attempted to download the manifest in the last 1 hour
        If we allow update, we update the last attempted manifest download time
        """
        now = datetime.datetime.utcnow()

        if self._last_attempted_manifest_download_time != datetime.datetime.min:
            next_attempt_time = self._last_attempted_manifest_download_time + datetime.timedelta(
                seconds=conf.get_autoupdate_frequency())
        else:
            next_attempt_time = now

        if next_attempt_time > now:
            return False
        self._last_attempted_manifest_download_time = now
        return True

    def is_update_allowed_this_time(self, ext_gs_updated):
        """
        Checks if we allowed download manifest as per manifest download frequency
        """
        if not self._should_agent_attempt_manifest_download():
            return False
        return True

    def is_rsm_update_enabled(self, agent_family, ext_gs_updated):
        """
        Checks if there is a new goal state and decide if we need to continue with self-update or switch to rsm update.
        if vm is not enabled for RSM updates or agent not supports GA versioning then we continue with self update, otherwise we return true to switch to rsm update.
        if isVersionFromRSM is missing but isVMEnabledForRSMUpgrades is present in the goal state, we ignore the update as we consider it as invalid goal state.
        """
        if ext_gs_updated:
            if conf.get_enable_ga_versioning() and agent_family.is_vm_enabled_for_rsm_upgrades is not None and agent_family.is_vm_enabled_for_rsm_upgrades:
                if agent_family.is_version_from_rsm is None:
                    raise AgentUpdateError(
                        "Received invalid goal state:{0}, missing isVersionFromRSM property. So, skipping agent update".format(
                            self._gs_id))
                else:
                    if agent_family.version is None:
                        raise AgentUpdateError(
                            "Received invalid goal state:{0}, missing version property. So, skipping agent update".format(
                                self._gs_id))
                    return True

        return False

    def retrieve_agent_version(self, agent_family, goal_state):
        """
        Get the largest version from the agent manifest
        """
        self._agent_manifest = goal_state.fetch_agent_manifest(agent_family.name, agent_family.uris)
        largest_version = self._get_largest_version(self._agent_manifest)
        self._version = largest_version

    def is_retrieved_version_allowed_to_update(self, agent_family):
        """
        checks update is spread per (as specified in the conf.get_self_update_hotfix_frequency() or conf.get_self_update_regular_frequency())
        or if version below than current version
        return false when we don't allow updates.
        """
        if not self._is_new_agent_allowed_update():
            return False

        if self._version <= CURRENT_VERSION:
            return False

        return True

    def log_new_agent_update_message(self):
        """
        This function logs the update message after we check version allowed to update.
        """
        msg = "Self-update is ready to upgrade the new agent: {0} now before processing the goal state: {1}".format(
            str(self._version), self._gs_id)
        logger.info(msg)
        add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False)

    def proceed_with_update(self):
        """
        upgrade to largest version. Downgrade is not supported.
            Raises: AgentUpgradeExitException
        """
        if self._version > CURRENT_VERSION:
            # In case of an upgrade, we don't need to exclude anything as the daemon will automatically
            # start the next available highest version which would be the target version
            raise AgentUpgradeExitException(
                "Current Agent {0} completed all update checks, exiting current process to upgrade to the new Agent version {1}".format(CURRENT_VERSION,
                    self._version))
