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
import random

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, AgentUpdateError
from azurelinuxagent.common.future import UTC, datetime_min_utc, ustr
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils import timeutil
from azurelinuxagent.common.version import CURRENT_VERSION
from azurelinuxagent.ga.ga_version_updater import GAVersionUpdater
from azurelinuxagent.ga.guestagent import GuestAgentUpdateUtil


class SelfUpdateType(object):
    """
    Enum for different modes of Self updates
    """
    Hotfix = "Hotfix"
    Regular = "Regular"


class SelfUpdateVersionUpdater(GAVersionUpdater):
    def __init__(self, gs_id):
        super(SelfUpdateVersionUpdater, self).__init__(gs_id)
        self._last_attempted_manifest_download_time = datetime_min_utc
        self._next_update_time = datetime_min_utc

    @staticmethod
    def _get_agent_upgrade_type(version):
        # We follow semantic versioning for the agent, if <Major>.<Minor>.<Patch> is same, then <Build> has changed.
        # In this case, we consider it as a Hotfix upgrade. Else we consider it a Regular upgrade.
        if version.major == CURRENT_VERSION.major and version.minor == CURRENT_VERSION.minor and version.patch == CURRENT_VERSION.patch:
            return SelfUpdateType.Hotfix
        return SelfUpdateType.Regular

    @staticmethod
    def _get_next_process_time(upgrade_type, now):
        """
        Returns random time in between 0 to 24hrs(regular) or 4hrs(hotfix) from now
        """
        if upgrade_type == SelfUpdateType.Hotfix:
            frequency = conf.get_self_update_hotfix_frequency()
        else:
            frequency = conf.get_self_update_regular_frequency()
        return now + datetime.timedelta(seconds=random.randint(0, frequency))

    def _new_agent_allowed_now_to_update(self):
        """
        This method is called when a new update is detected and computes a random time for the next update on the first call.
        Since the method is called periodically until we reach the next update time, we shouldn't refresh or recompute the next update time on every call.
        We use default value(datetime.datetime.min) to ensure the computation happens only once. This next_update_time will reset to default value(datetime.min) when agent allowed to update.
        So that, in case the update fails due to an issue, such as a package download error, the same default value used to recompute the next update time.
        """
        now = datetime.datetime.now(UTC)
        upgrade_type = self._get_agent_upgrade_type(self._version)

        if self._next_update_time == datetime_min_utc:
            self._next_update_time = self._get_next_process_time(upgrade_type, now)
        message = "Self-update discovered new {0} upgrade WALinuxAgent-{1}; Will upgrade on or after {2}".format(
            upgrade_type, str(self._version), timeutil.create_utc_timestamp(self._next_update_time))
        logger.info(message)
        add_event(op=WALAEventOperation.AgentUpgrade, message=message, log_event=False)

        if self._next_update_time <= now:
            self._next_update_time = datetime_min_utc
            return True
        return False

    def _should_agent_attempt_manifest_download(self):
        """
        The agent should attempt to download the manifest if
        the agent has not attempted to download the manifest in the last 1 hour
        If we allow update, we update the last attempted manifest download time
        """
        now = datetime.datetime.now(UTC)

        if self._last_attempted_manifest_download_time != datetime_min_utc:
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

    def _retrieve_sorted_agent_versions(self, agent_family, goal_state):
        """
        Fetch the agent manifest and return all versions from the agent manifest, sorted highest-first.
        """
        self._agent_manifest = goal_state.fetch_agent_manifest(agent_family.name, agent_family.uris)
        return sorted(
            [FlexibleVersion(pkg.version) for pkg in self._agent_manifest.pkg_list.versions],
            reverse=True
        )

    def _log_new_agent_update_message(self):
        """
        This function logs the update message after we check version allowed to update.
        """
        msg = "Self-update is ready to upgrade the new agent: {0} now before processing the goal state: {1}".format(
            str(self._version), self._gs_id)
        logger.info(msg)
        add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False)

    def retrieve_and_download_agent(self, protocol, agent_family, goal_state):
        """
        Retrieve the target agent version, validate eligibility, and download it.
        On download/unzip failure, falls back to the next highest version in the manifest.

        The flow is:
        1. Fetch manifest and determine versions > CURRENT_VERSION.
        2. If there are no eligible candidates, return None.
        3. Run the timing gate once (may mutate _next_update_time) using the largest version's upgrade type.
        4. Iterate candidates descending, attempting download for each. On failure, try the next.

        @return: GuestAgent if a version was successfully downloaded, None if no update should be attempted.
        @raises: If all candidate downloads/validations fail, an appropriate Exception will be raised based on the failure
        """
        # Fetch manifest and get all agent versions sorted highest-first
        sorted_versions = self._retrieve_sorted_agent_versions(agent_family, goal_state)

        # We should attempt to update to latest version in manifest
        self._version = sorted_versions[0] if len(sorted_versions) > 0 else FlexibleVersion("0.0.0.0")
        if self._version <= CURRENT_VERSION:
            return None

        # If this is not the first update attempt, check if the agent is allowed to update now
        if not GuestAgentUpdateUtil.is_initial_update():
            if not self._new_agent_allowed_now_to_update():
                return None

        # Try downloading the latest version. If there's any issue with the download, try the next highest version until 
        # we exhaust all options to prevent baked-in agent from processing extensions.
        update_candidates = [v for v in sorted_versions if v > CURRENT_VERSION]
        for i in range(len(update_candidates)):
            self._version = update_candidates[i]
            self._log_new_agent_update_message()
            try:
                return self._download_and_get_new_agent(protocol, agent_family, goal_state)
            except Exception as err:
                if i < len(update_candidates) - 1:
                    msg = "Self-update: failed to prepare version {0} for update, trying next largest version. Error: {1}".format(self._version, ustr(err))
                    logger.warn(msg)
                    add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False, is_success=False)
                else:
                    raise

        return None

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
