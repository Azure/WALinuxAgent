import datetime
import glob
import json
import os
import shutil

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, AgentUpdateError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateSource
from azurelinuxagent.common.protocol.restapi import VMAgentUpdateStatuses, VMAgentUpdateStatus, VERSION_0
from azurelinuxagent.common.utils import fileutil, textutil, timeutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import get_daemon_version, CURRENT_VERSION, AGENT_NAME, AGENT_DIR_PATTERN
from azurelinuxagent.ga.guestagent import GuestAgent


def get_agent_update_handler(protocol):
    return AgentUpdateHandler(protocol)


class SelfUpdateType(object):
    """
    Enum for different modes of Self updates
    """
    Hotfix = "Hotfix"
    Regular = "Regular"


class AgentUpdateHandlerUpdateState(object):
    """
    This class is primarily used to maintain the in-memory persistent state for the agent updates.
    This state will be persisted throughout the current service run.
    """
    def __init__(self):
        self.last_attempted_rsm_version_update_time = datetime.datetime.min
        self.last_attempted_self_update_hotfix_time = datetime.datetime.min
        self.last_attempted_self_update_regular_time = datetime.datetime.min
        self.last_attempted_manifest_download_time = datetime.datetime.min
        self.last_attempted_update_error_msg = ""
        self.last_attempted_update_version = FlexibleVersion("0.0.0.0")


class AgentUpdateHandler(object):
    """
    This class handles two type of agent updates and chooses the appropriate updater based on the below conditions:
        RSM update: This is the update requested by RSM. The contract between CRP and agent is we get following properties in the goal state:
                    version: it will have what version to update
                    isVersionFromRSM: True if the version is from RSM deployment.
                    isVMEnabledForRSMUpgrades: True if the VM is enabled for RSM upgrades.
                    if vm enabled for RSM upgrades, we use RSM update path. But if requested update is not by rsm deployment
                    we ignore the update.
                    This update is allowed once per (as specified in the conf.get_autoupdate_frequency())
        Self update: We fallback to this if above is condition not met. This update to the largest version available in the manifest
                    we allow update once per (as specified in the conf.get_self_update_hotfix_frequency() or conf.get_self_update_regular_frequency())
                    Note: Self-update don't support downgrade.
    """
    def __init__(self, protocol):
        self._protocol = protocol
        self._ga_family = conf.get_autoupdate_gafamily()
        self._autoupdate_enabled = conf.get_autoupdate_enabled()
        self._gs_id = "unknown"
        self._daemon_version = self._get_daemon_version_for_update()
        self.update_state = AgentUpdateHandlerUpdateState()

        # restore the state of rsm update
        if not os.path.exists(self._get_rsm_version_state_file()):
            self._is_version_from_rsm = False
            self._is_vm_enabled_for_rsm_upgrades = False
        else:
            self._is_version_from_rsm = self._get_is_version_from_rsm()
            self._is_vm_enabled_for_rsm_upgrades = self._get_is_vm_enabled_for_rsm_upgrades()

    @staticmethod
    def _get_daemon_version_for_update():
        daemon_version = get_daemon_version()
        if daemon_version != FlexibleVersion(VERSION_0):
            return daemon_version
        # We return 0.0.0.0 if daemon version is not specified. In that case,
        # use the min version as 2.2.53 as we started setting the daemon version starting 2.2.53.
        return FlexibleVersion("2.2.53")

    @staticmethod
    def _get_rsm_version_state_file():
        # This file keeps the isversionfromrsm and isvmeabledforrsmupgrades of the most recent goal state.
        return os.path.join(conf.get_lib_dir(), "rsm_version.json")

    def _save_rsm_version_state(self, isVersionFromRSM, isVMEnabledForRSMUpgrades, timestamp):
        """
        Save the rsm state to the file
        """
        try:
            with open(self._get_rsm_version_state_file(), "w") as file_:
                json.dump({"isVersionFromRSM": isVersionFromRSM,
                           "isVMEnabledForRSMUpgrades": isVMEnabledForRSMUpgrades,
                           "timestamp": timestamp}, file_)
        except Exception as e:
            logger.warn("Error updating the RSM version state ({0}): {1}", self._get_rsm_version_state_file(), ustr(e))

    def _get_is_version_from_rsm(self):
        """
        Returns isVersionFromRSM property of most recent goal state or False if the most recent
        goal state was not added this property or set to False in gs.
        """
        if not os.path.exists(self._get_rsm_version_state_file()):
            return False

        try:
            with open(self._get_rsm_version_state_file(), "r") as file_:
                return json.load(file_)["isVersionFromRSM"]
        except Exception as e:
            logger.warn(
                "Can't retrieve the is_version_from_rsm most recent rsm state ({0}), will assume it False. Error: {1}",
                self._get_rsm_version_state_file(), ustr(e))
        return False

    def _get_is_vm_enabled_for_rsm_upgrades(self):
        """
        Returns isVMEnabledForRSMUpgrades property of most recent goal state or False if the most recent
        goal state was not added this property or set to False in gs.
        """
        if not os.path.exists(self._get_rsm_version_state_file()):
            return False

        try:
            with open(self._get_rsm_version_state_file(), "r") as file_:
                return json.load(file_)["isVMEnabledForRSMUpgrades"]
        except Exception as e:
            logger.warn(
                "Can't retrieve the is_vm_enabled_for_rsm_upgrades most recent rsm state ({0}), will assume it False. Error: {1}",
                self._get_rsm_version_state_file(), ustr(e))
        return False

    def _get_rsm_state_used_gs_timestamp(self):
        """
        Returns the timestamp of th goal state used for rsm state, or min if the most recent
        goal state has not been invoked.
        """
        if not os.path.exists(self._get_rsm_version_state_file()):
            return timeutil.create_timestamp(datetime.datetime.min)

        try:
            with open(self._get_rsm_version_state_file(), "r") as file_:
                return json.load(file_)["timestamp"]

        except Exception as e:
            logger.warn(
                "Can't retrieve the timestamp of goal state used for rsm state ({0}), will assume the datetime.min time. Error: {1}",
                self._get_rsm_version_state_file(), ustr(e))
        return timeutil.create_timestamp(datetime.datetime.min)

    def _update_rsm_version_state_if_changed(self, goalstate_timestamp, agent_family):
        """
        Persisting state to address the issue when HGPA supported(properties present) to unsupported(properties not present) and also sync between Wireserver and HGAP.
        Updates the isVrsionFromRSM and isVMEnabledForRSMUpgrades of the most recent goal state retrieved if
        properties changed from last rsm state.
        Timestamp is the timestamp of the goal state used to update the state. This timestamp helps ignore old goal states when it gets to the vm as a recent goal state.
        """
        last_timestamp = self._get_rsm_state_used_gs_timestamp()
        # update the state if the goal state is newer than the last goal state used to update the state.
        if last_timestamp < goalstate_timestamp:
            update_file = False
            if agent_family.is_version_from_rsm is not None and self._is_version_from_rsm != agent_family.is_version_from_rsm:
                self._is_version_from_rsm = agent_family.is_version_from_rsm
                update_file = True

            if agent_family.is_vm_enabled_for_rsm_upgrades is not None and self._is_vm_enabled_for_rsm_upgrades != agent_family.is_vm_enabled_for_rsm_upgrades:
                self._is_vm_enabled_for_rsm_upgrades = agent_family.is_vm_enabled_for_rsm_upgrades
                update_file = True

            if update_file:
                self._save_rsm_version_state(self._is_version_from_rsm, self._is_vm_enabled_for_rsm_upgrades, goalstate_timestamp)

    def _get_agent_family_manifest(self, goal_state):
        """
        Get the agent_family from last GS for the given family
        Returns: first entry of Manifest
                 Exception if no manifests found in the last GS
        """
        family = self._ga_family
        agent_families = goal_state.extensions_goal_state.agent_families
        family_found = False
        agent_family_manifests = []
        for m in agent_families:
            if m.name == family:
                family_found = True
                if len(m.uris) > 0:
                    agent_family_manifests.append(m)

        if not family_found:
            raise AgentUpdateError(u"Agent family: {0} not found in the goal state incarnation: {1}, skipping agent update".format(family, self._gs_id))

        if len(agent_family_manifests) == 0:
            raise AgentUpdateError(
                u"No manifest links found for agent family: {0} for incarnation: {1}, skipping agent update".format(
                    self._ga_family, self._gs_id))
        return agent_family_manifests[0]

    @staticmethod
    def _get_version_from_gs(agent_family):
        """
        Get the version from agent family
        Returns: version if supported and available in the GS
                 None if version is missing
        """
        if agent_family.version is not None:
            return FlexibleVersion(agent_family.version)
        return None

    def run(self, goal_state):

        try:
            # Ignore new agents if update is disabled. The latter flag only used in e2e tests.
            if not self._autoupdate_enabled or not conf.get_download_new_agents():
                return

            agent_family = self._get_agent_family_manifest(goal_state)
            version = self._get_version_from_gs(agent_family)
            gs_id = goal_state.extensions_goal_state.id
            self._update_rsm_version_state_if_changed(goal_state.extensions_goal_state.created_on_timestamp, agent_family)
            # if version is specified and vm is enabled for rsm upgrades, use rsm update path, else sef-update
            if version is None and self._is_vm_enabled_for_rsm_upgrades and self._is_version_from_rsm:
                raise AgentUpdateError("VM Enabled for RSM upgrades but version is missing in Goal state: {0}, so skipping agent update".format(gs_id))
            elif conf.get_enable_ga_versioning() and self._is_vm_enabled_for_rsm_upgrades:
                updater = RSMVersionUpdater(gs_id, agent_family, None, version, self.update_state, self._is_version_from_rsm, self._daemon_version)
                self.update_state.last_attempted_update_version = version
            else:
                updater = SelfUpdateVersionUpdater(gs_id, agent_family, None, None, self.update_state)

            # verify if agent update is allowed
            if not updater.should_update_agent(goal_state):
                return
            updater.log_new_agent_update_message()
            updater.purge_extra_agents_from_disk()
            agent = updater.download_and_get_new_agent(self._protocol, goal_state)
            if agent.is_blacklisted or not agent.is_downloaded:
                msg = "Downloaded agent version is in bad state : {0} , skipping agent update".format(
                    str(agent.version))
                raise AgentUpdateError(msg)
            updater.proceed_with_update()

        except Exception as err:
            if isinstance(err, AgentUpgradeExitException):
                raise err
            elif isinstance(err, AgentUpdateError):
                error_msg = ustr(err)
            else:
                error_msg = "Unable to update Agent: {0}".format(textutil.format_exception(err))
            logger.warn(error_msg)
            add_event(op=WALAEventOperation.AgentUpgrade, is_success=False, message=error_msg, log_event=False)
            self.update_state.last_attempted_update_error_msg = error_msg

    def get_vmagent_update_status(self):
        """
        This function gets the VMAgent update status as per the last attempted update.
        Returns: None if fail to report or update never attempted with rsm version specified in GS
        """
        try:
            if conf.get_enable_ga_versioning() and self._is_vm_enabled_for_rsm_upgrades and self._is_version_from_rsm:
                if not self.update_state.last_attempted_update_error_msg:
                    status = VMAgentUpdateStatuses.Success
                    code = 0
                else:
                    status = VMAgentUpdateStatuses.Error
                    code = 1
                return VMAgentUpdateStatus(expected_version=str(self.update_state.last_attempted_update_version), status=status, code=code, message=self.update_state.last_attempted_update_error_msg)
        except Exception as err:
            msg = "Unable to report agent update status: {0}".format(textutil.format_exception(err))
            logger.warn(msg)
            add_event(op=WALAEventOperation.AgentUpgrade, is_success=False, message=msg, log_event=True)
        return None


class GAVersionUpdater(object):

    def __init__(self, gs_id, agent_family, agent_manifest, version, update_state):
        self._gs_id = gs_id
        self._agent_family = agent_family
        self._agent_manifest = agent_manifest
        self._version = version
        self._update_state = update_state

    def should_update_agent(self, goal_state):
        """
        RSM version update:
            update is allowed once per (as specified in the conf.get_autoupdate_frequency()) and
            if new version not same as current version, not below than daemon version and if version is from rsm request
            return false when we don't allow updates.
        self-update:
            1) checks if we allowed download manifest as per manifest download frequency
            2) update is allowed once per (as specified in the conf.get_self_update_hotfix_frequency() or conf.get_self_update_regular_frequency())
            3) not below than current version
            return false when we don't allow updates.
        """
        raise NotImplementedError

    def log_new_agent_update_message(self):
        """
        This function logs the update message after we check agent allowed to update.
        """
        raise NotImplementedError

    def purge_extra_agents_from_disk(self):
        """
        RSM version update:
            remove the agents( including rsm version if exists) from disk except current version. There is a chance that rsm version could exist and/or blacklisted
            on previous update attempts. So we should remove it from disk in order to honor current rsm version update.
        self-update:
            remove the agents from disk except current version and new agent version if exists
        """
        raise NotImplementedError

    def proceed_with_update(self):
        """
        RSM version update:
                upgrade/downgrade to the specified version.
                Raises: AgentUpgradeExitException
        self-update:
                If largest version is found in manifest, upgrade to that version. Downgrade is not supported.
                Raises: AgentUpgradeExitException
        """
        raise NotImplementedError

    def download_and_get_new_agent(self, protocol, goal_state):
        """
        This function downloads the new agent and returns the downloaded version.
        """
        if self._agent_manifest is None:  # Fetch agent manifest if it's not already done
            self._agent_manifest = goal_state.fetch_agent_manifest(self._agent_family.name, self._agent_family.uris)
        package_to_download = self._get_agent_package_to_download(self._agent_manifest, self._version)
        is_fast_track_goal_state = goal_state.extensions_goal_state.source == GoalStateSource.FastTrack
        agent = GuestAgent.from_agent_package(package_to_download, protocol, is_fast_track_goal_state)
        return agent

    def _get_agent_package_to_download(self, agent_manifest, version):
        """
        Returns the package of the given Version found in the manifest. If not found, returns exception
        """
        for pkg in agent_manifest.pkg_list.versions:
            if FlexibleVersion(pkg.version) == version:
                # Found a matching package, only download that one
                return pkg

        raise AgentUpdateError("No matching package found in the agent manifest for version: {0} in goal state incarnation: {1}, "
                        "skipping agent update".format(str(version), self._gs_id))

    @staticmethod
    def _purge_unknown_agents_from_disk(known_agents):
        """
        Remove from disk all directories and .zip files of unknown agents
        """
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))

        for agent_path in glob.iglob(path):
            try:
                name = fileutil.trim_ext(agent_path, "zip")
                m = AGENT_DIR_PATTERN.match(name)
                if m is not None and FlexibleVersion(m.group(1)) not in known_agents:
                    if os.path.isfile(agent_path):
                        logger.info(u"Purging outdated Agent file {0}", agent_path)
                        os.remove(agent_path)
                    else:
                        logger.info(u"Purging outdated Agent directory {0}", agent_path)
                        shutil.rmtree(agent_path)
            except Exception as e:
                logger.warn(u"Purging {0} raised exception: {1}", agent_path, ustr(e))


class RSMVersionUpdater(GAVersionUpdater):
    def __init__(self, gs_id, agent_family, agent_manifest, version, update_state, is_version_from_rsm, daemon_version):
        super(RSMVersionUpdater, self).__init__(gs_id, agent_family, agent_manifest, version, update_state)
        self._is_version_from_rsm = is_version_from_rsm
        self._daemon_version = daemon_version

    @staticmethod
    def _get_all_agents_on_disk():
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))
        return [GuestAgent.from_installed_agent(path=agent_dir) for agent_dir in glob.iglob(path) if os.path.isdir(agent_dir)]

    def _get_available_agents_on_disk(self):
        available_agents = [agent for agent in self._get_all_agents_on_disk() if agent.is_available]
        return sorted(available_agents, key=lambda agent: agent.version, reverse=True)

    def _is_update_allowed_this_time(self):
        """
        update is allowed once per (as specified in the conf.get_autoupdate_frequency())
        If update allowed, we update the last_attempted_rsm_version_update_time to current time.
        """
        now = datetime.datetime.now()

        if self._update_state.last_attempted_rsm_version_update_time != datetime.datetime.min:
            next_attempt_time = self._update_state.last_attempted_rsm_version_update_time + datetime.timedelta(
                seconds=conf.get_autoupdate_frequency())
        else:
            next_attempt_time = now

        if next_attempt_time > now:
            return False
        self._update_state.last_attempted_rsm_version_update_time = now
        # The time limit elapsed for us to allow updates.
        return True

    def should_update_agent(self, goal_state):
        if not self._is_update_allowed_this_time():
            return False

        # we don't allow updates if version is not from RSM or downgrades below daemon version or if version is same as current version
        if not self._is_version_from_rsm or self._version < self._daemon_version or self._version == CURRENT_VERSION:
            return False

        return True

    def log_new_agent_update_message(self):
        msg = "New agent version:{0} requested by RSM in Goal state {1}, will update the agent before processing the goal state.".format(str(self._version), self._gs_id)
        logger.info(msg)
        add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False)

    def purge_extra_agents_from_disk(self):
        known_agents = [CURRENT_VERSION]
        self._purge_unknown_agents_from_disk(known_agents)

    def proceed_with_update(self):
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
            "Agent completed all update checks, exiting current process to {0} to the new Agent version {1}".format(prefix,
                                                                                                     self._version))


class SelfUpdateVersionUpdater(GAVersionUpdater):

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

    def _get_next_upgrade_times(self, now):
        """
        Get the next upgrade times
        return: Next Hotfix Upgrade Time, Next Regular Upgrade Time
        """

        def get_next_process_time(last_val, frequency):
            return now if last_val == datetime.datetime.min else last_val + datetime.timedelta(seconds=frequency)

        next_hotfix_time = get_next_process_time(self._update_state.last_attempted_self_update_hotfix_time,
                                                 conf.get_self_update_hotfix_frequency())
        next_regular_time = get_next_process_time(self._update_state.last_attempted_self_update_regular_time,
                                                  conf.get_self_update_regular_frequency())

        return next_hotfix_time, next_regular_time

    def _is_update_allowed_this_time(self):
        """
        This method ensure that update is allowed only once per (hotfix/Regular) upgrade frequency
        """
        now = datetime.datetime.now()
        next_hotfix_time, next_regular_time = self._get_next_upgrade_times(now)
        upgrade_type = self._get_agent_upgrade_type(self._version)

        if (upgrade_type == SelfUpdateType.Hotfix and next_hotfix_time <= now) or (
                upgrade_type == SelfUpdateType.Regular and next_regular_time <= now):
            # Update the last upgrade check time even if no new agent is available for upgrade
            self._update_state.last_attempted_self_update_hotfix_time = now
            self._update_state.last_attempted_self_update_regular_time = now
            return True
        return False

    def _should_agent_attempt_manifest_download(self):
        """
        The agent should attempt to download the manifest if
        the agent has not attempted to download the manifest in the last 1 hour
        If we allow update, we update the last attempted manifest download time
        """
        now = datetime.datetime.now()

        if self._update_state.last_attempted_manifest_download_time != datetime.datetime.min:
            next_attempt_time = self._update_state.last_attempted_manifest_download_time + datetime.timedelta(seconds=conf.get_autoupdate_frequency())
        else:
            next_attempt_time = now

        if next_attempt_time > now:
            return False
        self._update_state.last_attempted_manifest_download_time = now
        return True

    def should_update_agent(self, goal_state):
        # First we check if we allowed to download the manifest
        if not self._should_agent_attempt_manifest_download():
            return False

        # Fetch agent manifest to find largest version
        self._agent_manifest = goal_state.fetch_agent_manifest(self._agent_family.name, self._agent_family.uris)
        largest_version = self._get_largest_version(self._agent_manifest)
        self._version = largest_version

        if not self._is_update_allowed_this_time():
            return False

        if self._version <= CURRENT_VERSION:
            return False

        return True

    def log_new_agent_update_message(self):
        msg = "Self-update discovered new agent version:{0} in agent manifest for goal state {1}, will update the agent before processing the goal state.".format(
            str(self._version), self._gs_id)
        logger.info(msg)
        add_event(op=WALAEventOperation.AgentUpgrade, message=msg, log_event=False)

    def purge_extra_agents_from_disk(self):
        known_agents = [CURRENT_VERSION, self._version]
        self._purge_unknown_agents_from_disk(known_agents)

    def proceed_with_update(self):
        if self._version > CURRENT_VERSION:
            # In case of an upgrade, we don't need to exclude anything as the daemon will automatically
            # start the next available highest version which would be the target version
            raise AgentUpgradeExitException("Agent completed all update checks, exiting current process to upgrade to the new Agent version {0}".format(self._version))