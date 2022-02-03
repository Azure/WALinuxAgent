import shutil
import time

import os

import glob
from datetime import datetime

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logger import LogLevel
from azurelinuxagent.common.protocol.restapi import VERSION_0, VMAgentUpdateStatuses, VMAgentUpdateStatus
from azurelinuxagent.common.utils import textutil, fileutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import get_daemon_version, CURRENT_VERSION, AGENT_NAME, AGENT_DIR_PATTERN
from azurelinuxagent.ga.update import GuestAgent


def get_agent_update_handler(protocol):
    return AgentUpdateHandler(protocol)


class _PersistentUpdateHandlerState(object):
    """
    This class is primarily used to maintain the in-memory persistent state for the agent updates.
    This state will be persisted throughout the current service run and might be modified by external classes.
    """

    def __init__(self):
        now = time.time()
        self.last_update_available_check_time = None
        self.last_hotfix_upgrade_time = None
        self.last_normal_upgrade_time = None


class AgentUpdateHandler(object):
    """
        This class handles checks for new Agent updates and raises AgentUpgradeExitException if available.
        There are 2 different ways the agent checks for an update -
            1) Requested Version is specified in the Goal State.
                - In this case, the Agent will download the requested version and upgrade/downgrade instantly.
            2) No requested version.
                - In this case, the agent will periodically check (1 hr) for new agent versions in GA Manifest.
                - If available, it will download all versions > CURRENT_VERSION.
                - Depending on the highest version > CURRENT_VERSION,
                  the agent will update within 4 hrs (for a Hotfix update) or 24 hrs (for a Normal update)
        """

    def __init__(self, protocol):
        self.__protocol = protocol
        self.__daemon_version = self.__get_daemon_version_for_update()
        self.__ga_family = conf.get_autoupdate_gafamily()
        self.__autoupdate_enabled = conf.get_autoupdate_enabled()
        self.persistent_update_data = _PersistentUpdateHandlerState()

    @property
    def protocol(self):
        return self.__protocol

    @property
    def daemon_version(self):
        return self.__daemon_version

    @property
    def ga_family(self):
        return self.__ga_family

    @property
    def autoupdate_enabled(self):
        return self.__autoupdate_enabled

    @staticmethod
    def __get_daemon_version_for_update():
        daemon_version = get_daemon_version()
        if daemon_version != FlexibleVersion(VERSION_0):
            return daemon_version
        # We return 0.0.0.0 if daemon version is not specified. In that case,
        # use the min version as 2.2.53 as we started setting the daemon version starting 2.2.53.
        return FlexibleVersion("2.2.53")

    def __get_requested_version_and_manifest_from_last_gs(self):
        """
        Get the requested version and corresponding manifests from last GS if supported
        Returns: (Requested Version, Manifest) if supported and available
                 (None, None) if no manifests found in the last GS
                 (None, manifest) if not supported or not specified in GS
        """
        family = conf.get_autoupdate_gafamily()
        manifest_list, _ = self.protocol.get_vmagent_manifests()
        manifests = [m for m in manifest_list if m.family == family and len(m.uris) > 0]
        if len(manifests) == 0:
            return None, None
        if conf.get_enable_ga_versioning() and manifests[0].is_requested_version_specified:
            return manifests[0].requested_version, manifests[0]
        return None, manifests[0]

    @staticmethod
    def __log_if_gs_updated(gs_updated, level, msg_, success_=False):
        if gs_updated:
            logger.log(level, msg_)
            add_event(op=WALAEventOperation.AgentUpgrade, is_success=success_, message=msg_, log_event=False)
        else:
            logger.verbose(msg_)

    def run(self, gs_updated, host, base_version=CURRENT_VERSION):

        # Ignore new agents if updating is disabled
        if not self.autoupdate_enabled:
            return

        try:
            updater = self.get_updater()
            self._process_update_if_available(updater, gs_updated, host, base_version)
            updater.process_post_update_available_ops()
        except AgentUpgradeExitException:
            raise
        except Exception as err:
            AgentUpdateHandler.__log_if_gs_updated(gs_updated, LogLevel.WARNING,
                                                   "Unable to update Agent: {0}".format(textutil.format_exception(err)))

    def _process_update_if_available(self, updater, gs_updated, host, base_version):
        """
        This function downloads the new agent if an update is available and updates to that version depending on the Agent Updater.
        """
        if not updater.can_update(gs_updated):
            return

        packages_to_download = updater.get_agent_package_list_to_download(self.protocol)
        agents = AgentUpdateHandler.__download_and_get_agents(packages_to_download, host)
        # If the agent was not installed properly, we delete the directory and the zip package from the filesystem
        AgentUpdateHandler.__purge_extra_agents_from_disk(known_agents=agents)

        if not any(agents) or not updater.is_update_available(agents[0], base_version):
            return

        updater.process_update(agents[0])

    def get_updater(self):
        # Fetch the agent manifests from the latest Goal State
        requested_version, manifest = self.__get_requested_version_and_manifest_from_last_gs()
        gs_id = self.protocol.get_incarnation()
        if manifest is None:
            raise Exception(
                u"No manifest links found for agent family: {0} for incarnation: {1}, skipping update check".format(
                    self.ga_family, gs_id))

        if requested_version is not None:
            # If GA versioning is enabled and requested version present in GS, use the Requested Version Updater
            return _RequestedGAVersionUpdater(requested_version, manifest, gs_id, self.ga_family, self.daemon_version)
        else:
            # If no requested version specified in the Goal State, use the Largest GA Version Updater
            # Note: If the first Goal State contains a requested version, this timer won't start (i.e. self.last_attempt_time won't be updated).
            # If any subsequent goal state does not contain requested version, this timer will start then, and we will
            # download all versions available in PIR and auto-update to the highest available version on that goal state.
            return _LargestGAVersionAvailableUpdater(manifest, gs_id, self.ga_family, self.daemon_version,
                                                     self.persistent_update_data)

    @staticmethod
    def __purge_extra_agents_from_disk(known_agents):
        """
        Remove from disk all directories and .zip files of unknown agents
        (without removing the current, running agent).
        """
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))

        known_versions = [agent.version for agent in known_agents]
        if CURRENT_VERSION not in known_versions:
            logger.verbose(
                u"Running Agent {0} was not found in the agent manifest - adding to list",
                CURRENT_VERSION)
            known_versions.append(CURRENT_VERSION)

        for agent_path in glob.iglob(path):
            try:
                name = fileutil.trim_ext(agent_path, "zip")
                m = AGENT_DIR_PATTERN.match(name)
                if m is not None and FlexibleVersion(m.group(1)) not in known_versions:
                    if os.path.isfile(agent_path):
                        logger.info(u"Purging outdated Agent file {0}", agent_path)
                        os.remove(agent_path)
                    else:
                        logger.info(u"Purging outdated Agent directory {0}", agent_path)
                        shutil.rmtree(agent_path)
            except Exception as e:
                logger.warn(u"Purging {0} raised exception: {1}", agent_path, ustr(e))

    def get_vmagent_update_status(self, gs_updated):
        """
        This function gets the VMAgent update status as per the last GoalState.
        Returns: None if the last GS does not ask for requested version else VMAgentUpdateStatus
        """

        try:
            updater = self.get_updater()
            return updater.get_vm_update_status()
        except Exception as err:
            AgentUpdateHandler.__log_if_gs_updated(gs_updated, LogLevel.WARNING,
                                                   "Unable to report agent update status: {0}".format(
                                                       textutil.format_exception(err)))
        return None

    @staticmethod
    def __download_and_get_agents(packages_to_download, host):
        """
        Download the agents that were requested by the Updaters.
        Filter out the agents that were downloaded/extracted successfully.
        """
        agents_to_download = [GuestAgent(pkg=pkg, host=host) for pkg in packages_to_download]
        agents = [agent for agent in agents_to_download if agent.is_available]
        return sorted(agents, key=lambda agent: agent.version, reverse=True)

    @staticmethod
    def get_available_agents_on_disk():
        available_agents = [agent for agent in AgentUpdateHandler.get_all_agents_on_disk() if not agent.is_blacklisted]
        return sorted(available_agents, key=lambda agent: agent.version, reverse=True)

    @staticmethod
    def get_all_agents_on_disk():
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))
        return [GuestAgent(path=agent_dir) for agent_dir in glob.iglob(path) if os.path.isdir(agent_dir)]


class _GuestAgentUpdaterInterface(object):

    def __init__(self, manifest, gs_id, ga_family, daemon_version):
        self.__manifest = manifest
        self.__ga_family = ga_family
        self.__gs_id = gs_id
        self.__daemon_version = daemon_version

    @property
    def manifest(self):
        return self.__manifest

    @property
    def ga_family(self):
        return self.__ga_family

    @property
    def gs_id(self):
        return self.__gs_id

    @property
    def daemon_version(self):
        return self.__daemon_version

    def get_agent_package_list_to_download(self, protocol):
        raise NotImplementedError

    def is_update_available(self, largest_agent, base_version):
        raise NotImplementedError

    def can_update(self, gs_updated):
        raise NotImplementedError

    def process_update(self, largest_agent):
        raise NotImplementedError

    def process_post_update_available_ops(self):
        raise NotImplementedError

    def get_vm_update_status(self):
        raise NotImplementedError


class _RequestedGAVersionUpdater(_GuestAgentUpdaterInterface):

    def __init__(self, requested_version, manifest, gs_id, ga_family, daemon_version):
        super(_RequestedGAVersionUpdater, self).__init__(manifest, gs_id, ga_family, daemon_version)
        self.__requested_version = requested_version

    @property
    def requested_version(self):
        return self.__requested_version

    def can_update(self, gs_updated):
        if not gs_updated:
            # If incarnation didn't change, don't process anything.
            return False

        # We will get a new GS when CRP wants us to auto-update using required version.
        # If there's no new incarnation, don't proceed with anything
        msg_ = "Found requested version in manifest: {0} for incarnation: {1}".format(self.requested_version, self.gs_id)
        logger.info(msg_)
        add_event(op=WALAEventOperation.AgentUpgrade, is_success=True, message=msg_, log_event=False)

        if self.requested_version < self.daemon_version:
            # Don't process the update if the requested version is lesser than daemon version,
            # as we don't support downgrades below daemon versions.
            msg = "Can't process the upgrade as the requested version: {0} is < current daemon version: {1}".format(
                self.requested_version, self.daemon_version)
            logger.warn(msg)
            add_event(op=WALAEventOperation.AgentUpgrade, is_success=False, message=msg, log_event=False)
            return False

        # A requested version in a new GS.
        return True

    def get_agent_package_list_to_download(self, protocol):
        """
        Returns the package of the Requested Version that was specified in the GS.
        If the Requested Version == Current Version, returns empty list
        """
        if self.requested_version == CURRENT_VERSION:
            # If the requested version is the current version, don't download anything;
            # In this case, no need to even fetch the GA family manifest as we don't need to download any agent.
            msg = "The requested version is running as the current version: {0}".format(self.requested_version)
            logger.info(msg)
            add_event(op=WALAEventOperation.AgentUpgrade, is_success=True, message=msg)
            return []

        pkg_list = protocol.get_vmagent_pkgs(self.manifest)
        for pkg in pkg_list.versions:
            if FlexibleVersion(pkg.version) == self.requested_version:
                # Found a matching package, only download that one
                return [pkg]

        raise Exception("No matching package found in the agent manifest for requested version: {0} in incarnation: {1}, "
                        "skipping agent update".format(self.requested_version, self.gs_id))

    def is_update_available(self, largest_agent, base_version):
        """
        Return True if an agent with a different version number than the current version is available that is
        higher than the current daemon version
        """
        return largest_agent.version != base_version and largest_agent.version > self.daemon_version

    def process_update(self, _):
        """
        If requested version specified, upgrade/downgrade to the specified version instantly as this is
        driven by the goal state.
        Raises: AgentUpgradeExitException
        """
        if self.requested_version < CURRENT_VERSION:
            # In case of a downgrade, we blacklist the current agent to avoid starting it back up ever again
            # (the expectation here being that if RSM is asking us to a downgrade,
            # there's a good reason for not wanting the current version).
            prefix = "downgrade"
            try:
                # We should always have an agent directory for the CURRENT_VERSION
                # (unless the CURRENT_VERSION == daemon version, but since we don't support downgrading
                # below daemon version, we will never reach this code path if that's the scenario)
                agents_on_disk = AgentUpdateHandler.get_available_agents_on_disk()
                current_agent = next(agent for agent in agents_on_disk if agent.version == CURRENT_VERSION)
                msg = "Blacklisting the agent {0} since a downgrade was requested in the GoalState, " \
                      "suggesting that we really don't want to execute any extensions using this version".format(
                       CURRENT_VERSION)
                logger.info(msg)
                current_agent.mark_failure(is_fatal=True, reason=msg)
            except StopIteration:
                logger.warn(
                    "Could not find a matching agent with current version {0} to blacklist, skipping it".format(
                        CURRENT_VERSION))
        else:
            # In case of an upgrade, we don't need to blacklist anything as the daemon will automatically
            # start the next available highest version which would be the requested version
            prefix = "upgrade"
        raise AgentUpgradeExitException(
            "Exiting current process to {0} to the request Agent version {1}".format(prefix, self.requested_version))

    def get_vm_update_status(self):
        if CURRENT_VERSION == self.requested_version:
            status = VMAgentUpdateStatuses.Success
            code = 0
        else:
            status = VMAgentUpdateStatuses.Error
            code = 1
        return VMAgentUpdateStatus(expected_version=str(self.manifest.requested_version), status=status, code=code)

    def process_post_update_available_ops(self):
        # No post-op to perform for Requested Version updates, everything is driven by a GoalState
        pass


class _LargestGAVersionAvailableUpdater(_GuestAgentUpdaterInterface):

    def __init__(self, manifest, gs_id, ga_family, daemon_version, persistent_data):
        super(_LargestGAVersionAvailableUpdater, self).__init__(manifest, gs_id, ga_family, daemon_version)
        self.persistent_data = persistent_data

    def get_agent_package_list_to_download(self, protocol):
        """
        Returns the list of all GA versions specified in the GA Manifest.
        """
        pkg_list = protocol.get_vmagent_pkgs(self.manifest)
        return pkg_list.versions

    def is_update_available(self, largest_agent, base_version):
        """
        return True if the highest agent is > base_version (defaults to the CURRENT_VERSION)
        """
        return largest_agent.version > base_version

    def can_update(self, _):
        """
        Check to see if the Updater is permitted to update. We only check for agent updates once per hour
         (or as specified in the  conf.get_autoupdate_frequency())
        """
        now = time.time()
        if self.persistent_data.last_update_available_check_time is not None:
            next_attempt_time = self.persistent_data.last_update_available_check_time + conf.get_autoupdate_frequency()
        else:
            next_attempt_time = now
        if next_attempt_time > now:
            return False

        logger.info("No requested version specified, checking for all versions for agent update (family: {0})",
                    self.ga_family)
        self.persistent_data.last_update_available_check_time = now

        # The 1hr time limit has elapsed for us to check the agent manifest for updates.
        return True

    def process_update(self, largest_agent):
        """
        If we detect a new agent update, log the details of the Update but don't update just yet.
        This is done to prevent the agent for updating as soon as it detects an update and instead trickle down the updates all through the region.
        """
        next_normal_time, next_hotfix_time = self.__get_next_upgrade_times()
        upgrade_type = self.__get_agent_upgrade_type(largest_agent)
        next_time = next_hotfix_time if upgrade_type == AgentUpgradeType.Hotfix else next_normal_time
        message_ = "Discovered new {0} upgrade {1}; Will upgrade on or after {2}".format(
            upgrade_type, largest_agent.name,
            datetime.utcfromtimestamp(next_time).strftime(logger.Logger.LogTimeFormatInUTC))
        add_event(AGENT_NAME, op=WALAEventOperation.AgentUpgrade, version=CURRENT_VERSION, is_success=True,
                  message=message_, log_event=False)
        logger.info(message_)

    def process_post_update_available_ops(self):
        """
        Check every 4hrs for a Hotfix Upgrade and 24 hours for a Normal upgrade and upgrade the agent if available.
        raises: AgentUpgradeExitException when a new upgrade is available in the relevant time window, else returns
        """

        next_normal_time, next_hotfix_time = self.__get_next_upgrade_times()
        now = time.time()
        # Not permitted to update yet for any of the AgentUpgradeModes
        if next_hotfix_time > now and next_normal_time > now:
            return

        # Update the last upgrade check time even if no new agent is available for upgrade
        self.persistent_data.last_hotfix_upgrade_time = now if next_hotfix_time <= now else self.persistent_data.last_hotfix_upgrade_time
        self.persistent_data.last_normal_upgrade_time = now if next_normal_time <= now else self.persistent_data.last_normal_upgrade_time

        agents_on_disk = AgentUpdateHandler.get_available_agents_on_disk()
        try:
            largest_available_agent = next(agent for agent in agents_on_disk if
                                           agent.is_available and agent.version > CURRENT_VERSION)
        except StopIteration:
            logger.verbose("No agent found on disk > Current agent: {0}".format(CURRENT_VERSION))
            return

        upgrade_type = self.__get_agent_upgrade_type(largest_available_agent)
        upgrade_message = "{0} Agent upgrade discovered, updating to {1} -- exiting".format(upgrade_type,
                                                                                            largest_available_agent.name)

        if (upgrade_type == AgentUpgradeType.Hotfix and next_hotfix_time <= now) or (
                upgrade_type == AgentUpgradeType.Normal and next_normal_time <= now):
            raise AgentUpgradeExitException(upgrade_message)

    def get_vm_update_status(self):
        # We don't need to report update status for this updater
        return None

    def __get_next_upgrade_times(self):
        """
        Get the next upgrade times
        return: Next Normal Upgrade Time, Next Hotfix Upgrade Time
        """

        def get_next_process_time(last_val, frequency):
            return now if last_val is None else last_val + frequency

        now = time.time()
        next_hotfix_time = get_next_process_time(self.persistent_data.last_hotfix_upgrade_time,
                                                 conf.get_hotfix_upgrade_frequency())
        next_normal_time = get_next_process_time(self.persistent_data.last_normal_upgrade_time,
                                                 conf.get_normal_upgrade_frequency())

        return next_normal_time, next_hotfix_time

    @staticmethod
    def __get_agent_upgrade_type(available_agent):
        # We follow semantic versioning for the agent, if <Major>.<Minor> is same, then <Patch>.<Build> has changed.
        # In this case, we consider it as a Hotfix upgrade. Else we consider it a Normal upgrade.
        if available_agent.version.major == CURRENT_VERSION.major and available_agent.version.minor == CURRENT_VERSION.minor:
            return AgentUpgradeType.Hotfix
        return AgentUpgradeType.Normal


class AgentUpgradeType(object):
    """
    Enum for different modes of Agent Upgrade
    """
    Hotfix = "Hotfix"
    Normal = "Normal"
