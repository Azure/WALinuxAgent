import datetime
import glob
import os
import shutil

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logger import LogLevel
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateSource
from azurelinuxagent.common.protocol.restapi import VMAgentUpdateStatuses, VMAgentUpdateStatus
from azurelinuxagent.common.utils import fileutil, textutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import CURRENT_VERSION, AGENT_NAME, AGENT_DIR_PATTERN
from azurelinuxagent.ga.guestagent import GuestAgent, GAUpdateReportState


def get_agent_update_handler(protocol):
    return AgentUpdateHandler(protocol)


class AgentUpdateHandler(object):

    def __init__(self, protocol):
        self._protocol = protocol
        self._ga_family = conf.get_autoupdate_gafamily()
        self._autoupdate_enabled = conf.get_autoupdate_enabled()
        self._gs_id = self._protocol.get_goal_state().extensions_goal_state.id
        self._last_attempted_update_time = datetime.datetime.min
        self._last_attempted_update_version = FlexibleVersion("0.0.0.0")

    def __should_update_agent(self, requested_version):
        """
        check to see if update is allowed once per (as specified in the conf.get_autoupdate_frequency())
        return false when we don't allow updates.
        """
        now = datetime.datetime.now()

        if self._last_attempted_update_time != datetime.datetime.min and self._last_attempted_update_version == requested_version:
            next_attempt_time = self._last_attempted_update_time + datetime.timedelta(seconds=conf.get_autoupdate_frequency())
        else:
            next_attempt_time = now

        if next_attempt_time > now:
            return False
        # The time limit elapsed for us to allow updates.
        return True

    def __get_agent_family_from_last_gs(self, goal_state):
        """
        Get the agent_family from last GS for the given family
        Returns: first entry of Manifest
                 Exception if no manifests found in the last GS
        """
        family = self._ga_family
        agent_families = goal_state.extensions_goal_state.agent_families
        agent_family_manifests = [m for m in agent_families if m.name == family and len(m.uris) > 0]
        if len(agent_family_manifests) == 0:
            raise Exception(
                u"No manifest links found for agent family: {0} for incarnation: {1}, skipping agent update".format(
                    self._ga_family, self._gs_id))
        return agent_family_manifests[0]

    @staticmethod
    def __get_requested_version(agent_family):
        """
        Get the requested version from agent family
        Returns: Requested version if supported and available
                 None if requested version missing or GA versioning not enabled
        """
        if conf.get_enable_ga_versioning() and agent_family.is_requested_version_specified:
            if agent_family.requested_version is not None:
                return FlexibleVersion(agent_family.requested_version)
        return None

    @staticmethod
    def __get_largest_version(agent_manifest):
        largest_version = FlexibleVersion("0.0.0.0")
        for pkg in agent_manifest.pkg_list.versions:
            pkg_version = FlexibleVersion(pkg.version)
            if pkg_version > largest_version:
                largest_version = pkg_version
        return largest_version

    def __download_and_get_agent(self, goal_state, agent_family, agent_manifest, requested_version):
        """
        This function downloads the new agent(requested version) and returns the downloaded version.
        """
        if agent_manifest is None:  # Fetch agent manifest if it's not already done
            agent_manifest = goal_state.fetch_agent_manifest(agent_family.name, agent_family.uris)
        package_to_download = self.__get_agent_package_to_download(agent_manifest, requested_version)
        is_fast_track_goal_state = goal_state.extensions_goal_state.source == GoalStateSource.FastTrack
        agent = GuestAgent.from_agent_package(package_to_download, self._protocol, is_fast_track_goal_state)
        return agent

    def __get_agent_package_to_download(self, agent_manifest, version):
        """
        Returns the package of the given Version found in the manifest. If not found, returns exception
        """
        for pkg in agent_manifest.pkg_list.versions:
            if FlexibleVersion(pkg.version) == version:
                # Found a matching package, only download that one
                return pkg

        raise Exception("No matching package found in the agent manifest for requested version: {0} in goal state incarnation: {1}, "
                        "skipping agent update".format(str(version), self._gs_id))

    @staticmethod
    def __purge_extra_agents_from_disk(known_agents):
        """
        Remove from disk all directories and .zip files of unknown agents
        (without removing the current, running agent).
        """
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))

        known_versions = [agent.version for agent in known_agents]
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

    @staticmethod
    def __proceed_with_update(requested_version):
        """
        If requested version is specified, upgrade/downgrade to the specified version.
        Raises: AgentUpgradeExitException
        """
        if requested_version < CURRENT_VERSION:
            # In case of a downgrade, we mark the current agent as bad version to avoid starting it back up ever again
            # (the expectation here being that if we get request to a downgrade,
            # there's a good reason for not wanting the current version).
            prefix = "downgrade"
            try:
                # We should always have an agent directory for the CURRENT_VERSION
                agents_on_disk = AgentUpdateHandler.__get_available_agents_on_disk()
                current_agent = next(agent for agent in agents_on_disk if agent.version == CURRENT_VERSION)
                msg = "Marking the agent {0} as bad version since a downgrade was requested in the GoalState, " \
                      "suggesting that we really don't want to execute any extensions using this version".format(CURRENT_VERSION)
                logger.info(msg)
                current_agent.mark_failure(is_fatal=True, reason=msg)
            except StopIteration:
                logger.warn(
                    "Could not find a matching agent with current version {0} to blacklist, skipping it".format(
                        CURRENT_VERSION))
        else:
            # In case of an upgrade, we don't need to exclude anything as the daemon will automatically
            # start the next available highest version which would be the target version
            prefix = "upgrade"
        raise AgentUpgradeExitException("Agent update found, Exiting current process to {0} to the new Agent version {1}".format(prefix, requested_version))

    @staticmethod
    def __get_available_agents_on_disk():
        available_agents = [agent for agent in AgentUpdateHandler.__get_all_agents_on_disk() if agent.is_available]
        return sorted(available_agents, key=lambda agent: agent.version, reverse=True)

    @staticmethod
    def __get_all_agents_on_disk():
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))
        return [GuestAgent.from_installed_agent(path=agent_dir) for agent_dir in glob.iglob(path) if os.path.isdir(agent_dir)]

    @staticmethod
    def __log_event(level, msg_, success_=True):
        if level == LogLevel.WARNING:
            logger.warn(msg_)
        elif level == LogLevel.ERROR:
            logger.error(msg_)
        elif level == LogLevel.INFO:
            logger.info(msg_)
        add_event(op=WALAEventOperation.AgentUpgrade, is_success=success_, message=msg_, log_event=False)

    def run(self, goal_state):
        try:
            # Ignore new agents if update is disabled. The latter flag only used in e2e tests.
            if not self._autoupdate_enabled or not conf.get_ga_updates_enabled():
                return

            self._gs_id = goal_state.extensions_goal_state.id
            agent_family = self.__get_agent_family_from_last_gs(goal_state)
            requested_version = self.__get_requested_version(agent_family)
            agent_manifest = None  # This is to make sure fetch agent manifest once per update

            if requested_version is None:
                if conf.get_enable_ga_versioning():  # log the warning only when ga versioning is enabled
                    warn_msg = "Missing requested version in agent family: {0} for incarnation: {1}, fallback to largest version update".format(self._ga_family, self._gs_id)
                    self.__log_event(LogLevel.WARNING, warn_msg)
                    GAUpdateReportState.report_error_msg = warn_msg
                agent_manifest = goal_state.fetch_agent_manifest(agent_family.name, agent_family.uris)
                requested_version = self.__get_largest_version(agent_manifest)
            else:
                # Save the requested version to report back
                GAUpdateReportState.report_expected_version = requested_version
                # Remove the missing requested version warning once requested version becomes available
                if "Missing requested version" in GAUpdateReportState.report_error_msg:
                    GAUpdateReportState.report_error_msg = ""

            if requested_version == CURRENT_VERSION:
                return

            # Check if an update is allowed
            if not self.__should_update_agent(requested_version):
                return

            msg_ = "Goal state {0} is requesting a new agent version {1}, will update the agent before processing the goal state.".format(
                self._gs_id, str(requested_version))
            self.__log_event(LogLevel.INFO, msg_)

            try:
                agent = self.__download_and_get_agent(goal_state, agent_family, agent_manifest, requested_version)

                if not agent.is_available:
                    msg = "Downloaded agent version is in bad state : {0} , skipping agent update".format(
                        str(agent.version))
                    self.__log_event(LogLevel.WARNING, msg)
                    return

                # We delete the directory and the zip package from the filesystem except current version and target version
                self.__purge_extra_agents_from_disk(known_agents=[agent])
                self.__proceed_with_update(requested_version)

            finally:
                self._last_attempted_update_time = datetime.datetime.now()
                self._last_attempted_update_version = requested_version

        except Exception as err:
            if isinstance(err, AgentUpgradeExitException):
                raise err
            if "Missing requested version" not in GAUpdateReportState.report_error_msg:
                GAUpdateReportState.report_error_msg = "Unable to update Agent: {0}".format(textutil.format_exception(err))
            self.__log_event(LogLevel.WARNING, GAUpdateReportState.report_error_msg, success_=False)

    def get_vmagent_update_status(self):
        """
        This function gets the VMAgent update status as per the last attempted update.
        Returns: None if fail to report or update never attempted with requested version
        """
        try:
            if conf.get_enable_ga_versioning():
                if not GAUpdateReportState.report_error_msg:
                    status = VMAgentUpdateStatuses.Success
                    code = 0
                else:
                    status = VMAgentUpdateStatuses.Error
                    code = 1
                return VMAgentUpdateStatus(expected_version=str(GAUpdateReportState.report_expected_version), status=status, code=code, message=GAUpdateReportState.report_error_msg)
        except Exception as err:
            self.__log_event(LogLevel.WARNING, "Unable to report agent update status: {0}".format(
                                                       textutil.format_exception(err)), success_=False)
        return None
