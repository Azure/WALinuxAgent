import glob
import json
import os
import shutil
import time

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, UpdateError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logger import LogLevel
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateSource
from azurelinuxagent.common.protocol.restapi import VMAgentUpdateStatuses, VMAgentUpdateStatus
from azurelinuxagent.common.utils import fileutil, textutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import CURRENT_VERSION, AGENT_NAME, AGENT_DIR_PATTERN
from azurelinuxagent.ga.exthandlers import HandlerManifest

AGENT_ERROR_FILE = "error.json"  # File name for agent error record
AGENT_MANIFEST_FILE = "HandlerManifest.json"
MAX_FAILURE = 3  # Max failure allowed for agent before declare bad agent


def get_agent_update_handler(protocol):
    return AgentUpdateHandler(protocol)


class PersistentUpdateHandlerState(object):
    """
    This class is primarily used to maintain the in-memory persistent state for the agent updates.
    This state will be persisted throughout the current service run and might be modified by external classes.
    """
    report_error = None


class AgentUpdateHandler(object):

    def __init__(self, protocol):
        self.__protocol = protocol
        self.__ga_family = conf.get_autoupdate_gafamily()
        self.__autoupdate_enabled = conf.get_autoupdate_enabled()
        self.__gs_id = self.protocol.get_goal_state().incarnation
        self._last_attempted_update_time = None
        self._last_attempted_update_version = FlexibleVersion("0.0.0.0")
        self._pkg_list = None

    @property
    def protocol(self):
        return self.__protocol

    @property
    def ga_family(self):
        return self.__ga_family

    @property
    def autoupdate_enabled(self):
        return self.__autoupdate_enabled

    @property
    def gs_id(self):
        return self.__gs_id

    def __is_update_allowed(self, requested_version):
        """
        check to see if update is allowed once per (as specified in the conf.get_autoupdate_frequency())
        """
        now = time.time()

        if self._last_attempted_update_time is not None and self._last_attempted_update_version == requested_version:
            next_attempt_time = self._last_attempted_update_time + conf.get_autoupdate_frequency()
        else:
            next_attempt_time = now

        if next_attempt_time > now:
            return False

        self._last_attempted_update_time = now
        self._last_attempted_update_version = requested_version
        # The time limit elapsed for us to allow updates.
        return True

    def __get_agent_manifest_from_last_gs(self):
        """
        Get the manifests from last GS for the given family
        Returns: first entry of Manifest
                 Exception if no manifests found in the last GS
        """
        family = self.ga_family
        agent_family = self.protocol.get_goal_state().extensions_goal_state.agent_families
        manifests = [m for m in agent_family if m.name == family and len(m.uris) > 0]
        if len(manifests) == 0:
            raise Exception(
                u"No manifest links found for agent family: {0} for incarnation: {1}, skipping agent update".format(
                    self.ga_family, self.gs_id))
        return manifests[0]

    def __fetch_pkg_list(self, agent_manifest):
        """
        Fetch the agent pkg version, and it's uris from manifest
        """
        agent_manifest = self.protocol.get_goal_state().fetch_agent_manifest(agent_manifest.name, agent_manifest.uris)
        self._pkg_list = agent_manifest.pkg_list

    @staticmethod
    def __get_requested_version(agent_manifest):
        """
        Get the requested version from agent manifest
        Returns: Requested version if supported and available
                 None if None of the above is True
        """
        if conf.get_enable_ga_versioning() and agent_manifest.is_requested_version_specified:
            if agent_manifest.requested_version is not None:
                return FlexibleVersion(agent_manifest.requested_version)
        return None

    def _process_update(self, requested_version):
        """
        This function downloads the new agent(requested version) and updates to that version.
        """
        package_to_download = self.__get_agent_package_to_download(requested_version)
        agent = self.__download_and_get_agent(package_to_download)
        # if unable to download/unpack the agent
        if not agent or agent.version != requested_version:
            msg = "Unable to download/unpack the agent version : {0} , skipping agent update".format(requested_version)
            self.__log_event(LogLevel.INFO, msg)
            return
        # We delete the directory and the zip package from the filesystem except current version and target version
        self.__purge_extra_agents_from_disk(known_agents=[agent])
        self.__proceed_with_update(requested_version)

    def __get_agent_package_to_download(self, requested_version):
        """
        Returns the package of the requested Version found in the manifest. If not found, returns exception
        """
        if self._pkg_list is not None:
            for pkg in self._pkg_list.versions:
                if FlexibleVersion(pkg.version) == requested_version:
                    # Found a matching package, only download that one
                    return pkg

        raise Exception("No matching package found in the agent manifest for requested version: {0} in goal state incarnation: {1}, "
                        "skipping agent update".format(str(requested_version), self.gs_id))

    def __download_and_get_agent(self, package_to_download):
        """
        Download the agent that is requested.
        Filter out the agent that is downloaded/extracted successfully.
        """
        is_fast_track_goal_state = self.protocol.get_goal_state().extensions_goal_state.source == GoalStateSource.FastTrack
        agent_to_download = GuestAgent.from_agent_package(package_to_download, self.protocol, is_fast_track_goal_state)
        agent = agent_to_download if agent_to_download.is_available else None
        return agent

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
                # (unless the CURRENT_VERSION == daemon version, but since we don't support downgrading
                # below daemon version, we will never reach this code path if that's the scenario)
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
        available_agents = [agent for agent in AgentUpdateHandler.__get_all_agents_on_disk() if not agent.is_blacklisted]
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

    def run(self):
        try:
            # Ignore new agents if update is disabled
            if not self.autoupdate_enabled:
                return

            agent_manifest = self.__get_agent_manifest_from_last_gs()
            requested_version = self.__get_requested_version(agent_manifest)

            if not requested_version or requested_version == CURRENT_VERSION:
                return

            # Check if an update is allowed
            if not self.__is_update_allowed(requested_version):
                return

            msg_ = "Found requested version: {0} in manifest for goal state incarnation: {1} to update agent".format(
                str(requested_version), self.gs_id)
            self.__log_event(LogLevel.INFO, msg_)

            self.__fetch_pkg_list(agent_manifest)
            self._process_update(requested_version)

        except Exception as err:
            if isinstance(err, AgentUpgradeExitException):
                raise err
            PersistentUpdateHandlerState.report_error = "Unable to update Agent: {0}".format(textutil.format_exception(err))
            self.__log_event(LogLevel.WARNING, PersistentUpdateHandlerState.report_error, success_=False)

    def get_vmagent_update_status(self, gs_updated):
        """
        This function gets the VMAgent update status as per the last GoalState.
        Returns: None if the last GS does not ask for requested version else VMAgentUpdateStatus
        """
        try:
            if not gs_updated:
                return None

            agent_manifest = self.__get_agent_manifest_from_last_gs()
            target_version = self.__get_requested_version(agent_manifest)

            if target_version is not None:
                if CURRENT_VERSION == target_version:
                    status = VMAgentUpdateStatuses.Success
                    code = 0
                    message = ""
                else:
                    status = VMAgentUpdateStatuses.Error
                    code = 1
                    message = PersistentUpdateHandlerState.report_error if PersistentUpdateHandlerState.report_error else ""
                PersistentUpdateHandlerState.report_error = None
                return VMAgentUpdateStatus(expected_version=str(target_version), status=status, code=code, message=message)
        except Exception as err:
            self.__log_event(LogLevel.WARNING, "Unable to report agent update status: {0}".format(
                                                       textutil.format_exception(err)), success_=False)
        return None


class GuestAgent(object):
    def __init__(self, path, pkg, protocol, is_fast_track_goal_state):
        """
        If 'path' is given, the object is initialized to the version installed under that path.

        If 'pkg' is given, the version specified in the package information is downloaded and the object is
        initialized to that version.

        'is_fast_track_goal_state' and 'protocol' are used only when a package is downloaded.

        NOTE: Prefer using the from_installed_agent and from_agent_package methods instead of calling __init__ directly
        """
        self._is_fast_track_goal_state = is_fast_track_goal_state
        self.pkg = pkg
        self._protocol = protocol
        version = None
        if path is not None:
            m = AGENT_DIR_PATTERN.match(path)
            if m is None:
                raise UpdateError(u"Illegal agent directory: {0}".format(path))
            version = m.group(1)
        elif self.pkg is not None:
            version = pkg.version

        if version is None:
            raise UpdateError(u"Illegal agent version: {0}".format(version))
        self.version = FlexibleVersion(version)

        location = u"disk" if path is not None else u"package"
        logger.verbose(u"Loading Agent {0} from {1}", self.name, location)

        self.error = GuestAgentError(self.get_agent_error_file())
        self.error.load()

        try:
            self._ensure_downloaded()
            self._ensure_loaded()
        except Exception as e:
            # If we're unable to download/unpack the agent, delete the Agent directory
            try:
                if os.path.isdir(self.get_agent_dir()):
                    shutil.rmtree(self.get_agent_dir(), ignore_errors=True)
            except Exception as err:
                logger.warn("Unable to delete Agent files: {0}".format(err))
            msg = u"Agent {0} install failed with exception:".format(
                self.name)
            detailed_msg = '{0} {1}'.format(msg, textutil.format_exception(e))
            PersistentUpdateHandlerState.report_error = detailed_msg  # capture the download errors to report back
            add_event(
                AGENT_NAME,
                version=self.version,
                op=WALAEventOperation.Install,
                is_success=False,
                message=detailed_msg)

    @staticmethod
    def from_installed_agent(path):
        """
        Creates an instance of GuestAgent using the agent installed in the given 'path'.
        """
        return GuestAgent(path, None, None, False)

    @staticmethod
    def from_agent_package(package, protocol, is_fast_track_goal_state):
        """
        Creates an instance of GuestAgent using the information provided in the 'package'; if that version of the agent is not installed it, it installs it.
        """
        return GuestAgent(None, package, protocol, is_fast_track_goal_state)

    @property
    def name(self):
        return "{0}-{1}".format(AGENT_NAME, self.version)

    def get_agent_cmd(self):
        return self.manifest.get_enable_command()

    def get_agent_dir(self):
        return os.path.join(conf.get_lib_dir(), self.name)

    def get_agent_error_file(self):
        return os.path.join(conf.get_lib_dir(), self.name, AGENT_ERROR_FILE)

    def get_agent_manifest_path(self):
        return os.path.join(self.get_agent_dir(), AGENT_MANIFEST_FILE)

    def get_agent_pkg_path(self):
        return ".".join((os.path.join(conf.get_lib_dir(), self.name), "zip"))

    def clear_error(self):
        self.error.clear()
        self.error.save()

    @property
    def is_available(self):
        return self.is_downloaded and not self.is_blacklisted

    @property
    def is_blacklisted(self):
        return self.error is not None and self.error.is_blacklisted

    @property
    def is_downloaded(self):
        return self.is_blacklisted or \
               os.path.isfile(self.get_agent_manifest_path())

    def mark_failure(self, is_fatal=False, reason=''):
        try:
            if not os.path.isdir(self.get_agent_dir()):
                os.makedirs(self.get_agent_dir())
            self.error.mark_failure(is_fatal=is_fatal, reason=reason)
            self.error.save()
            if self.error.is_blacklisted:
                msg = u"Agent {0} is permanently blacklisted".format(self.name)
                logger.warn(msg)
                add_event(op=WALAEventOperation.AgentBlacklisted, is_success=False, message=msg, log_event=False,
                          version=self.version)
        except Exception as e:
            logger.warn(u"Agent {0} failed recording error state: {1}", self.name, ustr(e))

    def _ensure_downloaded(self):
        logger.verbose(u"Ensuring Agent {0} is downloaded", self.name)

        if self.is_downloaded:
            logger.verbose(u"Agent {0} was previously downloaded - skipping download", self.name)
            return

        if self.pkg is None:
            raise UpdateError(u"Agent {0} is missing package and download URIs".format(
                self.name))

        self._download()

        msg = u"Agent {0} downloaded successfully".format(self.name)
        logger.verbose(msg)
        add_event(
            AGENT_NAME,
            version=self.version,
            op=WALAEventOperation.Install,
            is_success=True,
            message=msg)

    def _ensure_loaded(self):
        self._load_manifest()
        self._load_error()

    def _download(self):
        try:
            self._protocol.client.download_zip_package("agent package", self.pkg.uris, self.get_agent_pkg_path(), self.get_agent_dir(), use_verify_header=self._is_fast_track_goal_state)
        except Exception as exception:
            msg = "Unable to download Agent {0}: {1}".format(self.name, ustr(exception))
            add_event(
                AGENT_NAME,
                op=WALAEventOperation.Download,
                version=CURRENT_VERSION,
                is_success=False,
                message=msg)
            raise UpdateError(msg)

    def _load_error(self):
        try:
            self.error = GuestAgentError(self.get_agent_error_file())
            self.error.load()
            logger.verbose(u"Agent {0} error state: {1}", self.name, ustr(self.error))
        except Exception as e:
            logger.warn(u"Agent {0} failed loading error state: {1}", self.name, ustr(e))

    def _load_manifest(self):
        path = self.get_agent_manifest_path()
        if not os.path.isfile(path):
            msg = u"Agent {0} is missing the {1} file".format(self.name, AGENT_MANIFEST_FILE)
            raise UpdateError(msg)

        with open(path, "r") as manifest_file:
            try:
                manifests = json.load(manifest_file)
            except Exception as e:
                msg = u"Agent {0} has a malformed {1} ({2})".format(self.name, AGENT_MANIFEST_FILE, ustr(e))
                raise UpdateError(msg)
            if type(manifests) is list:
                if len(manifests) <= 0:
                    msg = u"Agent {0} has an empty {1}".format(self.name, AGENT_MANIFEST_FILE)
                    raise UpdateError(msg)
                manifest = manifests[0]
            else:
                manifest = manifests

        try:
            self.manifest = HandlerManifest(manifest)  # pylint: disable=W0201
            if len(self.manifest.get_enable_command()) <= 0:
                raise Exception(u"Manifest is missing the enable command")
        except Exception as e:
            msg = u"Agent {0} has an illegal {1}: {2}".format(
                self.name,
                AGENT_MANIFEST_FILE,
                ustr(e))
            raise UpdateError(msg)

        logger.verbose(
            u"Agent {0} loaded manifest from {1}",
            self.name,
            self.get_agent_manifest_path())
        logger.verbose(u"Successfully loaded Agent {0} {1}: {2}",
                       self.name,
                       AGENT_MANIFEST_FILE,
                       ustr(self.manifest.data))
        return


class GuestAgentError(object):
    def __init__(self, path):
        self.last_failure = 0.0
        self.was_fatal = False
        if path is None:
            raise UpdateError(u"GuestAgentError requires a path")
        self.path = path
        self.failure_count = 0
        self.reason = ''

        self.clear()
        return

    def mark_failure(self, is_fatal=False, reason=''):
        self.last_failure = time.time()
        self.failure_count += 1
        self.was_fatal = is_fatal
        self.reason = reason
        return

    def clear(self):
        self.last_failure = 0.0
        self.failure_count = 0
        self.was_fatal = False
        self.reason = ''
        return

    @property
    def is_blacklisted(self):
        return self.was_fatal or self.failure_count >= MAX_FAILURE

    def load(self):
        if self.path is not None and os.path.isfile(self.path):
            try:
                with open(self.path, 'r') as f:
                    self.from_json(json.load(f))
            except Exception as error:
                # The error.json file is only supposed to be written only by the agent.
                # If for whatever reason the file is malformed, just delete it to reset state of the errors.
                logger.warn(
                    "Ran into error when trying to load error file {0}, deleting it to clean state. Error: {1}".format(
                        self.path, textutil.format_exception(error)))
                try:
                    os.remove(self.path)
                except Exception:
                    # We try best case efforts to delete the file, ignore error if we're unable to do so
                    pass
        return

    def save(self):
        if os.path.isdir(os.path.dirname(self.path)):
            with open(self.path, 'w') as f:
                json.dump(self.to_json(), f)
        return

    def from_json(self, data):
        self.last_failure = max(self.last_failure, data.get(u"last_failure", 0.0))
        self.failure_count = max(self.failure_count, data.get(u"failure_count", 0))
        self.was_fatal = self.was_fatal or data.get(u"was_fatal", False)
        reason = data.get(u"reason", '')
        self.reason = reason if reason != '' else self.reason
        return

    def to_json(self):
        data = {
            u"last_failure": self.last_failure,
            u"failure_count": self.failure_count,
            u"was_fatal": self.was_fatal,
            u"reason": ustr(self.reason)
        }
        return data

    def __str__(self):
        return "Last Failure: {0}, Total Failures: {1}, Fatal: {2}, Reason: {3}".format(
            self.last_failure,
            self.failure_count,
            self.was_fatal,
            self.reason)
