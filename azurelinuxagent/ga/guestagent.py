import json
import os
import shutil
import time

from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import textutil

from azurelinuxagent.common import logger, conf
from azurelinuxagent.common.exception import UpdateError
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_DIR_PATTERN, AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.ga.exthandlers import HandlerManifest

AGENT_ERROR_FILE = "error.json"  # File name for agent error record
AGENT_MANIFEST_FILE = "HandlerManifest.json"
MAX_FAILURE = 3  # Max failure allowed for agent before declare bad agent


class GAUpdateReportState(object):
    """
    This class is primarily used to maintain the in-memory persistent state for the agent updates.
    This state will be persisted throughout the current service run and might be modified by external classes.
    """
    report_error_msg = ""
    report_expected_version = FlexibleVersion("0.0.0.0")


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
            if "Missing requested version" not in GAUpdateReportState.report_error_msg:
                GAUpdateReportState.report_error_msg = detailed_msg  # capture the download errors to report back
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
