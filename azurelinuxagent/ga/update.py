# Windows Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#
import glob
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import zipfile

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.restutil as restutil
import azurelinuxagent.common.utils.textutil as textutil

from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import UpdateError, ProtocolError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, AGENT_LONG_VERSION, \
                                            AGENT_DIR_GLOB, AGENT_PKG_GLOB, \
                                            AGENT_PATTERN, AGENT_NAME_PATTERN, AGENT_DIR_PATTERN, \
                                            CURRENT_AGENT, CURRENT_VERSION

from azurelinuxagent.ga.exthandlers import HandlerManifest


AGENT_ERROR_FILE = "error.json" # File name for agent error record
AGENT_MANIFEST_FILE = "HandlerManifest.json"

CHILD_LAUNCH_INTERVAL = 5 * 60
CHILD_LAUNCH_RESTART_MAX = 3

MAX_FAILURE = 3 # Max failure allowed for agent before blacklisted

GOAL_STATE_INTERVAL = 25
REPORT_STATUS_INTERVAL = 15
RETAIN_INTERVAL = 24 * 60 * 60 # Retain interval for black list


def get_update_handler():
    return UpdateHandler()


def get_python_cmd():
    major_version = platform.python_version_tuple()[0]
    return "python" if int(major_version) <= 2 else "python{0}".format(major_version)


class UpdateHandler(object):

    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()

        self.running = True
        self.last_etag = None
        self.last_attempt_time = None

        self.agents = []

        self.child_agent = None
        self.child_launch_time = None
        self.child_launch_attempts = 0
        self.child_process = None
        self.signal_handler = None
        return

    def run_latest(self):
        """
        This method is called from the daemon to find and launch the most
        current, downloaded agent.

        Note:
        - Most events should be tagged to the launched agent (agent_version)
        """
        latest_agent = self.get_latest_agent()
        if latest_agent == None:
            agent_cmd = "python -u {0} -run-exthandlers".format(sys.argv[0])
            agent_dir = os.getcwd()
            agent_name = CURRENT_AGENT
            agent_version = CURRENT_VERSION
        else:
            agent_cmd = latest_agent.get_agent_cmd()
            agent_dir = latest_agent.get_agent_dir()
            agent_name = latest_agent.name
            agent_version = latest_agent.version

        if self.child_process is not None:
            raise Exception("Illegal attempt to launch multiple child processes")

        try:

            self.signal_handler = signal.signal(signal.SIGTERM, self.forward_signal)

            # Launch the correct Python version for python-based agents
            cmds = shlex.split(agent_cmd)
            if cmds[0].lower() == "python":
                cmds[0] = get_python_cmd()
                agent_cmd = " ".join(cmds)

            self._evaluate_agent_health(latest_agent)

            self.child_process = subprocess.Popen(
                cmds,
                cwd=agent_dir,
                stdout=sys.stdout,
                stderr=sys.stderr)

            msg = u"Agent {0} launched with command '{1}'".format(agent_name, agent_cmd)
            logger.info(msg)
            add_event(AGENT_NAME, version=agent_version, message=msg)

            ret = self.child_process.wait()
            if ret == None:
                ret = 1
            if ret > 0:
                msg = u"Agent {0} launched with command '{1}' failed with code: {2}".format(
                    agent_name,
                    agent_cmd,
                    ret)
                logger.warn(msg)
                add_event(
                    AGENT_NAME,
                    version=agent_version,
                    op=WALAEventOperation.Enable,
                    is_success=False,
                    message=msg)
                if latest_agent is not None:
                    latest_agent.mark_failure()
            else:
                msg = u"Agent {0} launched with command '{1}' returned {2}".format(
                    agent_name,
                    agent_cmd,
                    ret)
                logger.info(msg)
                add_event(
                    AGENT_NAME,
                    version=agent_version,
                    op=WALAEventOperation.Enable,
                    is_success=True,
                    message=msg)
        except Exception as e:
            msg = u"Agent {0} launch failed with command '{1}' failed with exception: {2}".format(
                agent_name,
                agent_cmd,
                ustr(e))
            logger.warn(msg)
            add_event(
                AGENT_NAME,
                version=agent_version,
                op=WALAEventOperation.Enable,
                is_success=False,
                message=msg)
            if latest_agent is not None:
                latest_agent.mark_failure(is_fatal=True)
                msg = u"Agent {0} is blacklisted".format(agent_name)
                logger.info(msg)
                add_event(
                    AGENT_NAME,
                    version=agent_version,
                    op=WALAEventOperation.Enable,
                    is_success=False,
                    message=msg)

        self.child_process = None
        return

    def run(self):
        """
        This is the main loop which watches for agent and extension updates.
        """

        msg = u"Agent {0} is running as the current agent".format(
            CURRENT_AGENT)
        logger.info(msg)
        add_event(AGENT_NAME, version=CURRENT_VERSION, is_success=True, message=msg)

        # Launch monitoring threads
        from azurelinuxagent.ga.monitor import get_monitor_handler
        get_monitor_handler().run()

        from azurelinuxagent.ga.env import get_env_handler
        get_env_handler().run()

        from azurelinuxagent.ga.exthandlers import get_exthandlers_handler
        exthandlers_handler = get_exthandlers_handler()

        # TODO: Add means to stop running
        try:
            while self.running:
                # Check for a new agent.
                # If a new agent exists (that is, ensure_latest_agent returns
                # true), exit to allow the daemon to respawn using that agent.
                if self._ensure_latest_agent():
                    msg = u"Agent {0} discovered agent update and will exit".format(
                        CURRENT_AGENT)
                    logger.info(msg)
                    add_event(
                        AGENT_NAME,
                        version=CURRENT_VERSION,
                        is_success=True,
                        message=msg)
                    break

                # Process extensions
                exthandlers_handler.run()
                
                time.sleep(25)

        except Exception as e:
            msg = u"Agent {0} failed with exception: {1}".format(CURRENT_AGENT, ustr(e))
            logger.warn(msg)
            add_event(
                AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.Enable,
                is_success=False,
                message=msg)
            sys.exit(1)

        sys.exit(0)
        return

    def forward_signal(self, signum, frame):
        if self.child_process is None:
            return
        
        self.child_process.send_signal(signum)

        if not self.signal_handler in (None, signal.SIG_IGN, signal.SIG_DFL):
            self.signal_handler(signum, frame)
        elif self.signal_handler is signal.SIG_DFL:
            if signum == signal.SIGTERM:
                sys.exit(0)
        return

    def get_latest_agent(self):
        """
        If autoupdate is enabled, return the most current, downloaded,
        non-blacklisted agent (if any).
        Otherwise, return None (implying to use the installed agent).
        """

        if not conf.get_autoupdate_enabled():
            return None
        
        self._load_agents()
        available_agents = [agent for agent in self.agents if agent.is_available]
        return available_agents[0] if len(available_agents) >= 1 else None

    def _ensure_latest_agent(self, base_version=CURRENT_VERSION):
        # Ignore new agents if updating is disabled
        if not conf.get_autoupdate_enabled():
            return False

        now = time.time()
        if self.last_attempt_time is not None:
            next_attempt_time = self.last_attempt_time + conf.get_autoupdate_frequency()
        else:
            next_attempt_time = now
        if next_attempt_time > now:
            return False

        self.last_attempt_time = now
        try:
            protocol = self.protocol_util.get_protocol()
            manifest_list, etag = protocol.get_vmagent_manifests()
        except Exception as e:
            msg = u"Exception retrieving agent manifests: {0}".format(ustr(e))
            logger.warn(msg)
            add_event(
                AGENT_NAME,
                version=CURRENT_VERSION,
                is_success=False,
                message=msg)
            return False

        if self.last_etag is not None and self.last_etag == etag:
            msg = u"Incarnation {0} has no agent updates".format(etag)
            logger.info(msg)
            add_event(AGENT_NAME, version=CURRENT_VERSION, message=msg)
            return False

        logger.info("Check for agent updates")

        family = conf.get_autoupdate_gafamily()
        manifests = [m for m in manifest_list.vmAgentManifests if m.family == family]
        if len(manifests) == 0:
            msg = u"Incarnation {0} has no agent family {1} updates".format(etag, family)
            logger.info(msg)
            add_event(AGENT_NAME, version=CURRENT_VERSION, message=msg)
            return False

        try:
            pkg_list = protocol.get_vmagent_pkgs(manifests[0])
        except ProtocolError as e:
            msg= u"Incarnation {0} failed to get {1} package list: {1}".format(etag,
                                                                               family,
                                                                               ustr(e))
            logger.warn(msg)
            add_event(
                AGENT_NAME,
                version=CURRENT_VERSION,
                is_success=False,
                message=msg)
            return False

        # Set the agents to those available for download at least as current as the existing agent
        # and remove from disk any agent no longer report to the VM.
        # Note:
        #  The code leaves on disk available, but blacklisted, agents so as to preserve the state.
        #  Otherwise, those agents could be again downloaded and inappropriately retried.
        self._set_agents([GuestAgent(pkg=pkg) for pkg in
                            [pkg for pkg in pkg_list.versions
                                if FlexibleVersion(pkg.version) > base_version]])
        self._purge_agents()
        self._filter_blacklisted_agents()

        # Return True if agents more recent than the current are available
        return len(self.agents) > 0 and self.agents[0].version > base_version

    def _evaluate_agent_health(self, latest_agent):
        """
        Evaluate the health of the selected agent: If it is restarting
        too frequently, raise an Exception to force blacklisting.
        """
        if latest_agent is None:
            return

        if self.child_agent is None or latest_agent.version != self.child_agent.version:
            self.child_agent = latest_agent
            self.child_launch_time = None
            self.child_launch_attempts = 0

        if self.child_launch_time is None:
            self.child_launch_time = time.time()

        self.child_launch_attempts += 1

        if (time.time() - self.child_launch_time) <= CHILD_LAUNCH_INTERVAL \
            and self.child_launch_attempts >= CHILD_LAUNCH_RESTART_MAX:
                msg = u"Agent {0} restarted more than {1} times in {2} seconds".format(
                    self.child_agent.name,
                    CHILD_LAUNCH_RESTART_MAX,
                    CHILD_LAUNCH_INTERVAL)
                raise Exception(msg)
        return

    def _filter_blacklisted_agents(self):
        self.agents = [agent for agent in self.agents if not agent.is_blacklisted]
        return

    def _load_agents(self):
        """
        Load all non-blacklisted agents currently on disk.
        """
        if len(self.agents) <= 0:
            try:
                path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))
                self._set_agents([GuestAgent(path=agent_dir)
                                    for agent_dir in glob.iglob(path) if os.path.isdir(agent_dir)])
                self._filter_blacklisted_agents()
            except Exception as e:
                msg = u"Exception occurred loading available agents: {0}".format(ustr(e))
                add_event(
                    AGENT_NAME,
                    version=CURRENT_VERSION,
                    is_success=False,
                    message=msg)
        return

    def _purge_agents(self):
        """
        Remove from disk all directories and .zip files of unknown agents
        (without removing the current, running agent).
        """
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))
        known_versions = [agent.version for agent in self.agents]
        known_versions.append(CURRENT_VERSION)
        for agent_path in glob.iglob(path):
            try:
                name = fileutil.trim_ext(agent_path, "zip")
                m = AGENT_DIR_PATTERN.match(name)
                if m is not None and not FlexibleVersion(m.group(1)) in known_versions:
                    if os.path.isfile(agent_path):
                        os.remove(agent_path)
                    else:
                        shutil.rmtree(agent_path)
            except Exception as e:
                msg = u"Exception purging {0}: {1}".format(agent_path, ustr(e))
                logger.warn(msg)
                add_event(
                    AGENT_NAME,
                    version=CURRENT_VERSION,
                    is_success=False,
                    message=msg)
        return

    def _set_agents(self, agents=[]):
        self.agents = agents
        self.agents.sort(key=lambda agent: agent.version, reverse=True)
        return


class GuestAgent(object):
    def __init__(self, path=None, pkg=None):
        self.pkg = pkg
        if path is not None:
            m = AGENT_DIR_PATTERN.match(path)
            if m == None:
                raise UpdateError(u"Illegal agent directory: {0}".format(path))
            version = m.group(1)
        elif self.pkg is not None:
            version = pkg.version

        if version == None:
            raise UpdateError(u"Illegal agent version: {0}".format(version))
        self.version = FlexibleVersion(version)

        self.error = None
        self._load_error()
        self._ensure_downloaded()

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
        return

    @property
    def is_available(self):
        return self.is_downloaded and not self.is_blacklisted

    @property
    def is_blacklisted(self):
        return self.error is not None and self.error.is_blacklisted

    @property
    def is_downloaded(self):
        return os.path.isfile(self.get_agent_manifest_path())

    def mark_failure(self, is_fatal=False):
        try:
            if not os.path.isdir(self.get_agent_dir()):
                os.makedirs(self.get_agent_dir())
            self.error.mark_failure(is_fatal)
            self.error.save()
            if is_fatal:
                msg = u"Agent {0} is permanently blacklisted".format(self.name)
                logger.warn(msg)
                add_event(AGENT_NAME, version=self.version, is_success=False, message=msg)
        except Exception as e:
            msg = u"Agent {0} failed recording error state: {1}".format(ustr(e))
            logger.warn(msg)
            add_event(AGENT_NAME, version=self.version, is_success=False, message=msg)
        return

    def _ensure_downloaded(self):
        try:
            if self.is_blacklisted:
                msg = u"Agent {0} is blacklisted - skipping download".format(self.name)
                logger.info(msg)
                add_event(AGENT_NAME, version=self.version, is_success=True, message=msg)
                return

            if self.is_downloaded:
                self._load_manifest()
                return

            if self.pkg is None:
                raise UpdateError(u"Agent {0} is missing package and download URIs".format(
                    self.name))
            
            self._download()
            self._unpack()
            self._load_manifest()
            self._load_error()

            msg = u"Agent {0} downloaded successfully".format(self.name)
            logger.info(msg)
            add_event(
                AGENT_NAME,
                version=self.version,
                op=WALAEventOperation.Install,
                is_success=True,
                message=msg)

        except Exception as e:
            # Note the failure, blacklist the agent if the package downloaded
            # - An exception with a downloaded package indicates the package
            #   is corrupt (e.g., missing the HandlerManifest.json file)
            self.mark_failure(is_fatal=os.path.isfile(self.get_agent_pkg_path()))

            msg = u"Agent {0} download failed with exception: {1}".format(self.name, ustr(e))
            logger.warn(msg)
            add_event(
                AGENT_NAME,
                version=self.version,
                op=WALAEventOperation.Install,
                is_success=False,
                message=msg)
        return

    def _download(self):
        msg = u"Initiating download of Agent {0}".format(self.name)
        logger.info(msg)
        add_event(AGENT_NAME, version=self.version, message=msg)
        package = None

        for uri in self.pkg.uris:
            try:
                resp = restutil.http_get(uri.uri, chk_proxy=True)
                if resp.status == restutil.httpclient.OK:
                    package = resp.read()
                    fileutil.write_file(self.get_agent_pkg_path(), bytearray(package), asbin=True)
                    break
            except restutil.HttpError as e:
                msg = u"Agent {0} download from {1} failed".format(self.name, uri.uri)
                logger.warn(msg)
                add_event(AGENT_NAME, version=self.version, is_success=False, message=msg)

        if not os.path.isfile(self.get_agent_pkg_path()):
            msg = u"Unable to download Agent {0} from any URI".format(self.name)
            raise UpdateError(msg)
        return

    def _load_error(self):
        try:
            if self.error is None:
                self.error = GuestAgentError(self.get_agent_error_file())
            self.error.load()
        except Exception as e:
            msg = u"Agent {0} failed loading error state: {1}".format(ustr(e))
            logger.warn(msg)
            add_event(AGENT_NAME, version=self.version, is_success=False, message=msg)
        return

    def _load_manifest(self):
        logger.info(u"Loading Agent manifest from {0}", self.get_agent_manifest_path())

        path = self.get_agent_manifest_path()
        if not os.path.isfile(path):
            msg = u"Agent {0} is missing the {1} file".format(self.name, AGENT_MANIFEST_FILE)
            raise UpdateError(msg)

        with open(path, "r") as manifest_file:
            try:
                manifests = json.load(manifest_file)
            except Exception as e:
                msg = u"Agent {0} has a malformed {1}".format(self.name, AGENT_MANIFEST_FILE)
                raise UpdateError(msg)
            if type(manifests) is list:
                if len(manifests) <= 0:
                    msg = u"Agent {0} has an empty {1}".format(self.name, AGENT_MANIFEST_FILE)
                    raise UpdateError(msg)
                manifest = manifests[0]
            else:
                manifest = manifests

        try:
            self.manifest = HandlerManifest(manifest)
            if len(self.manifest.get_enable_command()) <= 0:
                raise Exception(u"Manifest is missing the enable command")
        except Exception as e:
            msg = u"Agent {0} has an illegal {1}: {2}".format(
                self.name,
                AGENT_MANIFEST_FILE,
                ustr(e))
            raise UpdateError(msg)

        logger.verbose(u"Successfully loaded Agent {0} {1}: {2}",
            self.name,
            AGENT_MANIFEST_FILE,
            ustr(self.manifest.data))
        return

    def _unpack(self):
        logger.info(u"Unpacking agent package {0}", self.name)

        try:
            if os.path.isdir(self.get_agent_dir()):
                shutil.rmtree(self.get_agent_dir())

            zipfile.ZipFile(self.get_agent_pkg_path()).extractall(self.get_agent_dir())
        except Exception as e:
            msg = u"Exception unpacking Agent {0} from {1}: {2}".format(
                self.name,
                self.get_agent_pkg_path(),
                ustr(e))
            raise UpdateError(msg)

        if not os.path.isdir(self.get_agent_dir()):
            msg = u"Unpacking Agent {0} failed to create directory {1}".format(
                        self.name,
                        self.get_agent_dir())
            raise UpdateError(msg)

        msg = u"Agent {0} successfully unpacked".format(self.name)
        logger.info(msg)
        add_event(AGENT_NAME, version=self.version, message=msg)
        return


class GuestAgentError(object):
    def __init__(self, path):
        if path is None:
            raise UpdateError(u"GuestAgentError requires a path")
        self.path = path

        self.clear()
        self.load()
        return
   
    def mark_failure(self, is_fatal=False):
        self.last_failure = time.time()
        self.failure_count += 1
        self.was_fatal = is_fatal
        return

    def clear(self):
        self.last_failure = 0.0
        self.failure_count = 0
        self.was_fatal = False
        return
    
    def clear_old_failure(self):
        if self.last_failure <= 0.0:
            return
        if self.last_failure < (time.time() - RETAIN_INTERVAL):
            self.clear()
        return

    @property
    def is_blacklisted(self):
        return self.was_fatal or self.failure_count >= MAX_FAILURE

    def load(self):
        if self.path is not None and os.path.isfile(self.path):
            with open(self.path, 'r') as f:
                self.from_json(json.load(f))
        return

    def save(self):
        if os.path.isdir(os.path.dirname(self.path)):
            with open(self.path, 'w') as f:
                json.dump(self.to_json(), f)
        return
    
    def from_json(self, data):
        self.last_failure = max(
            self.last_failure,
            data.get(u"last_failure", 0.0))
        self.failure_count = max(
            self.failure_count,
            data.get(u"failure_count", 0))
        self.was_fatal = self.was_fatal or data.get(u"was_fatal", False)
        return

    def to_json(self):
        data = {
            u"last_failure": self.last_failure,
            u"failure_count": self.failure_count,
            u"was_fatal" : self.was_fatal
        }  
        return data
