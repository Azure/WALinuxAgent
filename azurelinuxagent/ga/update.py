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
import shutil
import signal
import subprocess
import sys
import time
import traceback
import zipfile

from datetime import datetime, timedelta

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.restutil as restutil
import azurelinuxagent.common.utils.textutil as textutil

from azurelinuxagent.common.event import add_event, \
                                    elapsed_milliseconds, \
                                    WALAEventOperation
from azurelinuxagent.common.exception import UpdateError, ProtocolError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, AGENT_LONG_VERSION, \
                                            AGENT_DIR_GLOB, AGENT_PKG_GLOB, \
                                            AGENT_PATTERN, AGENT_NAME_PATTERN, AGENT_DIR_PATTERN, \
                                            CURRENT_AGENT, CURRENT_VERSION, \
                                            is_current_agent_installed

from azurelinuxagent.ga.exthandlers import HandlerManifest

AGENT_ERROR_FILE = "error.json" # File name for agent error record
AGENT_MANIFEST_FILE = "HandlerManifest.json"
AGENT_SUPPORTED_FILE = "supported.json"

CHILD_HEALTH_INTERVAL = 15 * 60
CHILD_LAUNCH_INTERVAL = 5 * 60
CHILD_LAUNCH_RESTART_MAX = 3
CHILD_POLL_INTERVAL = 60

MAX_FAILURE = 3 # Max failure allowed for agent before blacklisted

GOAL_STATE_INTERVAL = 3
REPORT_STATUS_INTERVAL = 15

ORPHAN_WAIT_INTERVAL = 15 * 60 * 60

AGENT_SENTINAL_FILE = "current_version"

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
        self.last_attempt_time = None

        self.agents = []

        self.child_agent = None
        self.child_launch_time = None
        self.child_launch_attempts = 0
        self.child_process = None

        self.signal_handler = None
        return

    def run_latest(self, child_args=None):
        """
        This method is called from the daemon to find and launch the most
        current, downloaded agent.

        Note:
        - Most events should be tagged to the launched agent (agent_version)
        """

        if self.child_process is not None:
            raise Exception("Illegal attempt to launch multiple goal state Agent processes")

        if self.signal_handler is None:
            self.signal_handler = signal.signal(signal.SIGTERM, self.forward_signal)

        latest_agent = self.get_latest_agent()
        if latest_agent is None:
            logger.info(u"Installed Agent {0} is the most current agent", CURRENT_AGENT)
            agent_cmd = "python -u {0} -run-exthandlers".format(sys.argv[0])
            agent_dir = os.getcwd()
            agent_name = CURRENT_AGENT
            agent_version = CURRENT_VERSION
        else:
            logger.info(u"Determined Agent {0} to be the latest agent", latest_agent.name)
            agent_cmd = latest_agent.get_agent_cmd()
            agent_dir = latest_agent.get_agent_dir()
            agent_name = latest_agent.name
            agent_version = latest_agent.version

        if child_args is not None:
            agent_cmd = "{0} {1}".format(agent_cmd, child_args)

        try:

            # Launch the correct Python version for python-based agents
            cmds = textutil.safe_shlex_split(agent_cmd)
            if cmds[0].lower() == "python":
                cmds[0] = get_python_cmd()
                agent_cmd = " ".join(cmds)

            self._evaluate_agent_health(latest_agent)

            self.child_process = subprocess.Popen(
                cmds,
                cwd=agent_dir,
                stdout=sys.stdout,
                stderr=sys.stderr,
                env=os.environ)

            logger.verbose(u"Agent {0} launched with command '{1}'", agent_name, agent_cmd)

            # If the most current agent is the installed agent and update is enabled,
            # assume updates are likely available and poll every second.
            # This reduces the start-up impact of finding / launching agent updates on
            # fresh VMs.
            if latest_agent is None and conf.get_autoupdate_enabled():
                poll_interval = 1
            else:
                poll_interval = CHILD_POLL_INTERVAL

            ret = None
            start_time = time.time()
            while (time.time() - start_time) < CHILD_HEALTH_INTERVAL:
                time.sleep(poll_interval)
                ret = self.child_process.poll()
                if ret is not None:
                    break

            if ret is None or ret <= 0:
                msg = u"Agent {0} launched with command '{1}' is successfully running".format(
                    agent_name,
                    agent_cmd)
                logger.info(msg)
                add_event(
                    AGENT_NAME,
                    version=agent_version,
                    op=WALAEventOperation.Enable,
                    is_success=True,
                    message=msg)

                if ret is None:
                    ret = self.child_process.wait()

            else:
                msg = u"Agent {0} launched with command '{1}' failed with return code: {2}".format(
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

            if ret is not None and ret > 0:
                msg = u"Agent {0} launched with command '{1}' returned code: {2}".format(
                    agent_name,
                    agent_cmd,
                    ret)
                logger.warn(msg)
                if latest_agent is not None:
                    latest_agent.mark_failure(is_fatal=True)

        except Exception as e:
            msg = u"Agent {0} launched with command '{1}' failed with exception: {2}".format(
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

        self.child_process = None
        return

    def run(self):
        """
        This is the main loop which watches for agent and extension updates.
        """

        logger.info(u"Agent {0} is running as the goal state agent", CURRENT_AGENT)

        # Launch monitoring threads
        from azurelinuxagent.ga.monitor import get_monitor_handler
        get_monitor_handler().run()

        from azurelinuxagent.ga.env import get_env_handler
        get_env_handler().run()

        from azurelinuxagent.ga.exthandlers import get_exthandlers_handler, migrate_handler_state
        exthandlers_handler = get_exthandlers_handler()
        migrate_handler_state()

        try:
            send_event_time = datetime.utcnow()

            self._ensure_no_orphans()
            self._emit_restart_event()

            while self.running:
                if self._is_orphaned:
                    logger.info("Goal state agent {0} was orphaned -- exiting", CURRENT_AGENT)
                    break

                if self._upgrade_available():
                    if len(self.agents) > 0:
                        logger.info(
                            u"Agent {0} discovered {1} as an update and will exit",
                            CURRENT_AGENT,
                            self.agents[0].name)
                    break

                utc_start = datetime.utcnow()

                last_etag = exthandlers_handler.last_etag
                exthandlers_handler.run()

                log_event = last_etag != exthandlers_handler.last_etag or \
                            (datetime.utcnow() >= send_event_time)
                add_event(
                    AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.ProcessGoalState,
                    is_success=True,
                    duration=elapsed_milliseconds(utc_start),
                    log_event=log_event)
                if log_event:
                    send_event_time += timedelta(minutes=REPORT_STATUS_INTERVAL)

                test_agent = self.get_test_agent()
                if test_agent is not None and test_agent.in_slice:
                    test_agent.enable()
                    logger.info(u"Enabled Agent {0} as test agent", test_agent.name)
                    break

                time.sleep(GOAL_STATE_INTERVAL)

        except Exception as e:
            logger.warn(u"Agent {0} failed with exception: {1}", CURRENT_AGENT, ustr(e))
            logger.warn(traceback.format_exc())
            sys.exit(1)
            return

        self._shutdown()
        sys.exit(0)
        return

    def forward_signal(self, signum, frame):
        # Note:
        #  - At present, the handler is registered only for SIGTERM.
        #    However, clean shutdown is both SIGTERM and SIGKILL.
        #    A SIGKILL handler is not being registered at this time to
        #    minimize perturbing the code.
        if signum in (signal.SIGTERM, signal.SIGKILL):
            self._shutdown()

        if self.child_process is None:
            return
        
        logger.info(
            u"Agent {0} forwarding signal {1} to {2}",
            CURRENT_AGENT,
            signum,
            self.child_agent.name if self.child_agent is not None else CURRENT_AGENT)
        self.child_process.send_signal(signum)

        if self.signal_handler not in (None, signal.SIG_IGN, signal.SIG_DFL):
            self.signal_handler(signum, frame)
        elif self.signal_handler is signal.SIG_DFL:
            if signum == signal.SIGTERM:
                # TODO: This should set self.running to False vs. just exiting
                sys.exit(0)
        return

    def get_latest_agent(self):
        """
        If autoupdate is enabled, return the most current, downloaded,
        non-blacklisted agent which is not the current version (if any).
        Otherwise, return None (implying to use the installed agent).
        """

        if not conf.get_autoupdate_enabled():
            return None
        
        self._find_agents()
        available_agents = [agent for agent in self.agents
                            if agent.is_available
                            and agent.version > FlexibleVersion(AGENT_VERSION)]

        return available_agents[0] if len(available_agents) >= 1 else None

    def get_test_agent(self):
        agent = None
        agents = [agent for agent in self._load_agents() if agent.is_test]
        if len(agents) > 0:
            agents.sort(key=lambda agent: agent.version, reverse=True)
            agent = agents[0]
        return agent

    def _emit_restart_event(self):
        if not self._is_clean_start:
            msg = u"{0} did not terminate cleanly".format(CURRENT_AGENT)
            logger.info(msg)
            add_event(
                AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.Restart,
                is_success=False,
                message=msg)

        self._set_sentinal() 
        return

    def _upgrade_available(self, base_version=CURRENT_VERSION):
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

        family = conf.get_autoupdate_gafamily()
        logger.verbose("Checking for agent family {0} updates", family)

        self.last_attempt_time = now
        try:
            protocol = self.protocol_util.get_protocol()
            manifest_list, etag = protocol.get_vmagent_manifests()
        except Exception as e:
            msg = u"Exception retrieving agent manifests: {0}".format(ustr(e))
            logger.warn(msg)
            add_event(
                AGENT_NAME,
                op=WALAEventOperation.Download,
                version=CURRENT_VERSION,
                is_success=False,
                message=msg)
            return False

        manifests = [m for m in manifest_list.vmAgentManifests \
                        if m.family == family and len(m.versionsManifestUris) > 0]
        if len(manifests) == 0:
            logger.verbose(u"Incarnation {0} has no agent family {1} updates", etag, family)
            return False

        try:
            pkg_list = protocol.get_vmagent_pkgs(manifests[0])
        except ProtocolError as e:
            msg = u"Incarnation {0} failed to get {1} package list: " \
                  u"{2}".format(
                etag,
                family,
                ustr(e))
            logger.warn(msg)
            add_event(
                AGENT_NAME,
                op=WALAEventOperation.Download,
                version=CURRENT_VERSION,
                is_success=False,
                message=msg)
            return False

        # Set the agents to those available for download at least as current
        # as the existing agent and remove from disk any agent no longer
        # reported to the VM.
        # Note:
        #  The code leaves on disk available, but blacklisted, agents so as to
        #  preserve the state. Otherwise, those agents could be again
        #  downloaded and inappropriately retried.
        host = None
        if protocol and protocol.client:
            host = protocol.client.get_host_plugin()

        self._set_agents([GuestAgent(pkg=pkg, host=host) for pkg in pkg_list.versions])
        self._purge_agents()
        self._filter_blacklisted_agents()

        # Return True if agents more recent than the current are available
        return len(self.agents) > 0 and self.agents[0].version > base_version

    def _ensure_no_orphans(self, orphan_wait_interval=ORPHAN_WAIT_INTERVAL):
        previous_pid_file, pid_file = self._write_pid_file()
        if previous_pid_file is not None:
            try:
                pid = fileutil.read_file(previous_pid_file)
                wait_interval = orphan_wait_interval
                while self.osutil.check_pid_alive(pid):
                    wait_interval -= GOAL_STATE_INTERVAL
                    if wait_interval <= 0:
                        logger.warn(
                            u"{0} forcibly terminated orphan process {1}",
                            CURRENT_AGENT,
                            pid)
                        os.kill(pid, signal.SIGKILL)
                        break
                    
                    logger.info(
                        u"{0} waiting for orphan process {1} to terminate",
                        CURRENT_AGENT,
                        pid)
                    time.sleep(GOAL_STATE_INTERVAL)

            except Exception as e:
                logger.warn(
                    u"Exception occurred waiting for orphan agent to terminate: {0}",
                    ustr(e))
        return

    def _evaluate_agent_health(self, latest_agent):
        """
        Evaluate the health of the selected agent: If it is restarting
        too frequently, raise an Exception to force blacklisting.
        """
        if latest_agent is None:
            self.child_agent = None
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

    def _find_agents(self):
        """
        Load all non-blacklisted agents currently on disk.
        """
        try:
            self._set_agents(self._load_agents())
            self._filter_blacklisted_agents()
        except Exception as e:
            logger.warn(u"Exception occurred loading available agents: {0}", ustr(e))
        return

    def _get_pid_files(self):
        pid_file = conf.get_agent_pid_file_path()
        
        pid_dir = os.path.dirname(pid_file)
        pid_name = os.path.basename(pid_file)
        
        pid_re = re.compile("(\d+)_{0}".format(re.escape(pid_name)))
        pid_files = [int(pid_re.match(f).group(1)) for f in os.listdir(pid_dir) if pid_re.match(f)]
        pid_files.sort()

        pid_index = -1 if len(pid_files) <= 0 else pid_files[-1]
        previous_pid_file = None \
                        if pid_index < 0 \
                        else os.path.join(pid_dir, "{0}_{1}".format(pid_index, pid_name))
        pid_file = os.path.join(pid_dir, "{0}_{1}".format(pid_index+1, pid_name))
        return previous_pid_file, pid_file

    @property
    def _is_clean_start(self):
        if not os.path.isfile(self._sentinal_file_path()):
            return True

        try:
            if fileutil.read_file(self._sentinal_file_path()) != CURRENT_AGENT:
                return True
        except Exception as e:
            logger.warn(
                u"Exception reading sentinal file {0}: {1}",
                self._sentinal_file_path(),
                str(e))

        return False

    @property
    def _is_orphaned(self):
        parent_pid = os.getppid()
        if parent_pid in (1, None):
            return True

        if not os.path.isfile(conf.get_agent_pid_file_path()):
            return True

        return fileutil.read_file(conf.get_agent_pid_file_path()) != ustr(parent_pid)

    def _load_agents(self):
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))
        return [GuestAgent(path=agent_dir)
                        for agent_dir in glob.iglob(path) if os.path.isdir(agent_dir)]

    def _purge_agents(self):
        """
        Remove from disk all directories and .zip files of unknown agents
        (without removing the current, running agent).
        """
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))

        known_versions = [agent.version for agent in self.agents]
        if not is_current_agent_installed() and CURRENT_VERSION not in known_versions:
            logger.warn(
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
        return

    def _set_agents(self, agents=[]):
        self.agents = agents
        self.agents.sort(key=lambda agent: agent.version, reverse=True)
        return

    def _set_sentinal(self, agent=CURRENT_AGENT):
        try:
            fileutil.write_file(self._sentinal_file_path(), agent)
        except Exception as e:
            logger.warn(
                u"Exception writing sentinal file {0}: {1}",
                self._sentinal_file_path(),
                str(e))
        return

    def _sentinal_file_path(self):
        return os.path.join(conf.get_lib_dir(), AGENT_SENTINAL_FILE)

    def _shutdown(self):
        if not os.path.isfile(self._sentinal_file_path()):
            return

        try:
            os.remove(self._sentinal_file_path())
        except Exception as e:
            logger.warn(
                u"Exception removing sentinal file {0}: {1}",
                self._sentinal_file_path(),
                str(e))
        return

    def _write_pid_file(self):
        previous_pid_file, pid_file = self._get_pid_files()
        try:
            fileutil.write_file(pid_file, ustr(os.getpid()))
            logger.info(u"{0} running as process {1}", CURRENT_AGENT, ustr(os.getpid()))
        except Exception as e:
            pid_file = None
            logger.warn(
                u"Expection writing goal state agent {0} pid to {1}: {2}",
                CURRENT_AGENT,
                pid_file,
                ustr(e))
        return previous_pid_file, pid_file


class GuestAgent(object):
    def __init__(self, path=None, pkg=None, host=None):
        self.pkg = pkg
        self.host = host
        version = None
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

        location = u"disk" if path is not None else u"package"
        logger.verbose(u"Instantiating Agent {0} from {1}", self.name, location)

        self.error = None
        self.supported = None

        self._load_error()
        self._load_supported()

        self._ensure_downloaded()
        return

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

    def get_agent_supported_file(self):
        return os.path.join(conf.get_lib_dir(), self.name, AGENT_SUPPORTED_FILE)

    def clear_error(self):
        self.error.clear()
        return

    def enable(self):
        if self.error.is_sentinel:
            self.error.clear()
            self.error.save()
        return

    @property
    def is_available(self):
        return self.is_downloaded and not self.is_blacklisted

    @property
    def is_blacklisted(self):
        return self.error is not None and self.error.is_blacklisted

    @property
    def is_downloaded(self):
        return self.is_blacklisted or os.path.isfile(self.get_agent_manifest_path())

    @property
    def is_test(self):
        return self.error.is_sentinel and self.supported.is_supported

    @property
    def in_slice(self):
        return self.is_test and self.supported.in_slice

    def mark_failure(self, is_fatal=False):
        try:
            if not os.path.isdir(self.get_agent_dir()):
                os.makedirs(self.get_agent_dir())
            self.error.mark_failure(is_fatal=is_fatal)
            self.error.save()
            if is_fatal:
                logger.warn(u"Agent {0} is permanently blacklisted", self.name)
        except Exception as e:
            logger.warn(u"Agent {0} failed recording error state: {1}", self.name, ustr(e))
        return

    def _ensure_downloaded(self):
        try:
            logger.verbose(u"Ensuring Agent {0} is downloaded", self.name)

            if self.is_blacklisted:
                logger.info(u"Agent {0} is blacklisted - skipping download", self.name)
                return

            if self.is_downloaded:
                logger.verbose(u"Agent {0} was previously downloaded - skipping download", self.name)
                self._load_manifest()
                return

            if self.pkg is None:
                raise UpdateError(u"Agent {0} is missing package and download URIs".format(
                    self.name))
            
            self._download()
            self._unpack()
            self._load_manifest()
            self._load_error()
            self._load_supported()

            msg = u"Agent {0} downloaded successfully".format(self.name)
            logger.verbose(msg)
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
        for uri in self.pkg.uris:
            if not HostPluginProtocol.is_default_channel() and self._fetch(uri.uri):
                break
            elif self.host is not None and self.host.ensure_initialized():
                if not HostPluginProtocol.is_default_channel():
                    logger.warn("Download unsuccessful, falling back to host plugin")
                else:
                    logger.verbose("Using host plugin as default channel")

                uri, headers = self.host.get_artifact_request(uri.uri, self.host.manifest_uri)
                if self._fetch(uri, headers=headers):
                    if not HostPluginProtocol.is_default_channel():
                        logger.verbose("Setting host plugin as default channel")
                        HostPluginProtocol.set_default_channel(True)
                    break
                else:
                    logger.warn("Host plugin download unsuccessful")
            else:
                logger.error("No download channels available")

        if not os.path.isfile(self.get_agent_pkg_path()):
            msg = u"Unable to download Agent {0} from any URI".format(self.name)
            add_event(
                AGENT_NAME,
                op=WALAEventOperation.Download,
                version=CURRENT_VERSION,
                is_success=False,
                message=msg)
            raise UpdateError(msg)
        return

    def _fetch(self, uri, headers=None):
        package = None
        try:
            resp = restutil.http_get(uri, chk_proxy=True, headers=headers)
            if resp.status == restutil.httpclient.OK:
                package = resp.read()
                fileutil.write_file(self.get_agent_pkg_path(),
                                    bytearray(package),
                                    asbin=True)
                logger.verbose(u"Agent {0} downloaded from {1}", self.name, uri)
            else:
                logger.verbose("Fetch was unsuccessful [{0}]",
                               HostPluginProtocol.read_response_error(resp))
        except restutil.HttpError as http_error:
            logger.verbose(u"Agent {0} download from {1} failed [{2}]",
                           self.name,
                           uri,
                           http_error)
        return package is not None

    def _load_error(self):
        try:
            if self.error is None:
                self.error = GuestAgentError(self.get_agent_error_file())
            self.error.load()
            logger.verbose(u"Agent {0} error state: {1}", self.name, ustr(self.error))
        except Exception as e:
            logger.warn(u"Agent {0} failed loading error state: {1}", self.name, ustr(e))
        return

    def _load_supported(self):
        try:
            self.supported = Supported(self.get_agent_supported_file())
        except Exception as e:
            self.supported = Supported()

    def _load_manifest(self):
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

        logger.verbose(
            u"Agent {0} loaded manifest from {1}",
            self.name,
            self.get_agent_manifest_path())
        logger.verbose(u"Successfully loaded Agent {0} {1}: {2}",
            self.name,
            AGENT_MANIFEST_FILE,
            ustr(self.manifest.data))
        return

    def _unpack(self):
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

        logger.verbose(
            u"Agent {0} unpacked successfully to {1}",
            self.name,
            self.get_agent_dir())
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

    @property
    def is_blacklisted(self):
        return self.was_fatal or self.failure_count >= MAX_FAILURE

    @property
    def is_sentinel(self):
        return self.was_fatal and self.last_failure == 0.0

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

    def __str__(self):
        return "Last Failure: {0}, Total Failures: {1}, Fatal: {2}".format(
            self.last_failure,
            self.failure_count,
            self.was_fatal)

class Supported(object):
    def __init__(self, path):
        if path is None:
            raise UpdateError(u"Supported requires a path")
        self.path = path

        self._load()
        return

    @property
    def is_supported(self):
        return self._supported_distribution is not None

    @property
    def in_slice(self):
        d = self._supported_distribution
        return d is not None and d.in_slice

    @property
    def _supported_distribution(self):
        for d in self.distributions:
            dd = self.distributions[d]
            if dd.is_supported:
                return dd
        return None

    def _load(self):
        self.distributions = {}
        try:
            if self.path is not None and os.path.isfile(self.path):
                j = json.loads(fileutil.read_file(self.path))
                for d in j:
                    self.distributions[d] = SupportedDistribution(j[d])
        except Exception as e:
            logger.warn("Failed JSON parse of {0}: {1}".format(self.path, e))
        return

class SupportedDistribution(object):
    def __init__(self, s):
        if s is None or not isinstance(s, dict):
            raise UpdateError(u"SupportedDisribution requires a dictionary")

        self.slice = s['slice']
        self.versions = s['versions']

    @property
    def is_supported(self):
        d = ','.join(platform.linux_distribution())
        for v in self.versions:
            if re.match(v, d):
                return True
        return False

    @property
    def in_slice(self):
        n = int((60 * self.slice) / 100)
        return (n - datetime.utcnow().second) > 0
