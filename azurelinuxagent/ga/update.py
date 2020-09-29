# Windows Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
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
#
import glob
import json
import os
import random
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback
import uuid
import zipfile

from datetime import datetime, timedelta

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.restutil as restutil
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator

from azurelinuxagent.common.event import add_event, initialize_event_logger_vminfo_common_parameters, \
    elapsed_milliseconds, WALAEventOperation, EVENTS_DIRECTORY
from azurelinuxagent.common.exception import ResourceGoneError, UpdateError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, AGENT_DIR_PATTERN, CURRENT_AGENT,\
    CURRENT_VERSION, DISTRO_NAME, DISTRO_VERSION, is_current_agent_installed, get_lis_version, PY_VERSION_MAJOR, \
    PY_VERSION_MINOR, PY_VERSION_MICRO
from azurelinuxagent.ga.collect_logs import get_collect_logs_handler, is_log_collection_allowed
from azurelinuxagent.ga.env import get_env_handler
from azurelinuxagent.ga.extension_telemetry import get_extension_telemetry_handler

from azurelinuxagent.ga.exthandlers import HandlerManifest, get_traceback, ExtHandlersHandler, \
    is_extension_telemetry_pipeline_enabled, list_agent_lib_directory
from azurelinuxagent.ga.monitor import get_monitor_handler

# pylint: disable=C0302

AGENT_ERROR_FILE = "error.json" # File name for agent error record
AGENT_MANIFEST_FILE = "HandlerManifest.json"
AGENT_PARTITION_FILE = "partition"

CHILD_HEALTH_INTERVAL = 15 * 60
CHILD_LAUNCH_INTERVAL = 5 * 60
CHILD_LAUNCH_RESTART_MAX = 3
CHILD_POLL_INTERVAL = 60

MAX_FAILURE = 3 # Max failure allowed for agent before blacklisted

GOAL_STATE_INTERVAL_DISABLED = 5 * 60

ORPHAN_POLL_INTERVAL = 3
ORPHAN_WAIT_INTERVAL = 15 * 60

AGENT_SENTINEL_FILE = "current_version"

READONLY_FILE_GLOBS = [
    "*.crt",
    "*.p7m",
    "*.pem",
    "*.prv",
    "ovf-env.xml"
]


def get_update_handler():
    return UpdateHandler()


class UpdateHandler(object): # pylint: disable=R0902
    TELEMETRY_HEARTBEAT_PERIOD = timedelta(minutes=30)

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

        self._last_telemetry_heartbeat = None
        self._heartbeat_id = str(uuid.uuid4()).upper()
        self._heartbeat_counter = 0
        self._heartbeat_update_goal_state_error_count = 0

    def run_latest(self, child_args=None): # pylint: disable=R0912,R1711
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
                cmds[0] = sys.executable
                agent_cmd = " ".join(cmds)

            self._evaluate_agent_health(latest_agent)

            self.child_process = subprocess.Popen(
                cmds,
                cwd=agent_dir,
                stdout=sys.stdout,
                stderr=sys.stderr,
                env=os.environ)

            logger.verbose(u"Agent {0} launched with command '{1}'", agent_name, agent_cmd)

            # Setting the poll interval to poll every second to reduce the agent provisioning time;
            # The daemon shouldn't wait for 60secs before starting the ext-handler in case the
            # ext-handler kills itself during agent-update during the first 15 mins (CHILD_HEALTH_INTERVAL)
            poll_interval = 1

            ret = None
            start_time = time.time()
            while (time.time() - start_time) < CHILD_HEALTH_INTERVAL:
                time.sleep(poll_interval)
                try:
                    ret = self.child_process.poll()
                except OSError:
                    # if child_process has terminated, calling poll could raise an exception
                    ret = -1
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
                    message=msg,
                    log_event=False)

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

        except Exception as e: # pylint: disable=C0103
            # Ignore child errors during termination
            if self.running:
                msg = u"Agent {0} launched with command '{1}' failed with exception: {2}".format(
                    agent_name,
                    agent_cmd,
                    ustr(e))
                logger.warn(msg)
                detailed_message = '{0} {1}'.format(msg, traceback.format_exc())
                add_event(
                    AGENT_NAME,
                    version=agent_version,
                    op=WALAEventOperation.Enable,
                    is_success=False,
                    message=detailed_message)
                if latest_agent is not None:
                    latest_agent.mark_failure(is_fatal=True)

        self.child_process = None
        return

    def run(self, debug=False):  # pylint: disable=R0912,R0914
        """
        This is the main loop which watches for agent and extension updates.
        """

        try:
            logger.info(u"Agent {0} is running as the goal state agent", CURRENT_AGENT)

            #
            # Fetch the goal state one time; some components depend on information provided by the goal state and this
            # call ensures the required info is initialized (e.g telemetry depends on the container ID.)
            #
            protocol = self.protocol_util.get_protocol()
            protocol.update_goal_state()

            # Initialize the common parameters for telemetry events
            initialize_event_logger_vminfo_common_parameters(protocol)

            # Log OS-specific info.
            os_info_msg = u"Distro: {0}-{1}; OSUtil: {2}; AgentService: {3}; Python: {4}.{5}.{6}; LISDrivers: {7}".format(
                DISTRO_NAME, DISTRO_VERSION, type(self.osutil).__name__, self.osutil.service_name, PY_VERSION_MAJOR,
                PY_VERSION_MINOR, PY_VERSION_MICRO, get_lis_version())
            logger.info(os_info_msg)
            add_event(AGENT_NAME, op=WALAEventOperation.OSInfo, message=os_info_msg)

            #
            # Perform initialization tasks
            #
            from azurelinuxagent.ga.exthandlers import get_exthandlers_handler, migrate_handler_state
            exthandlers_handler = get_exthandlers_handler(protocol)
            migrate_handler_state()

            from azurelinuxagent.ga.remoteaccess import get_remote_access_handler
            remote_access_handler = get_remote_access_handler(protocol)

            self._ensure_no_orphans()
            self._emit_restart_event()
            self._emit_changes_in_default_configuration()
            self._ensure_partition_assigned()
            self._ensure_readonly_files()
            self._ensure_cgroups_initialized()
            self._ensure_extension_telemetry_state_configured_properly(protocol)

            # Get all thread handlers
            all_thread_handlers = [
                get_monitor_handler(),
                get_env_handler()
            ]

            if is_log_collection_allowed():
                all_thread_handlers.append(get_collect_logs_handler())

            if is_extension_telemetry_pipeline_enabled():
                # Reuse the same protocol_util as the UpdateHandler class to avoid new initializations
                all_thread_handlers.append(get_extension_telemetry_handler(self.protocol_util))

            # Launch all monitoring threads
            for thread_handler in all_thread_handlers:
                thread_handler.run()

            goal_state_interval = conf.get_goal_state_period() if conf.get_extensions_enabled() else GOAL_STATE_INTERVAL_DISABLED

            while self.running:
                #
                # Check that the parent process (the agent's daemon) is still running
                #
                if not debug and self._is_orphaned:
                    logger.info("Agent {0} is an orphan -- exiting", CURRENT_AGENT)
                    break

                #
                # Check that all the threads are still running
                #
                for thread_handler in all_thread_handlers:
                    if not thread_handler.is_alive():
                        logger.warn("{0} thread died, restarting".format(thread_handler.get_thread_name()))
                        thread_handler.start()

                #
                # Process the goal state
                #
                if not protocol.try_update_goal_state():
                    self._heartbeat_update_goal_state_error_count += 1
                else:
                    if self._upgrade_available(protocol):
                        available_agent = self.get_latest_agent()
                        if available_agent is None:
                            logger.info(
                                "Agent {0} is reverting to the installed agent -- exiting",
                                CURRENT_AGENT)
                        else:
                            logger.info(
                                u"Agent {0} discovered update {1} -- exiting",
                                CURRENT_AGENT,
                                available_agent.name)
                        break

                    utc_start = datetime.utcnow()

                    last_etag = exthandlers_handler.last_etag
                    exthandlers_handler.run()

                    remote_access_handler.run()

                    if last_etag != exthandlers_handler.last_etag:
                        self._ensure_readonly_files()
                        duration = elapsed_milliseconds(utc_start)
                        logger.info('ProcessGoalState completed [incarnation {0}; {1} ms]',
                                    exthandlers_handler.last_etag,
                                    duration)
                        add_event(
                            AGENT_NAME,
                            op=WALAEventOperation.ProcessGoalState,
                            duration=duration,
                            message="Incarnation {0}".format(exthandlers_handler.last_etag))

                self._send_heartbeat_telemetry(protocol)
                time.sleep(goal_state_interval)

        except Exception as e: # pylint: disable=C0103
            msg = u"Agent {0} failed with exception: {1}".format(CURRENT_AGENT, ustr(e))
            self._set_sentinel(msg=msg)
            logger.warn(msg)
            logger.warn(traceback.format_exc())
            sys.exit(1)
            # additional return here because sys.exit is mocked in unit tests
            return

        self._shutdown()
        sys.exit(0)

    def forward_signal(self, signum, frame):
        if signum == signal.SIGTERM:
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
                self._shutdown()
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

    def _emit_restart_event(self): # pylint: disable=R1711
        try:
            if not self._is_clean_start:
                msg = u"Agent did not terminate cleanly: {0}".format(
                            fileutil.read_file(self._sentinel_file_path())) 
                logger.info(msg)
                add_event(
                    AGENT_NAME,
                    version=CURRENT_VERSION,
                    op=WALAEventOperation.Restart,
                    is_success=False,
                    message=msg)
        except Exception:
            pass

        return

    @staticmethod
    def _emit_changes_in_default_configuration():
        try:
            def log_if_int_changed_from_default(name, current):
                default = conf.get_int_default_value(name)
                if default != current:
                    msg = "{0} changed from its default; new value: {1}".format(name, current)
                    logger.info(msg)
                    add_event(AGENT_NAME, op=WALAEventOperation.ConfigurationChange, message=msg)

            log_if_int_changed_from_default("Extensions.GoalStatePeriod", conf.get_goal_state_period())

            if not conf.enable_firewall():
                message = "OS.EnableFirewall is False"
                logger.info(message)
                add_event(AGENT_NAME, op=WALAEventOperation.ConfigurationChange, message=message)
            else:
                log_if_int_changed_from_default("OS.EnableFirewallPeriod", conf.get_enable_firewall_period())

            if conf.get_lib_dir() != "/var/lib/waagent":
                message = "lib dir is in an unexpected location: {0}".format(conf.get_lib_dir())
                logger.info(message)
                add_event(AGENT_NAME, op=WALAEventOperation.ConfigurationChange, message=message)

        except Exception as e: # pylint: disable=C0103
            logger.warn("Failed to log changes in configuration: {0}", ustr(e))

    def _ensure_no_orphans(self, orphan_wait_interval=ORPHAN_WAIT_INTERVAL): # pylint: disable=R1711
        pid_files, ignored = self._write_pid_file() # pylint: disable=W0612
        for pid_file in pid_files:
            try:
                pid = fileutil.read_file(pid_file)
                wait_interval = orphan_wait_interval

                while self.osutil.check_pid_alive(pid):
                    wait_interval -= ORPHAN_POLL_INTERVAL
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
                    time.sleep(ORPHAN_POLL_INTERVAL)

                os.remove(pid_file)

            except Exception as e: # pylint: disable=C0103
                logger.warn(
                    u"Exception occurred waiting for orphan agent to terminate: {0}",
                    ustr(e))
        return

    def _ensure_partition_assigned(self):
        """
        Assign the VM to a partition (0 - 99). Downloaded updates may be configured
        to run on only some VMs; the assigned partition determines eligibility.
        """
        if not os.path.exists(self._partition_file):
            partition = ustr(int(datetime.utcnow().microsecond / 10000))
            fileutil.write_file(self._partition_file, partition)
            add_event(
                AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.Partition,
                is_success=True,
                message=partition)

    def _ensure_readonly_files(self):
        for g in READONLY_FILE_GLOBS: # pylint: disable=C0103
            for path in glob.iglob(os.path.join(conf.get_lib_dir(), g)):
                os.chmod(path, stat.S_IRUSR)

    def _ensure_cgroups_initialized(self):
        configurator = CGroupConfigurator.get_instance()
        configurator.initialize()

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
                msg = u"Agent {0} restarted more than {1} times in {2} seconds".format( # pylint: disable=W0311
                    self.child_agent.name,
                    CHILD_LAUNCH_RESTART_MAX,
                    CHILD_LAUNCH_INTERVAL)
                raise Exception(msg) # pylint: disable=W0311
        return

    def _filter_blacklisted_agents(self):
        self.agents = [agent for agent in self.agents if not agent.is_blacklisted]

    def _find_agents(self): # pylint: disable=R1711
        """
        Load all non-blacklisted agents currently on disk.
        """
        try:
            self._set_agents(self._load_agents())
            self._filter_blacklisted_agents()
        except Exception as e: # pylint: disable=C0103
            logger.warn(u"Exception occurred loading available agents: {0}", ustr(e))
        return

    def _get_host_plugin(self, protocol):
        return protocol.client.get_host_plugin() if protocol and protocol.client else None
    
    def _get_pid_parts(self):
        pid_file = conf.get_agent_pid_file_path()
        pid_dir = os.path.dirname(pid_file)
        pid_name = os.path.basename(pid_file)
        pid_re = re.compile("(\d+)_{0}".format(re.escape(pid_name))) # pylint: disable=W1401
        return pid_dir, pid_name, pid_re

    def _get_pid_files(self):
        pid_dir, pid_name, pid_re = self._get_pid_parts() # pylint: disable=W0612
        pid_files = [os.path.join(pid_dir, f) for f in os.listdir(pid_dir) if pid_re.match(f)]
        pid_files.sort(key=lambda f: int(pid_re.match(os.path.basename(f)).group(1)))
        return pid_files

    @property
    def _is_clean_start(self):
        return not os.path.isfile(self._sentinel_file_path())

    @property
    def _is_orphaned(self):
        parent_pid = os.getppid()
        if parent_pid in (1, None):
            return True

        if not os.path.isfile(conf.get_agent_pid_file_path()):
            return True

        return fileutil.read_file(conf.get_agent_pid_file_path()) != ustr(parent_pid)

    def _is_version_eligible(self, version):
        # Ensure the installed version is always eligible
        if version == CURRENT_VERSION and is_current_agent_installed():
            return True

        for agent in self.agents:
            if agent.version == version:
                return agent.is_available

        return False

    def _load_agents(self):
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))
        return [GuestAgent(path=agent_dir)
                        for agent_dir in glob.iglob(path) if os.path.isdir(agent_dir)] 

    def _partition(self):
        return int(fileutil.read_file(self._partition_file))

    @property
    def _partition_file(self):
        return os.path.join(conf.get_lib_dir(), AGENT_PARTITION_FILE)

    def _purge_agents(self): # pylint: disable=R1711
        """
        Remove from disk all directories and .zip files of unknown agents
        (without removing the current, running agent).
        """
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))

        known_versions = [agent.version for agent in self.agents]
        if CURRENT_VERSION not in known_versions:
            logger.verbose(
                u"Running Agent {0} was not found in the agent manifest - adding to list",
                CURRENT_VERSION)
            known_versions.append(CURRENT_VERSION)

        for agent_path in glob.iglob(path):
            try:
                name = fileutil.trim_ext(agent_path, "zip")
                m = AGENT_DIR_PATTERN.match(name) # pylint: disable=C0103
                if m is not None and FlexibleVersion(m.group(1)) not in known_versions:
                    if os.path.isfile(agent_path):
                        logger.info(u"Purging outdated Agent file {0}", agent_path)
                        os.remove(agent_path)
                    else:
                        logger.info(u"Purging outdated Agent directory {0}", agent_path)
                        shutil.rmtree(agent_path)
            except Exception as e: # pylint: disable=C0103
                logger.warn(u"Purging {0} raised exception: {1}", agent_path, ustr(e))
        return

    def _set_agents(self, agents=[]): # pylint: disable=W0102,R1711
        self.agents = agents
        self.agents.sort(key=lambda agent: agent.version, reverse=True)
        return

    def _set_sentinel(self, agent=CURRENT_AGENT, msg="Unknown cause"): # pylint: disable=R1711
        try:
            fileutil.write_file(
                self._sentinel_file_path(),
                "[{0}] [{1}]".format(agent, msg))
        except Exception as e: # pylint: disable=C0103
            logger.warn(
                u"Exception writing sentinel file {0}: {1}",
                self._sentinel_file_path(),
                str(e))
        return

    def _sentinel_file_path(self):
        return os.path.join(conf.get_lib_dir(), AGENT_SENTINEL_FILE)

    def _shutdown(self):
        self.running = False

        if not os.path.isfile(self._sentinel_file_path()):
            return

        try:
            os.remove(self._sentinel_file_path())
        except Exception as e: # pylint: disable=C0103
            logger.warn(
                u"Exception removing sentinel file {0}: {1}",
                self._sentinel_file_path(),
                str(e))
        return

    def _upgrade_available(self, protocol, base_version=CURRENT_VERSION):
        # Ignore new agents if updating is disabled
        if not conf.get_autoupdate_enabled():
            return False

        now = time.time()
        if self.last_attempt_time is not None:
            next_attempt_time = self.last_attempt_time + \
                                    conf.get_autoupdate_frequency()
        else:
            next_attempt_time = now
        if next_attempt_time > now:
            return False

        family = conf.get_autoupdate_gafamily()
        logger.info("Checking for agent updates (family: {0})", family)

        self.last_attempt_time = now

        try:
            manifest_list, etag = protocol.get_vmagent_manifests()

            manifests = [m for m in manifest_list.vmAgentManifests \
                            if m.family == family and len(m.versionsManifestUris) > 0]
            if len(manifests) == 0: # pylint: disable=len-as-condition
                logger.verbose(u"Incarnation {0} has no {1} agent updates",
                                etag, family) 
                return False

            pkg_list = protocol.get_vmagent_pkgs(manifests[0])

            # Set the agents to those available for download at least as
            # current as the existing agent and remove from disk any agent
            # no longer reported to the VM.
            # Note:
            #  The code leaves on disk available, but blacklisted, agents
            #  so as to preserve the state. Otherwise, those agents could be
            #  again downloaded and inappropriately retried.
            host = self._get_host_plugin(protocol=protocol)
            self._set_agents([GuestAgent(pkg=pkg, host=host) for pkg in pkg_list.versions])

            self._purge_agents()
            self._filter_blacklisted_agents()

            # Return True if current agent is no longer available or an
            # agent with a higher version number is available
            return not self._is_version_eligible(base_version) \
                or (len(self.agents) > 0 and self.agents[0].version > base_version)

        except Exception as e: # pylint: disable=W0612,C0103
            msg = u"Exception retrieving agent manifests: {0}".format(ustr(traceback.format_exc()))
            add_event(AGENT_NAME, op=WALAEventOperation.Download, version=CURRENT_VERSION, is_success=False, message=msg)
            return False

    def _write_pid_file(self):
        pid_files = self._get_pid_files()

        pid_dir, pid_name, pid_re = self._get_pid_parts()

        previous_pid_file = None if len(pid_files) <= 0 else pid_files[-1] # pylint: disable=len-as-condition
        pid_index = -1 \
                    if previous_pid_file is None \
                    else int(pid_re.match(os.path.basename(previous_pid_file)).group(1))
        pid_file = os.path.join(pid_dir, "{0}_{1}".format(pid_index+1, pid_name))

        try:
            fileutil.write_file(pid_file, ustr(os.getpid()))
            logger.info(u"{0} running as process {1}", CURRENT_AGENT, ustr(os.getpid()))
        except Exception as e: # pylint: disable=C0103
            pid_file = None
            logger.warn(
                u"Expection writing goal state agent {0} pid to {1}: {2}",
                CURRENT_AGENT,
                pid_file,
                ustr(e))

        return pid_files, pid_file

    def _send_heartbeat_telemetry(self, protocol):
        if self._last_telemetry_heartbeat is None:
            self._last_telemetry_heartbeat = datetime.utcnow() - UpdateHandler.TELEMETRY_HEARTBEAT_PERIOD

        if datetime.utcnow() >= (self._last_telemetry_heartbeat + UpdateHandler.TELEMETRY_HEARTBEAT_PERIOD):
            dropped_packets = self.osutil.get_firewall_dropped_packets(protocol.get_endpoint())
            auto_update_enabled = 1 if conf.get_autoupdate_enabled() else 0

            telemetry_msg = "{0};{1};{2};{3};{4}".format(self._heartbeat_counter, self._heartbeat_id, dropped_packets,
                                                         self._heartbeat_update_goal_state_error_count, auto_update_enabled)
            debug_log_msg = "[DEBUG HeartbeatCounter: {0};HeartbeatId: {1};DroppedPackets: {2};" \
                            "UpdateGSErrors: {3};AutoUpdate: {4}]".format(self._heartbeat_counter,
                                                                          self._heartbeat_id, dropped_packets,
                                                                          self._heartbeat_update_goal_state_error_count,
                                                                          auto_update_enabled)

            # Write Heartbeat events/logs
            add_event(name=AGENT_NAME, version=CURRENT_VERSION, op=WALAEventOperation.HeartBeat, is_success=True,
                      message=telemetry_msg, log_event=False)
            logger.info(u"[HEARTBEAT] Agent {0} is running as the goal state agent {1}", CURRENT_AGENT, debug_log_msg)

            # Update/Reset the counters
            self._heartbeat_counter += 1
            self._heartbeat_update_goal_state_error_count = 0
            self._last_telemetry_heartbeat = datetime.utcnow()

    @staticmethod
    def _ensure_extension_telemetry_state_configured_properly(protocol):
        for name, path in list_agent_lib_directory(skip_agent_package=True):

            try:
                handler_instance = ExtHandlersHandler.get_ext_handler_instance_from_path(name=name,
                                                                                         path=path,
                                                                                         protocol=protocol)
            except Exception:
                # Ignore errors if any
                continue

            try:
                if handler_instance is not None:
                    # Recreate the HandlerEnvironment for existing extensions on startup.
                    # This is to ensure that existing extensions can start using the telemetry pipeline if they support
                    # it and also ensures that the extensions are not sending out telemetry if the Agent has to disable the feature.
                    handler_instance.create_handler_env()
            except Exception as e: # pylint: disable=C0103
                logger.warn(
                    "Unable to re-create HandlerEnvironment file on service startup. Error: {0}".format(ustr(e)))
                continue

        try:
            if not is_extension_telemetry_pipeline_enabled():
                # If extension telemetry pipeline is disabled, ensure we delete all existing extension events directory
                # because the agent will not be listening on those events.
                extension_event_dirs = glob.glob(os.path.join(conf.get_ext_log_dir(), "*", EVENTS_DIRECTORY))
                for ext_dir in extension_event_dirs:
                    shutil.rmtree(ext_dir, ignore_errors=True)
        except Exception as e: # pylint: disable=C0103
            logger.warn("Error when trying to delete existing Extension events directory. Error: {0}".format(ustr(e)))


class GuestAgent(object):
    def __init__(self, path=None, pkg=None, host=None):
        self.pkg = pkg
        self.host = host
        version = None
        if path is not None:
            m = AGENT_DIR_PATTERN.match(path) # pylint: disable=C0103
            if m == None: # pylint: disable=C0121
                raise UpdateError(u"Illegal agent directory: {0}".format(path))
            version = m.group(1)
        elif self.pkg is not None:
            version = pkg.version

        if version == None: # pylint: disable=C0121
            raise UpdateError(u"Illegal agent version: {0}".format(version))
        self.version = FlexibleVersion(version)

        location = u"disk" if path is not None else u"package"
        logger.verbose(u"Loading Agent {0} from {1}", self.name, location)

        self.error = GuestAgentError(self.get_agent_error_file())
        self.error.load()

        try:
            self._ensure_downloaded()
            self._ensure_loaded()
        except Exception as e: # pylint: disable=C0103
            if isinstance(e, ResourceGoneError):
                raise

            # The agent was improperly blacklisting versions due to a timeout
            # encountered while downloading a later version. Errors of type
            # socket.error are IOError, so this should provide sufficient
            # protection against a large class of I/O operation failures.
            if isinstance(e, IOError):
                raise

            # Note the failure, blacklist the agent if the package downloaded
            # - An exception with a downloaded package indicates the package
            #   is corrupt (e.g., missing the HandlerManifest.json file)
            self.mark_failure(is_fatal=os.path.isfile(self.get_agent_pkg_path()))

            msg = u"Agent {0} install failed with exception: {1}".format(
                        self.name, ustr(e)) 
            detailed_msg = '{0} {1}'.format(msg, traceback.extract_tb(get_traceback(e)))
            add_event(
                AGENT_NAME,
                version=self.version,
                op=WALAEventOperation.Install,
                is_success=False,
                message=detailed_msg)

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

    def mark_failure(self, is_fatal=False):
        try:
            if not os.path.isdir(self.get_agent_dir()):
                os.makedirs(self.get_agent_dir())
            self.error.mark_failure(is_fatal=is_fatal)
            self.error.save()
            if self.error.is_blacklisted:
                logger.warn(u"Agent {0} is permanently blacklisted", self.name)
        except Exception as e: # pylint: disable=C0103
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
        self._unpack()

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
        uris_shuffled = self.pkg.uris
        random.shuffle(uris_shuffled)
        for uri in uris_shuffled:
            if not HostPluginProtocol.is_default_channel() and self._fetch(uri.uri): # pylint: disable=R1723
                break

            elif self.host is not None and self.host.ensure_initialized():
                if not HostPluginProtocol.is_default_channel():
                    logger.warn("Download failed, switching to host plugin")
                else:
                    logger.verbose("Using host plugin as default channel")

                uri, headers = self.host.get_artifact_request(uri.uri, self.host.manifest_uri)
                try:
                    if self._fetch(uri, headers=headers, use_proxy=False): # pylint: disable=R1723
                        if not HostPluginProtocol.is_default_channel():
                            logger.verbose("Setting host plugin as default channel")
                            HostPluginProtocol.set_default_channel(True)
                        break
                    else:
                        logger.warn("Host plugin download failed")

                # If the HostPlugin rejects the request,
                # let the error continue, but set to use the HostPlugin
                except ResourceGoneError:
                    HostPluginProtocol.set_default_channel(True)
                    raise

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

    def _fetch(self, uri, headers=None, use_proxy=True):
        package = None
        try:
            is_healthy = True
            error_response = ''
            resp = restutil.http_get(uri, use_proxy=use_proxy, headers=headers)
            if restutil.request_succeeded(resp):
                package = resp.read()
                fileutil.write_file(self.get_agent_pkg_path(),
                                    bytearray(package),
                                    asbin=True)
                logger.verbose(u"Agent {0} downloaded from {1}", self.name, uri)
            else:
                error_response = restutil.read_response_error(resp)
                logger.verbose("Fetch was unsuccessful [{0}]", error_response)
                is_healthy = not restutil.request_failed_at_hostplugin(resp)

            if self.host is not None:
                self.host.report_fetch_health(uri, is_healthy, source='GuestAgent', response=error_response)

        except restutil.HttpError as http_error:
            if isinstance(http_error, ResourceGoneError):
                raise

            logger.verbose(u"Agent {0} download from {1} failed [{2}]",
                           self.name,
                           uri,
                           http_error)

        return package is not None

    def _load_error(self):
        try:
            self.error = GuestAgentError(self.get_agent_error_file())
            self.error.load()
            logger.verbose(u"Agent {0} error state: {1}", self.name, ustr(self.error))
        except Exception as e: # pylint: disable=C0103
            logger.warn(u"Agent {0} failed loading error state: {1}", self.name, ustr(e))

    def _load_manifest(self): # pylint: disable=R1711
        path = self.get_agent_manifest_path()
        if not os.path.isfile(path):
            msg = u"Agent {0} is missing the {1} file".format(self.name, AGENT_MANIFEST_FILE)
            raise UpdateError(msg)

        with open(path, "r") as manifest_file:
            try:
                manifests = json.load(manifest_file)
            except Exception as e: # pylint: disable=C0103
                msg = u"Agent {0} has a malformed {1}".format(self.name, AGENT_MANIFEST_FILE)
                raise UpdateError(msg)
            if type(manifests) is list: # pylint: disable=C0123
                if len(manifests) <= 0: # pylint: disable=len-as-condition
                    msg = u"Agent {0} has an empty {1}".format(self.name, AGENT_MANIFEST_FILE)
                    raise UpdateError(msg)
                manifest = manifests[0]
            else:
                manifest = manifests

        try:
            self.manifest = HandlerManifest(manifest) # pylint: disable=W0201
            if len(self.manifest.get_enable_command()) <= 0: # pylint: disable=len-as-condition
                raise Exception(u"Manifest is missing the enable command")
        except Exception as e: # pylint: disable=C0103
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

    def _unpack(self): # pylint: disable=R1711
        try:
            if os.path.isdir(self.get_agent_dir()):
                shutil.rmtree(self.get_agent_dir())

            zipfile.ZipFile(self.get_agent_pkg_path()).extractall(self.get_agent_dir())

        except Exception as e: # pylint: disable=C0103
            fileutil.clean_ioerror(e,
                paths=[self.get_agent_dir(), self.get_agent_pkg_path()]) 

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
    def __init__(self, path): # pylint: disable=R1711
        if path is None:
            raise UpdateError(u"GuestAgentError requires a path")
        self.path = path

        self.clear()
        return
   
    def mark_failure(self, is_fatal=False): # pylint: disable=R1711
        self.last_failure = time.time() # pylint: disable=W0201
        self.failure_count += 1
        self.was_fatal = is_fatal # pylint: disable=W0201
        return

    def clear(self): # pylint: disable=R1711
        self.last_failure = 0.0
        self.failure_count = 0
        self.was_fatal = False
        return

    @property
    def is_blacklisted(self):
        return self.was_fatal or self.failure_count >= MAX_FAILURE

    def load(self): # pylint: disable=R1711
        if self.path is not None and os.path.isfile(self.path):
            with open(self.path, 'r') as f: # pylint: disable=C0103
                self.from_json(json.load(f))
        return

    def save(self): # pylint: disable=R1711
        if os.path.isdir(os.path.dirname(self.path)):
            with open(self.path, 'w') as f: # pylint: disable=C0103
                json.dump(self.to_json(), f)
        return
    
    def from_json(self, data): # pylint: disable=R1711
        self.last_failure = max( # pylint: disable=W0201
            self.last_failure,
            data.get(u"last_failure", 0.0))
        self.failure_count = max( # pylint: disable=W0201
            self.failure_count,
            data.get(u"failure_count", 0))
        self.was_fatal = self.was_fatal or data.get(u"was_fatal", False) # pylint: disable=W0201
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
