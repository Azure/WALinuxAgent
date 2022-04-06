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
import uuid
import zipfile
from datetime import datetime, timedelta

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.protocol.imds import get_imds_client
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.restutil as restutil
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.agent_supported_feature import get_supported_feature_by_name, SupportedFeatureNames
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.event import add_event, initialize_event_logger_vminfo_common_parameters, \
    WALAEventOperation, EVENTS_DIRECTORY
from azurelinuxagent.common.exception import ResourceGoneError, UpdateError, ExitException, AgentUpgradeExitException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil, systemd
from azurelinuxagent.common.persist_firewall_rules import PersistFirewallRulesHandler
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.protocol.restapi import VMAgentUpdateStatus, VMAgentUpdateStatuses, ExtHandlerPackageList, \
    VERSION_0
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.archive import StateArchiver, AGENT_STATUS_FILE
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.networkutil import AddFirewallRules
from azurelinuxagent.common.utils.shellutil import CommandError
from azurelinuxagent.common.version import AGENT_NAME, AGENT_DIR_PATTERN, CURRENT_AGENT, \
    CURRENT_VERSION, DISTRO_NAME, DISTRO_VERSION, get_lis_version, \
    has_logrotate, PY_VERSION_MAJOR, PY_VERSION_MINOR, PY_VERSION_MICRO, get_daemon_version
from azurelinuxagent.ga.collect_logs import get_collect_logs_handler, is_log_collection_allowed
from azurelinuxagent.ga.collect_telemetry_events import get_collect_telemetry_events_handler
from azurelinuxagent.ga.env import get_env_handler
from azurelinuxagent.ga.exthandlers import HandlerManifest, ExtHandlersHandler, list_agent_lib_directory, \
    ExtensionStatusValue, ExtHandlerStatusValue
from azurelinuxagent.ga.monitor import get_monitor_handler
from azurelinuxagent.ga.send_telemetry_events import get_send_telemetry_events_handler

AGENT_ERROR_FILE = "error.json"  # File name for agent error record
AGENT_MANIFEST_FILE = "HandlerManifest.json"
AGENT_PARTITION_FILE = "partition"

CHILD_HEALTH_INTERVAL = 15 * 60
CHILD_LAUNCH_INTERVAL = 5 * 60
CHILD_LAUNCH_RESTART_MAX = 3
CHILD_POLL_INTERVAL = 60

MAX_FAILURE = 3  # Max failure allowed for agent before blacklisted

GOAL_STATE_PERIOD_EXTENSIONS_DISABLED = 5 * 60

ORPHAN_POLL_INTERVAL = 3
ORPHAN_WAIT_INTERVAL = 15 * 60

AGENT_SENTINEL_FILE = "current_version"

# This file marks that the first goal state (after provisioning) has been completed, either because it converged or because we received another goal
# state before it converged. The contents will be an instance of ExtensionsSummary. If the file does not exist then we have not finished processing
# the goal state.
INITIAL_GOAL_STATE_FILE = "initial_goal_state"

READONLY_FILE_GLOBS = [
    "*.crt",
    "*.p7m",
    "*.pem",
    "*.prv",
    "ovf-env.xml"
]


class ExtensionsSummary(object):
    """
    The extensions summary is a list of (extension name, extension status) tuples for the current goal state; it is
    used to report changes in the status of extensions and to keep track of when the goal state converges (i.e. when
    all extensions in the goal state reach a terminal state: success or error.)
    The summary is computed from the VmStatus reported to blob storage.
    """
    def __init__(self, vm_status=None):
        if vm_status is None:
            self.summary = []
            self.converged = True
        else:
            # take the name and status of the extension if is it not None, else use the handler's
            self.summary = [(o.name, o.status) for o in map(lambda h: h.extension_status if h.extension_status is not None else h, vm_status.vmAgent.extensionHandlers)]
            self.summary.sort(key=lambda s: s[0])  # sort by extension name to make comparisons easier
            self.converged = all(status in (ExtensionStatusValue.success, ExtensionStatusValue.error, ExtHandlerStatusValue.ready, ExtHandlerStatusValue.not_ready) for _, status in self.summary)

    def __eq__(self, other):
        return self.summary == other.summary

    def __ne__(self, other):
        return not (self == other)

    def __str__(self):
        return ustr(self.summary)


class AgentUpgradeType(object):
    """
    Enum for different modes of Agent Upgrade
    """
    Hotfix = "Hotfix"
    Normal = "Normal"


def get_update_handler():
    return UpdateHandler()


class UpdateHandler(object):
    TELEMETRY_HEARTBEAT_PERIOD = timedelta(minutes=30)

    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()

        self._is_running = True

        # Member variables to keep track of the Agent AutoUpgrade
        self.last_attempt_time = None
        self._last_hotfix_upgrade_time = None
        self._last_normal_upgrade_time = None

        self.agents = []

        self.child_agent = None
        self.child_launch_time = None
        self.child_launch_attempts = 0
        self.child_process = None

        self.signal_handler = None

        self._last_telemetry_heartbeat = None
        self._heartbeat_id = str(uuid.uuid4()).upper()
        self._heartbeat_counter = 0

        # VM Size is reported via the heartbeat, default it here.
        self._vm_size = None

        # these members are used to avoid reporting errors too frequently
        self._heartbeat_update_goal_state_error_count = 0
        self._last_try_update_goal_state_failed = False
        self._report_status_last_failed_goal_state = None

        # incarnation of the last goal state that has been fully processed
        # (None if no goal state has been processed)
        self._last_incarnation = None
        # ID of the last extensions goal state that has been fully processed (incarnation for WireServer goal states or etag for HostGAPlugin goal states)
        # (None if no extensions goal state has been processed)
        self._last_extensions_gs_id = None
        # Goal state that is currently been processed (None if no goal state is being processed)
        self._goal_state = None
        # Whether the agent supports FastTrack (it does, as long as the HostGAPlugin supports the vmSettings API)
        self._supports_fast_track = False

        self._extensions_summary = ExtensionsSummary()

        self._is_initial_goal_state = not os.path.exists(self._initial_goal_state_file_path())

        if not conf.get_extensions_enabled():
            self._goal_state_period = GOAL_STATE_PERIOD_EXTENSIONS_DISABLED
        else:
            if self._is_initial_goal_state:
                self._goal_state_period = conf.get_initial_goal_state_period()
            else:
                self._goal_state_period = conf.get_goal_state_period()

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

        latest_agent = None if not conf.get_autoupdate_enabled() else self.get_latest_agent_greater_than_daemon(
            daemon_version=CURRENT_VERSION)
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
                    # Wait for the process to exit
                    if self.child_process.wait() > 0:
                        msg = u"ExtHandler process {0} launched with command '{1}' exited with return code: {2}".format(
                            agent_name,
                            agent_cmd,
                            ret)
                        logger.warn(msg)

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

        except Exception as e:
            # Ignore child errors during termination
            if self.is_running:
                msg = u"Agent {0} launched with command '{1}' failed with exception: \n".format(
                    agent_name,
                    agent_cmd)
                logger.warn(msg)
                detailed_message = '{0} {1}'.format(msg, textutil.format_exception(e))
                add_event(
                    AGENT_NAME,
                    version=agent_version,
                    op=WALAEventOperation.Enable,
                    is_success=False,
                    message=detailed_message)
                if latest_agent is not None:
                    latest_agent.mark_failure(is_fatal=True, reason=detailed_message)

        self.child_process = None
        return

    def run(self, debug=False):
        """
        This is the main loop which watches for agent and extension updates.
        """

        try:
            logger.info(u"Agent {0} is running as the goal state agent", CURRENT_AGENT)

            #
            # Initialize the goal state; some components depend on information provided by the goal state and this
            # call ensures the required info is initialized (e.g. telemetry depends on the container ID.)
            #
            protocol = self.protocol_util.get_protocol()

            while not self._try_update_goal_state(protocol):
                # Don't proceed with processing anything until we're able to fetch the first goal state.
                # self._try_update_goal_state() has its own logging and error handling so not adding anything here.
                time.sleep(conf.get_goal_state_period())

            # Initialize the common parameters for telemetry events
            initialize_event_logger_vminfo_common_parameters(protocol)

            # Log OS-specific info.
            os_info_msg = u"Distro: {dist_name}-{dist_ver}; "\
                u"OSUtil: {util_name}; AgentService: {service_name}; "\
                u"Python: {py_major}.{py_minor}.{py_micro}; "\
                u"systemd: {systemd}; "\
                u"LISDrivers: {lis_ver}; "\
                u"logrotate: {has_logrotate};".format(
                    dist_name=DISTRO_NAME, dist_ver=DISTRO_VERSION,
                    util_name=type(self.osutil).__name__,
                    service_name=self.osutil.service_name,
                    py_major=PY_VERSION_MAJOR, py_minor=PY_VERSION_MINOR,
                    py_micro=PY_VERSION_MICRO, systemd=systemd.is_systemd(),
                    lis_ver=get_lis_version(), has_logrotate=has_logrotate()
                )

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
            self._ensure_firewall_rules_persisted(dst_ip=protocol.get_endpoint())
            self._add_accept_tcp_firewall_rule_if_not_enabled(dst_ip=protocol.get_endpoint())
            self._reset_legacy_blacklisted_agents()

            # Get all thread handlers
            telemetry_handler = get_send_telemetry_events_handler(self.protocol_util)
            all_thread_handlers = [
                get_monitor_handler(),
                get_env_handler(),
                telemetry_handler,
                get_collect_telemetry_events_handler(telemetry_handler)
            ]

            if is_log_collection_allowed():
                all_thread_handlers.append(get_collect_logs_handler())

            # Launch all monitoring threads
            for thread_handler in all_thread_handlers:
                thread_handler.run()

            logger.info("Goal State Period: {0} sec. This indicates how often the agent checks for new goal states and reports status.", self._goal_state_period)

            self._cleanup_legacy_goal_state_history()

            while self.is_running:
                self._check_daemon_running(debug)
                self._check_threads_running(all_thread_handlers)
                self._process_goal_state(exthandlers_handler, remote_access_handler)
                self._send_heartbeat_telemetry(protocol)
                time.sleep(self._goal_state_period)

        except AgentUpgradeExitException as exitException:
            add_event(op=WALAEventOperation.AgentUpgrade, message=exitException.reason, log_event=False)
            logger.info(exitException.reason)
        except ExitException as exitException:
            logger.info(exitException.reason)
        except Exception as error:
            msg = u"Agent {0} failed with exception: {1}".format(CURRENT_AGENT, ustr(error))
            self._set_sentinel(msg=msg)
            logger.warn(msg)
            logger.warn(textutil.format_exception(error))
            sys.exit(1)
            # additional return here because sys.exit is mocked in unit tests
            return

        self._shutdown()
        sys.exit(0)

    def _get_vm_size(self, protocol):
        """
        Including VMSize is meant to capture the architecture of the VM (i.e. arm64 VMs will
        have arm64 included in their vmsize field and amd64 will have no architecture indicated).
        """
        if self._vm_size is None:

            imds_client = get_imds_client(protocol.get_endpoint())

            try:
                imds_info = imds_client.get_compute()
                self._vm_size = imds_info.vmSize
            except Exception as e:
                err_msg = "Attempts to retrieve VM size information from IMDS are failing: {0}".format(textutil.format_exception(e))
                logger.periodic_warn(logger.EVERY_SIX_HOURS, "[PERIODIC] {0}".format(err_msg))
                return "unknown"

        return self._vm_size

    def _check_daemon_running(self, debug):
        # Check that the parent process (the agent's daemon) is still running
        if not debug and self._is_orphaned:
            raise ExitException("Agent {0} is an orphan -- exiting".format(CURRENT_AGENT))

    def _check_threads_running(self, all_thread_handlers):
        # Check that all the threads are still running
        for thread_handler in all_thread_handlers:
            if thread_handler.keep_alive() and not thread_handler.is_alive():
                logger.warn("{0} thread died, restarting".format(thread_handler.get_thread_name()))
                thread_handler.start()

    def _try_update_goal_state(self, protocol):
        """
        Attempts to update the goal state and returns True on success or False on failure, sending telemetry events about the failures.
        """
        try:
            protocol.update_goal_state()

            self._goal_state = protocol.get_goal_state()

            if self._last_try_update_goal_state_failed:
                self._last_try_update_goal_state_failed = False
                message = u"Retrieving the goal state recovered from previous errors"
                add_event(AGENT_NAME, op=WALAEventOperation.FetchGoalState, version=CURRENT_VERSION, is_success=True, message=message, log_event=False)
                logger.info(message)

            self._supports_fast_track = conf.get_enable_fast_track() and protocol.client.get_host_plugin().check_vm_settings_support()

        except Exception as e:
            if not self._last_try_update_goal_state_failed:
                self._last_try_update_goal_state_failed = True
                message = u"An error occurred while retrieving the goal state: {0}".format(textutil.format_exception(e))
                logger.warn(message)
                add_event(AGENT_NAME, op=WALAEventOperation.FetchGoalState, version=CURRENT_VERSION, is_success=False, message=message, log_event=False)
            message = u"Attempts to retrieve the goal state are failing: {0}".format(ustr(e))
            logger.periodic_warn(logger.EVERY_SIX_HOURS, "[PERIODIC] {0}".format(message))
            self._heartbeat_update_goal_state_error_count += 1
            return False
        return True

    def __update_guest_agent(self, protocol):
        """
        This function checks for new Agent updates and raises AgentUpgradeExitException if available.
        There are 2 different ways the agent checks for an update -
            1) Requested Version is specified in the Goal State.
                - In this case, the Agent will download the requested version and upgrade/downgrade instantly.
            2) No requested version.
                - In this case, the agent will periodically check (1 hr) for new agent versions in GA Manifest.
                - If available, it will download all versions > CURRENT_VERSION.
                - Depending on the highest version > CURRENT_VERSION,
                  the agent will update within 4 hrs (for a Hotfix update) or 24 hrs (for a Normal update)
        """

        def log_next_update_time():
            next_normal_time, next_hotfix_time = self.__get_next_upgrade_times()
            upgrade_type = self.__get_agent_upgrade_type(available_agent)
            next_time = next_hotfix_time if upgrade_type == AgentUpgradeType.Hotfix else next_normal_time
            message_ = "Discovered new {0} upgrade {1}; Will upgrade on or after {2}".format(
                upgrade_type, available_agent.name,
                datetime.utcfromtimestamp(next_time).strftime(logger.Logger.LogTimeFormatInUTC))
            add_event(AGENT_NAME, op=WALAEventOperation.AgentUpgrade, version=CURRENT_VERSION, is_success=True,
                      message=message_, log_event=False)
            logger.info(message_)

        def handle_updates_for_requested_version():
            if requested_version < CURRENT_VERSION:
                prefix = "downgrade"
                # In case of a downgrade, we blacklist the current agent to avoid starting it back up ever again
                # (the expectation here being that if RSM is asking us to a downgrade,
                # there's a good reason for not wanting the current version).
                try:
                    # We should always have an agent directory for the CURRENT_VERSION
                    # (unless the CURRENT_VERSION == daemon version, but since we don't support downgrading
                    # below daemon version, we will never reach this code path if that's the scenario)
                    current_agent = next(agent for agent in self.agents if agent.version == CURRENT_VERSION)
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
                "Exiting current process to {0} to the request Agent version {1}".format(prefix, requested_version))

        # Ignore new agents if updating is disabled
        if not conf.get_autoupdate_enabled():
            return False

        if self._download_agent_if_upgrade_available(protocol):
            # The call to get_latest_agent_greater_than_daemon() also finds all agents in directory and sets the self.agents property.
            # This state is used to find the GuestAgent object with the current version later if requested version is available in last GS.
            available_agent = self.get_latest_agent_greater_than_daemon()
            requested_version, _ = self.__get_requested_version_and_manifest_from_last_gs(protocol)
            if requested_version is not None:
                # If requested version specified, upgrade/downgrade to the specified version instantly as this is
                # driven by the goal state (as compared to the agent periodically checking for new upgrades every hour)
                handle_updates_for_requested_version()
            elif available_agent is None:
                # Legacy behavior: The current agent can become unavailable and needs to be reverted.
                # In that case, self._upgrade_available() returns True and available_agent would be None. Handling it here.
                raise AgentUpgradeExitException(
                    "Agent {0} is reverting to the installed agent -- exiting".format(CURRENT_AGENT))
            else:
                log_next_update_time()

        self.__upgrade_agent_if_permitted()

    def _processing_new_incarnation(self):
        """
        True if we are currently processing a new incarnation (i.e. WireServer goal state)
        """
        return self._goal_state is not None and self._goal_state.incarnation != self._last_incarnation

    def _processing_new_extensions_goal_state(self):
        """
        True if we are currently processing a new extensions goal state
        """
        egs = self._goal_state.extensions_goal_state
        return self._goal_state is not None and egs.id != self._last_extensions_gs_id and not egs.is_outdated

    def _process_goal_state(self, exthandlers_handler, remote_access_handler):
        try:
            protocol = exthandlers_handler.protocol

            # update self._goal_state
            self._try_update_goal_state(protocol)

            # Update the Guest Agent if a new version is available
            if self._goal_state is not None:
                self.__update_guest_agent(protocol)

            if self._processing_new_extensions_goal_state():
                if not self._extensions_summary.converged:
                    message = "A new goal state was received, but not all the extensions in the previous goal state have completed: {0}".format(self._extensions_summary)
                    logger.warn(message)
                    add_event(op=WALAEventOperation.GoalState, message=message, is_success=False, log_event=False)
                    if self._is_initial_goal_state:
                        self._on_initial_goal_state_completed(self._extensions_summary)
                self._extensions_summary = ExtensionsSummary()
                exthandlers_handler.run()

            # always report status, even if the goal state did not change
            # do it before processing the remote access, since that operation can take a long time
            self._report_status(exthandlers_handler)

            if self._processing_new_incarnation():
                remote_access_handler.run()

            # lastly, cleanup the goal state history (but do it only on new goal states - no need to do it on every iteration)
            if self._processing_new_extensions_goal_state():
                UpdateHandler._cleanup_goal_state_history()

        finally:
            if self._goal_state is not None:
                self._last_incarnation = self._goal_state.incarnation
                self._last_extensions_gs_id = self._goal_state.extensions_goal_state.id

    @staticmethod
    def _cleanup_goal_state_history():
        try:
            archiver = StateArchiver(conf.get_lib_dir())
            archiver.purge()
            archiver.archive()
        except Exception as exception:
            logger.warn("Error cleaning up the goal state history: {0}", ustr(exception))

    @staticmethod
    def _cleanup_legacy_goal_state_history():
        try:
            StateArchiver.purge_legacy_goal_state_history()
        except Exception as exception:
            logger.warn("Error removing legacy history files: {0}", ustr(exception))

    def __get_vmagent_update_status(self, protocol, goal_state_changed):
        """
        This function gets the VMAgent update status as per the last GoalState.
        Returns: None if the last GS does not ask for requested version else VMAgentUpdateStatus
        """
        if not conf.get_enable_ga_versioning():
            return None

        update_status = None

        try:
            requested_version, manifest = self.__get_requested_version_and_manifest_from_last_gs(protocol)
            if manifest is None and goal_state_changed:
                logger.info("Unable to report update status as no matching manifest found for family: {0}".format(
                    conf.get_autoupdate_gafamily()))
                return None

            if requested_version is not None:
                if CURRENT_VERSION == requested_version:
                    status = VMAgentUpdateStatuses.Success
                    code = 0
                else:
                    status = VMAgentUpdateStatuses.Error
                    code = 1
                update_status = VMAgentUpdateStatus(expected_version=manifest.requested_version_string, status=status,
                                                    code=code)
        except Exception as error:
            if goal_state_changed:
                err_msg = "[This error will only be logged once per goal state] " \
                          "Ran into error when trying to fetch updateStatus for the agent, skipping reporting update satus. Error: {0}".format(
                           textutil.format_exception(error))
                logger.warn(err_msg)
                add_event(op=WALAEventOperation.AgentUpgrade, is_success=False, message=err_msg, log_event=False)

        return update_status

    def _report_status(self, exthandlers_handler):
        vm_agent_update_status = self.__get_vmagent_update_status(exthandlers_handler.protocol, self._processing_new_extensions_goal_state())
        # report_ext_handlers_status does its own error handling and returns None if an error occurred
        vm_status = exthandlers_handler.report_ext_handlers_status(
            goal_state_changed=self._processing_new_extensions_goal_state(),
            vm_agent_update_status=vm_agent_update_status, vm_agent_supports_fast_track=self._supports_fast_track)

        if vm_status is not None:
            self._report_extensions_summary(vm_status)
            if self._goal_state is not None:
                agent_status = exthandlers_handler.get_ext_handlers_status_debug_info(vm_status)
                self._goal_state.save_to_history(agent_status, AGENT_STATUS_FILE)
                if self._goal_state.extensions_goal_state.is_outdated:
                    exthandlers_handler.protocol.client.get_host_plugin().clear_fast_track_state()

    def _report_extensions_summary(self, vm_status):
        try:
            extensions_summary = ExtensionsSummary(vm_status)
            if self._extensions_summary != extensions_summary:
                self._extensions_summary = extensions_summary
                message = "Extension status: {0}".format(self._extensions_summary)
                logger.info(message)
                add_event(op=WALAEventOperation.GoalState, message=message)
                if self._extensions_summary.converged:
                    message = "All extensions in the goal state have reached a terminal state: {0}".format(extensions_summary)
                    logger.info(message)
                    add_event(op=WALAEventOperation.GoalState, message=message)
                    if self._is_initial_goal_state:
                        self._on_initial_goal_state_completed(self._extensions_summary)
        except Exception as error:
            # report errors only once per goal state
            if self._report_status_last_failed_goal_state != self._goal_state.extensions_goal_state.id:
                self._report_status_last_failed_goal_state = self._goal_state.extensions_goal_state.id
                msg = u"Error logging the goal state summary: {0}".format(textutil.format_exception(error))
                logger.warn(msg)
                add_event(op=WALAEventOperation.GoalState, is_success=False, message=msg)

    def _on_initial_goal_state_completed(self, extensions_summary):
        fileutil.write_file(self._initial_goal_state_file_path(), ustr(extensions_summary))
        if conf.get_extensions_enabled() and self._goal_state_period != conf.get_goal_state_period():
            self._goal_state_period = conf.get_goal_state_period()
            logger.info("Initial goal state completed, switched the goal state period to {0}", self._goal_state_period)
        self._is_initial_goal_state = False

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

    @staticmethod
    def __get_daemon_version_for_update():
        daemon_version = get_daemon_version()
        if daemon_version != FlexibleVersion(VERSION_0):
            return daemon_version
        # We return 0.0.0.0 if daemon version is not specified. In that case,
        # use the min version as 2.2.53 as we started setting the daemon version starting 2.2.53.
        return FlexibleVersion("2.2.53")

    def get_latest_agent_greater_than_daemon(self, daemon_version=None):
        """
        If autoupdate is enabled, return the most current, downloaded,
        non-blacklisted agent which is not the current version (if any) and is greater than the `daemon_version`.
        Otherwise, return None (implying to use the installed agent).
        If `daemon_version` is None, we fetch it from the environment variable set by the DaemonHandler
        """

        self._find_agents()
        daemon_version = self.__get_daemon_version_for_update() if daemon_version is None else daemon_version

        # Fetch the downloaded agents that are different from the current version and greater than the daemon version
        available_agents = [agent for agent in self.agents
                            if agent.is_available
                            and agent.version != CURRENT_VERSION and agent.version > daemon_version]

        return available_agents[0] if len(available_agents) >= 1 else None

    def _emit_restart_event(self):
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
            def log_event(msg):
                logger.info("******** {0} ********", msg)
                add_event(AGENT_NAME, op=WALAEventOperation.ConfigurationChange, message=msg)

            def log_if_int_changed_from_default(name, current, message=""):
                default = conf.get_int_default_value(name)
                if default != current:
                    log_event("{0} changed from its default: {1}. New value: {2}. {3}".format(name, default, current, message))

            def log_if_op_disabled(name, value):
                if not value:
                    log_event("{0} is set to False, not processing the operation".format(name))

            log_if_int_changed_from_default("Extensions.GoalStatePeriod", conf.get_goal_state_period(),
                "Changing this value affects how often extensions are processed and status for the VM is reported. Too small a value may report the VM as unresponsive")
            log_if_int_changed_from_default("Extensions.InitialGoalStatePeriod", conf.get_initial_goal_state_period(),
                "Changing this value affects how often extensions are processed and status for the VM is reported. Too small a value may report the VM as unresponsive")
            log_if_op_disabled("OS.EnableFirewall", conf.enable_firewall())
            log_if_op_disabled("Extensions.Enabled", conf.get_extensions_enabled())
            log_if_op_disabled("AutoUpdate.Enabled", conf.get_autoupdate_enabled())

            if conf.enable_firewall():
                log_if_int_changed_from_default("OS.EnableFirewallPeriod", conf.get_enable_firewall_period())

            if conf.get_autoupdate_enabled():
                log_if_int_changed_from_default("Autoupdate.Frequency", conf.get_autoupdate_frequency())

            if conf.get_lib_dir() != "/var/lib/waagent":
                log_event("lib dir is in an unexpected location: {0}".format(conf.get_lib_dir()))

        except Exception as e:
            logger.warn("Failed to log changes in configuration: {0}", ustr(e))

    def _ensure_no_orphans(self, orphan_wait_interval=ORPHAN_WAIT_INTERVAL):
        pid_files, ignored = self._write_pid_file()  # pylint: disable=W0612
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

            except Exception as e:
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
        for g in READONLY_FILE_GLOBS:
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
            msg = u"Agent {0} restarted more than {1} times in {2} seconds".format(
                self.child_agent.name,
                CHILD_LAUNCH_RESTART_MAX,
                CHILD_LAUNCH_INTERVAL)
            raise Exception(msg)
        return

    def _filter_blacklisted_agents(self):
        self.agents = [agent for agent in self.agents if not agent.is_blacklisted]

    def _find_agents(self):
        """
        Load all non-blacklisted agents currently on disk.
        """
        try:
            self._set_and_sort_agents(self._load_agents())
            self._filter_blacklisted_agents()
        except Exception as e:
            logger.warn(u"Exception occurred loading available agents: {0}", ustr(e))
        return

    def _get_host_plugin(self, protocol):
        return protocol.client.get_host_plugin() if protocol and protocol.client else None

    def _get_pid_parts(self):
        pid_file = conf.get_agent_pid_file_path()
        pid_dir = os.path.dirname(pid_file)
        pid_name = os.path.basename(pid_file)
        pid_re = re.compile("(\d+)_{0}".format(re.escape(pid_name)))  # pylint: disable=W1401
        return pid_dir, pid_name, pid_re

    def _get_pid_files(self):
        pid_dir, pid_name, pid_re = self._get_pid_parts()  # pylint: disable=W0612
        pid_files = [os.path.join(pid_dir, f) for f in os.listdir(pid_dir) if pid_re.match(f)]
        pid_files.sort(key=lambda f: int(pid_re.match(os.path.basename(f)).group(1)))
        return pid_files

    @property
    def is_running(self):
        return self._is_running

    @is_running.setter
    def is_running(self, value):
        self._is_running = value

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

    def _load_agents(self):
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))
        return [GuestAgent(path=agent_dir)
                for agent_dir in glob.iglob(path) if os.path.isdir(agent_dir)]

    def _partition(self):
        return int(fileutil.read_file(self._partition_file))

    @property
    def _partition_file(self):
        return os.path.join(conf.get_lib_dir(), AGENT_PARTITION_FILE)

    def _purge_agents(self):
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

    def _set_and_sort_agents(self, agents=None):
        if agents is None:
            agents = []
        self.agents = agents
        self.agents.sort(key=lambda agent: agent.version, reverse=True)
        return

    def _set_sentinel(self, agent=CURRENT_AGENT, msg="Unknown cause"):
        try:
            fileutil.write_file(
                self._sentinel_file_path(),
                "[{0}] [{1}]".format(agent, msg))
        except Exception as e:
            logger.warn(
                u"Exception writing sentinel file {0}: {1}",
                self._sentinel_file_path(),
                str(e))
        return

    def _sentinel_file_path(self):
        return os.path.join(conf.get_lib_dir(), AGENT_SENTINEL_FILE)

    @staticmethod
    def _initial_goal_state_file_path():
        return os.path.join(conf.get_lib_dir(), INITIAL_GOAL_STATE_FILE)

    def _shutdown(self):
        # Todo: Ensure all threads stopped when shutting down the main extension handler to ensure that the state of
        # all threads is clean.
        self.is_running = False

        if not os.path.isfile(self._sentinel_file_path()):
            return

        try:
            os.remove(self._sentinel_file_path())
        except Exception as e:
            logger.warn(
                u"Exception removing sentinel file {0}: {1}",
                self._sentinel_file_path(),
                str(e))
        return

    @staticmethod
    def __get_requested_version_and_manifest_from_last_gs(protocol):
        """
        Get the requested version and corresponding manifests from last GS if supported
        Returns: (Requested Version, Manifest) if supported and available
                 (None, None) if no manifests found in the last GS
                 (None, manifest) if not supported or not specified in GS
        """
        family = conf.get_autoupdate_gafamily()
        manifest_list, _ = protocol.get_vmagent_manifests()
        manifests = [m for m in manifest_list if m.family == family and len(m.uris) > 0]
        if len(manifests) == 0:
            return None, None
        if conf.get_enable_ga_versioning() and manifests[0].is_requested_version_specified:
            return manifests[0].requested_version, manifests[0]
        return None, manifests[0]

    def _download_agent_if_upgrade_available(self, protocol, base_version=CURRENT_VERSION):
        """
        This function downloads the new agent if an update is available.
        If a requested version is available in goal state, then only that version is downloaded (new-update model)
        Else, we periodically (1hr by default) checks if new Agent upgrade is available and download it on filesystem if available (old-update model)
        rtype: Boolean
        return: True if current agent is no longer available or an agent with a higher version number is available
        else False
        """

        def report_error(msg_, version_=CURRENT_VERSION, op=WALAEventOperation.Download):
            logger.warn(msg_)
            add_event(AGENT_NAME, op=op, version=version_, is_success=False, message=msg_, log_event=False)

        def can_proceed_with_requested_version():
            if not gs_updated:
                # If the goal state didn't change, don't process anything.
                return False

            # With the new model, we will get a new GS when CRP wants us to auto-update using required version.
            # If there's no new goal state, don't proceed with anything
            msg_ = "Found requested version in manifest: {0} for goal state {1}".format(
                requested_version, goal_state_id)
            logger.info(msg_)
            add_event(AGENT_NAME, op=WALAEventOperation.AgentUpgrade, is_success=True, message=msg_, log_event=False)

            if requested_version < daemon_version:
                # Don't process the update if the requested version is lesser than daemon version,
                # as we don't support downgrades below daemon versions.
                report_error(
                    "Can't process the upgrade as the requested version: {0} is < current daemon version: {1}".format(
                        requested_version, daemon_version), op=WALAEventOperation.AgentUpgrade)
                return False

            return True

        def agent_upgrade_time_elapsed(now_):
            if self.last_attempt_time is not None:
                next_attempt_time = self.last_attempt_time + conf.get_autoupdate_frequency()
            else:
                next_attempt_time = now_
            if next_attempt_time > now_:
                return False
            return True

        family = conf.get_autoupdate_gafamily()
        gs_updated = False
        daemon_version = self.__get_daemon_version_for_update()
        try:
            # Fetch the agent manifests from the latest Goal State
            goal_state_id = self._goal_state.extensions_goal_state.id
            gs_updated = self._processing_new_extensions_goal_state()
            requested_version, manifest = self.__get_requested_version_and_manifest_from_last_gs(protocol)
            if manifest is None:
                logger.verbose(
                    u"No manifest links found for agent family: {0} for goal state {1}, skipping update check".format(
                        family, goal_state_id))
                return False
        except Exception as err:
            # If there's some issues in fetching the agent manifests, report it only on goal state change
            msg = u"Exception retrieving agent manifests: {0}".format(textutil.format_exception(err))
            if gs_updated:
                report_error(msg)
            else:
                logger.verbose(msg)
            return False

        if requested_version is not None:
            # If GA versioning is enabled and requested version present in GS, and it's a new GS, follow new logic
            if not can_proceed_with_requested_version():
                return False
        else:
            # If no requested version specified in the Goal State, follow the old auto-update logic
            # Note: If the first Goal State contains a requested version, this timer won't start (i.e. self.last_attempt_time won't be updated).
            # If any subsequent goal state does not contain requested version, this timer will start then, and we will
            # download all versions available in PIR and auto-update to the highest available version on that goal state.
            now = time.time()
            if not agent_upgrade_time_elapsed(now):
                return False

            logger.info("No requested version specified, checking for all versions for agent update (family: {0})",
                        family)
            self.last_attempt_time = now

        try:
            # If we make it to this point, then either there is a requested version in a new GS (new auto-update model),
            # or the 1hr time limit has elapsed for us to check the agent manifest for updates (old auto-update model).
            pkg_list = ExtHandlerPackageList()

            # If the requested version is the current version, don't download anything;
            #       the call to purge() below will delete all other agents from disk
            # In this case, no need to even fetch the GA family manifest as we don't need to download any agent.
            if requested_version is not None and requested_version == CURRENT_VERSION:
                packages_to_download = []
                msg = "The requested version is running as the current version: {0}".format(requested_version)
                logger.info(msg)
                add_event(AGENT_NAME, op=WALAEventOperation.AgentUpgrade, is_success=True, message=msg)
            else:
                pkg_list = protocol.get_vmagent_pkgs(manifest)
                packages_to_download = pkg_list.versions

            # Verify the requested version is in GA family manifest (if specified)
            if requested_version is not None and requested_version != CURRENT_VERSION:
                for pkg in pkg_list.versions:
                    if FlexibleVersion(pkg.version) == requested_version:
                        # Found a matching package, only download that one
                        packages_to_download = [pkg]
                        break
                else:
                    msg = "No matching package found in the agent manifest for requested version: {0} in goal state {1}, skipping agent update".format(
                        requested_version, goal_state_id)
                    report_error(msg, version_=requested_version)
                    return False

            # Set the agents to those available for download at least as current as the existing agent
            # or to the requested version (if specified)
            host = self._get_host_plugin(protocol=protocol)
            agents_to_download = [GuestAgent(pkg=pkg, host=host) for pkg in packages_to_download]

            # Filter out the agents that were downloaded/extracted successfully. If the agent was not installed properly,
            # we delete the directory and the zip package from the filesystem
            self._set_and_sort_agents([agent for agent in agents_to_download if agent.is_available])

            # Remove from disk any agent no longer needed in the VM.
            # If requested version is provided, this would delete all other agents present on the VM except -
            #   - the current version and the requested version if requested version != current version
            #   - only the current version if requested version == current version
            # Note:
            #  The code leaves on disk available, but blacklisted, agents to preserve the state.
            #  Otherwise, those agents could be downloaded again and inappropriately retried.
            self._purge_agents()
            self._filter_blacklisted_agents()

            # If there are no agents available to upgrade/downgrade to, return False
            if len(self.agents) == 0:
                return False

            if requested_version is not None:
                # In case of requested version, return True if an agent with a different version number than the
                # current version is available that is higher than the current daemon version
                return self.agents[0].version != base_version and self.agents[0].version > daemon_version
            else:
                # Else, return True if the highest agent is > base_version (CURRENT_VERSION)
                return self.agents[0].version > base_version

        except Exception as err:
            msg = u"Exception downloading agents for update: {0}".format(textutil.format_exception(err))
            report_error(msg)
            return False

    def _write_pid_file(self):
        pid_files = self._get_pid_files()

        pid_dir, pid_name, pid_re = self._get_pid_parts()

        previous_pid_file = None if len(pid_files) <= 0 else pid_files[-1]
        pid_index = -1 \
            if previous_pid_file is None \
            else int(pid_re.match(os.path.basename(previous_pid_file)).group(1))
        pid_file = os.path.join(pid_dir, "{0}_{1}".format(pid_index + 1, pid_name))

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

        return pid_files, pid_file

    def _send_heartbeat_telemetry(self, protocol):
        if self._last_telemetry_heartbeat is None:
            self._last_telemetry_heartbeat = datetime.utcnow() - UpdateHandler.TELEMETRY_HEARTBEAT_PERIOD

        if datetime.utcnow() >= (self._last_telemetry_heartbeat + UpdateHandler.TELEMETRY_HEARTBEAT_PERIOD):
            dropped_packets = self.osutil.get_firewall_dropped_packets(protocol.get_endpoint())
            auto_update_enabled = 1 if conf.get_autoupdate_enabled() else 0
            # Include VMSize in the heartbeat message because the kusto table does not have 
            # a separate column for it (or architecture).
            vmsize = self._get_vm_size(protocol)

            telemetry_msg = "{0};{1};{2};{3};{4};{5}".format(self._heartbeat_counter, self._heartbeat_id, dropped_packets,
                                                         self._heartbeat_update_goal_state_error_count,
                                                         auto_update_enabled, vmsize)
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
        etp_enabled = get_supported_feature_by_name(SupportedFeatureNames.ExtensionTelemetryPipeline).is_supported
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
                    events_dir = handler_instance.get_extension_events_dir()
                    # If ETP is enabled and events directory doesn't exist for handler, create it
                    if etp_enabled and not(os.path.exists(events_dir)):
                        fileutil.mkdir(events_dir, mode=0o700)
            except Exception as e:
                logger.warn(
                    "Unable to re-create HandlerEnvironment file on service startup. Error: {0}".format(ustr(e)))
                continue

        try:
            if not etp_enabled:
                # If extension telemetry pipeline is disabled, ensure we delete all existing extension events directory
                # because the agent will not be listening on those events.
                extension_event_dirs = glob.glob(os.path.join(conf.get_ext_log_dir(), "*", EVENTS_DIRECTORY))
                for ext_dir in extension_event_dirs:
                    shutil.rmtree(ext_dir, ignore_errors=True)
        except Exception as e:
            logger.warn("Error when trying to delete existing Extension events directory. Error: {0}".format(ustr(e)))

    @staticmethod
    def _ensure_firewall_rules_persisted(dst_ip):

        if not conf.enable_firewall():
            logger.info("Not setting up persistent firewall rules as OS.EnableFirewall=False")
            return

        is_success = False
        logger.info("Starting setup for Persistent firewall rules")
        try:
            PersistFirewallRulesHandler(dst_ip=dst_ip, uid=os.getuid()).setup()
            msg = "Persistent firewall rules setup successfully"
            is_success = True
            logger.info(msg)
        except Exception as error:
            msg = "Unable to setup the persistent firewall rules: {0}".format(ustr(error))
            logger.error(msg)

        add_event(
            op=WALAEventOperation.PersistFirewallRules,
            is_success=is_success,
            message=msg,
            log_event=False)

    def _add_accept_tcp_firewall_rule_if_not_enabled(self, dst_ip):

        if not conf.enable_firewall():
            return

        def _execute_run_command(command):
            # Helper to execute a run command, returns True if no exception
            # Here we primarily check if an  iptable rule exist. True if it exits , false if not
            try:
                shellutil.run_command(command)
                return True
            except CommandError as err:
                # return code 1 is expected while using the check command. Raise if encounter any other return code
                if err.returncode != 1:
                    raise
            return False

        try:
            wait = self.osutil.get_firewall_will_wait()

            # "-C" checks if the iptable rule is available in the chain. It throws an exception with return code 1 if the ip table rule doesnt exist
            drop_rule = AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND, dst_ip, wait=wait)
            if not _execute_run_command(drop_rule):
                # DROP command doesn't exist indicates then none of the firewall rules are set yet
                # exiting here as the environment thread will set up all firewall rules
                logger.info("DROP rule is not available which implies no firewall rules are set yet. Environment thread will set it up.")
                return
            else:
                # DROP rule exists in the ip table chain. Hence checking if the DNS TCP to wireserver rule exists. If not we add it.
                accept_tcp_rule = AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND, dst_ip, wait=wait)
                if not _execute_run_command(accept_tcp_rule):
                    try:
                        logger.info(
                            "Firewall rule to allow DNS TCP request to wireserver for a non root user unavailable. Setting it now.")
                        accept_tcp_rule = AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.INSERT_COMMAND, dst_ip, wait=wait)
                        shellutil.run_command(accept_tcp_rule)
                        logger.info(
                            "Succesfully added firewall rule to allow non root users to do a DNS TCP request to wireserver")
                    except CommandError as error:
                        msg = "Unable to set the non root tcp access firewall rule :" \
                              "Run command execution for {0} failed with error:{1}.Return Code:{2}"\
                            .format(error.command, error.stderr, error.returncode)
                        logger.error(msg)
                else:
                    logger.info(
                        "Not setting the firewall rule to allow DNS TCP request to wireserver for a non root user since it already exists")
        except Exception as e:
            msg = "Error while checking ip table rules:{0}".format(ustr(e))
            logger.error(msg)

    def __get_next_upgrade_times(self):
        """
        Get the next upgrade times
        return: Next Normal Upgrade Time, Next Hotfix Upgrade Time
        """

        def get_next_process_time(last_val, frequency):
            return now if last_val is None else last_val + frequency

        now = time.time()
        next_hotfix_time = get_next_process_time(self._last_hotfix_upgrade_time, conf.get_hotfix_upgrade_frequency())
        next_normal_time = get_next_process_time(self._last_normal_upgrade_time, conf.get_normal_upgrade_frequency())

        return next_normal_time, next_hotfix_time

    @staticmethod
    def __get_agent_upgrade_type(available_agent):
        # We follow semantic versioning for the agent, if <Major>.<Minor> is same, then <Patch>.<Build> has changed.
        # In this case, we consider it as a Hotfix upgrade. Else we consider it a Normal upgrade.
        if available_agent.version.major == CURRENT_VERSION.major and available_agent.version.minor == CURRENT_VERSION.minor:
            return AgentUpgradeType.Hotfix
        return AgentUpgradeType.Normal

    def __upgrade_agent_if_permitted(self):
        """
        Check every 4hrs for a Hotfix Upgrade and 24 hours for a Normal upgrade and upgrade the agent if available.
        raises: ExitException when a new upgrade is available in the relevant time window, else returns
        """

        next_normal_time, next_hotfix_time = self.__get_next_upgrade_times()
        now = time.time()
        # Not permitted to update yet for any of the AgentUpgradeModes
        if next_hotfix_time > now and next_normal_time > now:
            return

        # Update the last upgrade check time even if no new agent is available for upgrade
        self._last_hotfix_upgrade_time = now if next_hotfix_time <= now else self._last_hotfix_upgrade_time
        self._last_normal_upgrade_time = now if next_normal_time <= now else self._last_normal_upgrade_time

        available_agent = self.get_latest_agent_greater_than_daemon()
        if available_agent is None or available_agent.version <= CURRENT_VERSION:
            logger.verbose("No agent upgrade discovered")
            return

        upgrade_type = self.__get_agent_upgrade_type(available_agent)
        upgrade_message = "{0} Agent upgrade discovered, updating to {1} -- exiting".format(upgrade_type,
                                                                                            available_agent.name)

        if (upgrade_type == AgentUpgradeType.Hotfix and next_hotfix_time <= now) or (
                upgrade_type == AgentUpgradeType.Normal and next_normal_time <= now):
            raise AgentUpgradeExitException(upgrade_message)

    def _reset_legacy_blacklisted_agents(self):
        # Reset the state of all blacklisted agents that were blacklisted by legacy agents (i.e. not during auto-update)

        # Filter legacy agents which are blacklisted but do not contain a `reason` in their error.json files
        # (this flag signifies that this agent was blacklisted by the newer agents).
        try:
            legacy_blacklisted_agents = [agent for agent in self._load_agents() if
                                         agent.is_blacklisted and agent.error.reason == '']
            for agent in legacy_blacklisted_agents:
                agent.clear_error()
        except Exception as err:
            logger.warn("Unable to reset legacy blacklisted agents due to: {0}".format(err))


class GuestAgent(object):
    def __init__(self, path=None, pkg=None, host=None):
        self.pkg = pkg
        self.host = host
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
            if isinstance(e, ResourceGoneError):
                raise

            # The agent was improperly blacklisting versions due to a timeout
            # encountered while downloading a later version. Errors of type
            # socket.error are IOError, so this should provide sufficient
            # protection against a large class of I/O operation failures.
            if isinstance(e, IOError):
                raise

            # If we're unable to download/unpack the agent, delete the Agent directory and the zip file (if exists) to
            # ensure we try downloading again in the next round.
            try:
                if os.path.isdir(self.get_agent_dir()):
                    shutil.rmtree(self.get_agent_dir(), ignore_errors=True)
                if os.path.isfile(self.get_agent_pkg_path()):
                    os.remove(self.get_agent_pkg_path())
            except Exception as err:
                logger.warn("Unable to delete Agent files: {0}".format(err))

            msg = u"Agent {0} install failed with exception:".format(
                self.name)
            detailed_msg = '{0} {1}'.format(msg, textutil.format_exception(e))
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
            if not HostPluginProtocol.is_default_channel and self._fetch(uri):
                break

            elif self.host is not None and self.host.ensure_initialized():
                if not HostPluginProtocol.is_default_channel:
                    logger.warn("Download failed, switching to host plugin")
                else:
                    logger.verbose("Using host plugin as default channel")

                uri, headers = self.host.get_artifact_request(uri, self.host.manifest_uri)
                try:
                    if self._fetch(uri, headers=headers, use_proxy=False):
                        if not HostPluginProtocol.is_default_channel:
                            logger.verbose("Setting host plugin as default channel")
                            HostPluginProtocol.is_default_channel = True
                        break
                    else:
                        logger.warn("Host plugin download failed")

                # If the HostPlugin rejects the request,
                # let the error continue, but set to use the HostPlugin
                except ResourceGoneError:
                    HostPluginProtocol.is_default_channel = True
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
            resp = restutil.http_get(uri, use_proxy=use_proxy, headers=headers, max_retry=1)
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

    def _unpack(self):
        try:
            if os.path.isdir(self.get_agent_dir()):
                shutil.rmtree(self.get_agent_dir())

            zipfile.ZipFile(self.get_agent_pkg_path()).extractall(self.get_agent_dir())

        except Exception as e:
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
