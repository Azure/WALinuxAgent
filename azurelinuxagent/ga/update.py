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
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common import event
from azurelinuxagent.common.utils import fileutil, textutil
from azurelinuxagent.common.agent_supported_feature import get_supported_feature_by_name, SupportedFeatureNames, \
    get_agent_supported_features_list_for_crp
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.common.event import add_event, initialize_event_logger_vminfo_common_parameters_and_protocol, \
    WALAEventOperation, EVENTS_DIRECTORY
from azurelinuxagent.common.exception import ExitException, AgentUpgradeExitException, AgentMemoryExceededException
from azurelinuxagent.ga.firewall_manager import FirewallManager, FirewallStateError, IptablesInconsistencyError
from azurelinuxagent.common.future import ustr, UTC, datetime_min_utc
from azurelinuxagent.common.osutil import get_osutil, systemd
from azurelinuxagent.ga.persist_firewall_rules import PersistFirewallRulesHandler
from azurelinuxagent.common.protocol.goal_state import GoalStateSource
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol, VmSettingsNotSupported
from azurelinuxagent.common.protocol.restapi import VERSION_0
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.archive import StateArchiver, AGENT_STATUS_FILE
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_LONG_NAME, AGENT_NAME, AGENT_DIR_PATTERN, CURRENT_AGENT, AGENT_VERSION, \
    CURRENT_VERSION, DISTRO_NAME, DISTRO_VERSION, get_lis_version, \
    has_logrotate, PY_VERSION_MAJOR, PY_VERSION_MINOR, PY_VERSION_MICRO, get_daemon_version
from azurelinuxagent.ga.agent_update_handler import get_agent_update_handler
from azurelinuxagent.ga.collect_logs import get_collect_logs_handler, is_log_collection_allowed
from azurelinuxagent.ga.collect_telemetry_events import get_collect_telemetry_events_handler
from azurelinuxagent.ga.env import get_env_handler
from azurelinuxagent.ga.exthandlers import ExtHandlersHandler, list_agent_lib_directory, \
    ExtensionStatusValue, ExtHandlerStatusValue
from azurelinuxagent.ga.guestagent import GuestAgent
from azurelinuxagent.ga.monitor import get_monitor_handler
from azurelinuxagent.ga.send_telemetry_events import get_send_telemetry_events_handler
from azurelinuxagent.ga.signing_certificate_util import write_signing_certificates, get_microsoft_signing_certificate_path
from azurelinuxagent.ga.confidential_vm_info import ConfidentialVMInfo

CHILD_HEALTH_INTERVAL = 15 * 60
CHILD_LAUNCH_INTERVAL = 5 * 60
CHILD_LAUNCH_RESTART_MAX = 3
CHILD_POLL_INTERVAL = 60

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
    "Certificates.xml",
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


def get_update_handler():
    return UpdateHandler()


class UpdateHandler(object):
    TELEMETRY_HEARTBEAT_PERIOD = timedelta(minutes=30)

    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()

        self._is_running = True

        self.agents = []

        self.child_agent = None
        self.child_launch_time = None
        self.child_launch_attempts = 0
        self.child_process = None

        self.signal_handler = None

        self._last_telemetry_heartbeat = None
        self._heartbeat_id = str(uuid.uuid4()).upper()
        self._heartbeat_counter = 0

        self._initial_attempt_check_memory_usage = True
        self._last_check_memory_usage_time = time.time()
        self._check_memory_usage_last_error_report = datetime_min_utc

        self._cloud_init_completed = False  # Only used when Extensions.WaitForCloudInit is enabled; note that this variable is always reset on service start.

        # VM Size is reported via the heartbeat, default it here.
        self._vm_size = None

        # these members are used to avoid reporting errors too frequently
        self._heartbeat_update_goal_state_error_count = 0
        self._update_goal_state_error_count = 0
        self._update_goal_state_next_error_report = datetime_min_utc
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

        both_auto_updates_used = conf.is_present("AutoUpdate.Enabled") and conf.is_present("AutoUpdate.UpdateToLatestVersion")
        if both_auto_updates_used:
            msg = u"The legacy AutoUpdate.Enabled configuration is also used, but it is ignored in favor of the new configuration (AutoUpdate.UpdateToLatestVersion)."
            logger.warn(msg)
            add_event(
                AGENT_NAME,
                version=CURRENT_VERSION,
                op=WALAEventOperation.Enable,
                is_success=False,
                message=msg,
                log_event=False)

        # If new flag explicitly set, agent will use latest agent downloaded and will not fall back to installed agent. See the new flag definition in conf.py
        use_latest_agent = conf.is_present("AutoUpdate.UpdateToLatestVersion") or conf.get_autoupdate_enabled()

        latest_agent = None if not use_latest_agent else self.get_latest_agent_greater_than_daemon(
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
            logger.info("{0} (Goal State Agent version {1})", AGENT_LONG_NAME, AGENT_VERSION)
            logger.info("OS: {0} {1}", DISTRO_NAME, DISTRO_VERSION)
            logger.info("Python: {0}.{1}.{2}", PY_VERSION_MAJOR, PY_VERSION_MINOR, PY_VERSION_MICRO)

            vm_arch = self.osutil.get_vm_arch()
            logger.info("CPU Arch: {0}", vm_arch)

            os_info_msg = u"Distro: {dist_name}-{dist_ver}; "\
                u"OSUtil: {util_name}; "\
                u"AgentService: {service_name}; "\
                u"Python: {py_major}.{py_minor}.{py_micro}; "\
                u"Arch: {vm_arch}; "\
                u"systemd: {systemd}; "\
                u"systemd_version: {systemd_version}; "\
                u"LISDrivers: {lis_ver}; "\
                u"logrotate: {has_logrotate};".format(
                    dist_name=DISTRO_NAME, dist_ver=DISTRO_VERSION,
                    util_name=type(self.osutil).__name__,
                    service_name=self.osutil.service_name,
                    py_major=PY_VERSION_MAJOR, py_minor=PY_VERSION_MINOR,
                    py_micro=PY_VERSION_MICRO, vm_arch=vm_arch, systemd=systemd.is_systemd(),
                    systemd_version=systemd.get_version(),
                    lis_ver=get_lis_version(), has_logrotate=has_logrotate()
                )
            logger.info(os_info_msg)

            # Initialize Confidential VM info but defer sending telemetry until common parameters are initialized
            cvm_info_err = None
            try:
                ConfidentialVMInfo.fetch_and_initialize_cvm_info()
            except Exception as ex:
                cvm_info_err = "Failed to get virtual machine security type from IMDS, will assume this is not a Confidential Virtual Machine: {0}".format(ustr(ex))

            #
            # Initialize the goal state; some components depend on information provided by the goal state and this
            # call ensures the required info is initialized (e.g. telemetry depends on the container ID.)
            #
            protocol = self.protocol_util.get_protocol(save_to_history=True)

            self._initialize_goal_state(protocol)

            # Initialize the common parameters for telemetry events
            initialize_event_logger_vminfo_common_parameters_and_protocol(protocol)

            # Send telemetry if protocol endpoint is not the known WireServer endpoint.
            endpoint = protocol.get_endpoint()
            if endpoint is not None and endpoint != KNOWN_WIRESERVER_IP:
                message = 'Protocol endpoint ({0}) is not known wireserver ip: {1}'.format(endpoint, KNOWN_WIRESERVER_IP)
                logger.info(message)
                add_event(op=WALAEventOperation.ProtocolEndpoint, message=message)

            # Send telemetry for the OS-specific info.
            add_event(AGENT_NAME, op=WALAEventOperation.OSInfo, message=os_info_msg)
            self._log_openssl_info()

            # Send telemetry for Confidential VM info
            if cvm_info_err is not None:
                logger.warn(cvm_info_err)
                add_event(op=WALAEventOperation.SignatureValidation, message=cvm_info_err, is_success=False, log_event=False)
            else:
                cvm_info_msg = "This {0} a confidential virtual machine.".format("is" if ConfidentialVMInfo.is_confidential_vm() else "is not")
                logger.info(cvm_info_msg)
                add_event(op=WALAEventOperation.SignatureValidation, message=cvm_info_msg)

            #
            # Perform initialization tasks
            #
            self._initialize_firewall(protocol.get_endpoint())

            from azurelinuxagent.ga.exthandlers import get_exthandlers_handler, migrate_handler_state
            exthandlers_handler = get_exthandlers_handler(protocol)
            migrate_handler_state()

            from azurelinuxagent.ga.remoteaccess import get_remote_access_handler
            remote_access_handler = get_remote_access_handler(protocol)

            agent_update_handler = get_agent_update_handler(protocol)

            self._ensure_no_orphans()
            self._emit_restart_event()
            self._emit_changes_in_default_configuration()
            self._ensure_readonly_files()
            self._ensure_cgroups_initialized()
            self._ensure_extension_telemetry_state_configured_properly(protocol)
            self._cleanup_legacy_goal_state_history()
            write_signing_certificates()

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
            self._start_threads(all_thread_handlers)

            logger.info("Goal State Period: {0} sec. This indicates how often the agent checks for new goal states and reports status.", self._goal_state_period)

            while self.is_running:
                self._check_daemon_running(debug)
                self._check_threads_running(all_thread_handlers)
                self._process_goal_state(exthandlers_handler, remote_access_handler, agent_update_handler)
                self._send_heartbeat_telemetry(agent_update_handler)
                self._check_agent_memory_usage()
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
            return  # pylint: disable=unreachable

        self._shutdown()
        sys.exit(0)

    @staticmethod
    def _log_openssl_info():
        try:
            version = shellutil.run_command(["openssl", "version"])
            message = "OpenSSL version: {0}".format(version)
            logger.info(message)
            add_event(op=WALAEventOperation.OpenSsl, message=message, is_success=True)
        except Exception as e:
            message = "Failed to get OpenSSL version: {0}".format(e)
            logger.info(message)
            add_event(op=WALAEventOperation.OpenSsl, message=message, is_success=False, log_event=False)
        #
        # Collect telemetry about the 'pkey' command. CryptUtil get_pubkey_from_prv() uses the 'pkey' command only as a fallback after trying 'rsa'.
        # 'pkey' also works for RSA keys, but it may not be available on older versions of OpenSSL. Check telemetry after a few releases and if there
        # are no versions of OpenSSL that do not support 'pkey' consider removing the use of 'rsa' altogether.
        #
        try:
            shellutil.run_command(["openssl", "help", "pkey"])
        except Exception as e:
            message = "OpenSSL does not support the pkey command: {0}".format(e)
            logger.info(message)
            add_event(op=WALAEventOperation.OpenSsl, message=message, is_success=False, log_event=False)

    def _initialize_goal_state(self, protocol):
        #
        # Block until we can fetch the first goal state (self._try_update_goal_state() does its own logging and error handling).
        #
        event.info(WALAEventOperation.GoalState, "Initializing the goal state...")
        while not self._try_update_goal_state(protocol):
            time.sleep(conf.get_goal_state_period())
        event.info(WALAEventOperation.GoalState, "Goal state initialization completed.")

        #
        # If FastTrack is disabled we need to check if the current goal state (which will be retrieved using the WireServer and
        # hence will be a Fabric goal state) is outdated.
        #
        if not conf.get_enable_fast_track():
            last_fast_track_timestamp = HostPluginProtocol.get_fast_track_timestamp()
            if last_fast_track_timestamp is not None:
                egs = protocol.client.get_goal_state().extensions_goal_state
                if egs.created_on_timestamp < last_fast_track_timestamp:
                    egs.is_outdated = True
                    event.info(
                        WALAEventOperation.GoalState,
                       "The current Fabric goal state is older than the most recent FastTrack goal state; will skip it.\nFabric:    {0}\nFastTrack: {1}",
                        egs.created_on_timestamp, last_fast_track_timestamp)

    def _wait_for_cloud_init(self):
        if conf.get_wait_for_cloud_init() and not self._cloud_init_completed:
            message = "Waiting for cloud-init to complete..."
            logger.info(message)
            add_event(op=WALAEventOperation.CloudInit, message=message)
            try:
                output = shellutil.run_command(["cloud-init", "status", "--wait"], timeout=conf.get_wait_for_cloud_init_timeout())
                message = "cloud-init completed\n{0}".format(output)
                logger.info(message)
                add_event(op=WALAEventOperation.CloudInit, message=message)
            except Exception as e:
                message = "An error occurred while waiting for cloud-init; will proceed to execute VM extensions. Extensions that have conflicts with cloud-init may fail.\n{0}".format(ustr(e))
                logger.error(message)
                add_event(op=WALAEventOperation.CloudInit, message=message, is_success=False, log_event=False)
            self._cloud_init_completed = True  # Mark as completed even on error since we will proceed to execute extensions

    def _get_vm_arch(self):
        return platform.machine()

    def _check_daemon_running(self, debug):
        # Check that the parent process (the agent's daemon) is still running
        if not debug and self._is_orphaned:
            raise ExitException("Agent {0} is an orphan -- exiting".format(CURRENT_AGENT))

    def _start_threads(self, all_thread_handlers):
        for thread_handler in all_thread_handlers:
            thread_handler.run()

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
        max_errors_to_log = 3

        try:
            #
            # For Fast Track goal states we need to ensure that the tenant certificate is in the goal state.
            #
            # Some scenarios can produce inconsistent goal states. For example, during hibernation/resume, the Fabric goal state changes (the
            # tenant certificate is re-generated when the VM is restarted) *without* the incarnation necessarily changing (e.g. if the incarnation
            # is 1 before the hibernation; on resume the incarnation is set to 1 even though the goal state has a new certificate). If a Fast
            # Track goal state comes after that, the extensions will need the new certificate.
            #
            # For new Fast Track goal states, we check the certificates and, if an inconsistency is detected,  re-fetch the entire goal state
            # (update_goal_state(force_update=True). We re-fetch 2 times, one without waiting (to address scenarios like hibernation) and one with
            # a delay (to address situations in which the HGAP and the WireServer are temporarily out of sync).
            #
            for attempt in range(3):
                protocol.client.update_goal_state(force_update=attempt > 0, silent=self._update_goal_state_error_count >= max_errors_to_log, save_to_history=True)

                self._goal_state = protocol.get_goal_state()

                if not (self._processing_new_extensions_goal_state() and self._goal_state.extensions_goal_state.source == GoalStateSource.FastTrack):
                    break

                if self._check_certificates(self._goal_state):
                    if attempt > 0:
                        event.info(WALAEventOperation.FetchGoalState, "The extensions goal state is now in sync with the tenant cert.")
                    break

                if attempt == 0:
                    event.info(WALAEventOperation.FetchGoalState, "The extensions are out of sync with the tenant cert. Will refresh the goal state.")
                elif attempt == 1:
                    event.info(WALAEventOperation.FetchGoalState, "The extensions are still out of sync with the tenant cert. Will refresh the goal state one more time after a short delay.")
                    time.sleep(conf.get_goal_state_period())
                else:
                    event.warn(WALAEventOperation.FetchGoalState, "The extensions are still out of sync with the tenant cert. Will continue execution, but some extensions may fail.")
                    break

            if self._update_goal_state_error_count > 0:
                event.info(
                    WALAEventOperation.FetchGoalState,
                    "Fetching the goal state recovered from previous errors. Fetched {0} (certificates: {1})",
                    self._goal_state.extensions_goal_state.id, self._goal_state.certs.summary)
                self._update_goal_state_error_count = 0

            try:
                self._supports_fast_track = conf.get_enable_fast_track() and protocol.client.get_host_plugin().check_vm_settings_support()
            except VmSettingsNotSupported:
                self._supports_fast_track = False

            return True

        except Exception as e:
            self._update_goal_state_error_count += 1
            self._heartbeat_update_goal_state_error_count += 1
            if self._update_goal_state_error_count <= max_errors_to_log:
                # Report up to 'max_errors_to_log' immediately
                self._update_goal_state_next_error_report = datetime.now(UTC)
                event.error(WALAEventOperation.FetchGoalState, "Error fetching the goal state: {0}", textutil.format_exception(e))
            else:
                # Report one single periodic error every 6 hours
                if datetime.now(UTC) >= self._update_goal_state_next_error_report:
                    self._update_goal_state_next_error_report = datetime.now(UTC) + timedelta(hours=6)
                    event.error(WALAEventOperation.FetchGoalState, "Fetching the goal state is still failing: {0}", textutil.format_exception(e))
            return False

    @staticmethod
    def _check_certificates(goal_state):
        # Check that the certificates needed by extensions are in the goal state certificates summary
        for extension in goal_state.extensions_goal_state.extensions:
            for settings in extension.settings:
                if settings.protectedSettings is not None:
                    certificate_path = os.path.join(conf.get_lib_dir(), settings.certificateThumbprint + '.crt')
                    if not os.path.isfile(certificate_path):
                        event.warn(WALAEventOperation.FetchGoalState, "The extensions goal state is out of sync with the tenant cert. Certificate {0}, needed by {1}, is missing.", settings.certificateThumbprint, extension.name)
                        return False
        return True

    def _processing_new_incarnation(self):
        """
        True if we are currently processing a new incarnation (i.e. WireServer goal state)
        """
        return self._goal_state is not None and self._goal_state.incarnation != self._last_incarnation

    def _processing_new_extensions_goal_state(self):
        """
        True if we are currently processing a new extensions goal state
        """
        return self._goal_state is not None and self._goal_state.extensions_goal_state.id != self._last_extensions_gs_id and not self._goal_state.extensions_goal_state.is_outdated

    def _process_goal_state(self, exthandlers_handler, remote_access_handler, agent_update_handler):
        protocol = exthandlers_handler.protocol

        # update self._goal_state
        if not self._try_update_goal_state(protocol):
            agent_update_handler.run(self._goal_state, self._processing_new_extensions_goal_state())
            # status reporting should be done even when the goal state is not updated
            self._report_status(exthandlers_handler, agent_update_handler)
            return

        # check for agent updates
        agent_update_handler.run(self._goal_state, self._processing_new_extensions_goal_state())

        self._wait_for_cloud_init()

        try:
            if self._processing_new_extensions_goal_state():
                if not self._extensions_summary.converged:
                    message = "A new goal state was received, but not all the extensions in the previous goal state have completed: {0}".format(self._extensions_summary)
                    logger.warn(message)
                    add_event(op=WALAEventOperation.GoalState, message=message, is_success=False, log_event=False)
                    if self._is_initial_goal_state:
                        self._on_initial_goal_state_completed(self._extensions_summary)
                self._extensions_summary = ExtensionsSummary()
                exthandlers_handler.run()

                # check cgroup and disable if any extension started in agent cgroup after goal state processed.
                # Note: Monitor thread periodically checks this in addition to here.
                CGroupConfigurator.get_instance().check_cgroups(cgroup_metrics=[])

            # report status before processing the remote access, since that operation can take a long time
            self._report_status(exthandlers_handler, agent_update_handler)

            if self._processing_new_incarnation():
                remote_access_handler.run()

            # lastly, archive the goal state history (but do it only on new goal states - no need to do it on every iteration)
            if self._processing_new_extensions_goal_state():
                UpdateHandler._archive_goal_state_history()

        finally:
            if self._goal_state is not None:
                self._last_incarnation = self._goal_state.incarnation
                self._last_extensions_gs_id = self._goal_state.extensions_goal_state.id

    @staticmethod
    def _archive_goal_state_history():
        try:
            archiver = StateArchiver(conf.get_lib_dir())
            archiver.archive()
        except Exception as exception:
            logger.warn("Error cleaning up the goal state history: {0}", ustr(exception))

    @staticmethod
    def _cleanup_legacy_goal_state_history():
        try:
            StateArchiver.purge_legacy_goal_state_history()
        except Exception as exception:
            logger.warn("Error removing legacy history files: {0}", ustr(exception))

    def _report_status(self, exthandlers_handler, agent_update_handler):
        # report_ext_handlers_status does its own error handling and returns None if an error occurred
        vm_status = exthandlers_handler.report_ext_handlers_status(
            goal_state_changed=self._processing_new_extensions_goal_state(),
            vm_agent_update_status=agent_update_handler.get_vmagent_update_status(), vm_agent_supports_fast_track=self._supports_fast_track)

        if vm_status is not None:
            self._report_extensions_summary(vm_status)
            if self._goal_state is not None:
                status_blob_text = exthandlers_handler.protocol.get_status_blob_data()
                if status_blob_text is None:
                    status_blob_text = "{}"
                self._goal_state.save_to_history(status_blob_text, AGENT_STATUS_FILE)
                if self._goal_state.extensions_goal_state.is_outdated:
                    exthandlers_handler.protocol.client.get_host_plugin().clear_fast_track_state()

    def _report_extensions_summary(self, vm_status):
        try:
            extensions_summary = ExtensionsSummary(vm_status)
            if self._extensions_summary != extensions_summary:
                self._extensions_summary = extensions_summary
                message = "Extension status: {0}".format(self._extensions_summary)
                logger.info(message)
                add_event(op=WALAEventOperation.GoalState, message=message, is_success=True)
                if self._extensions_summary.converged:
                    message = "All extensions in the goal state have reached a terminal state: {0}".format(extensions_summary)
                    logger.info(message)
                    add_event(op=WALAEventOperation.GoalState, message=message, is_success=True)
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
            u"Agent {0} forwarding signal {1} to {2}\n",
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

            def log_if_agent_versioning_feature_disabled():
                supports_ga_versioning = False
                for _, feature in get_agent_supported_features_list_for_crp().items():
                    if feature.name == SupportedFeatureNames.GAVersioningGovernance:
                        supports_ga_versioning = True
                        break
                if not supports_ga_versioning:
                    msg = "Agent : {0} doesn't support GA Versioning".format(CURRENT_VERSION)
                    log_event(msg)

            log_if_int_changed_from_default("Extensions.GoalStatePeriod", conf.get_goal_state_period(),
                "Changing this value affects how often extensions are processed and status for the VM is reported. Too small a value may report the VM as unresponsive")
            log_if_int_changed_from_default("Extensions.InitialGoalStatePeriod", conf.get_initial_goal_state_period(),
                "Changing this value affects how often extensions are processed and status for the VM is reported. Too small a value may report the VM as unresponsive")
            log_if_op_disabled("OS.EnableFirewall", conf.enable_firewall())
            log_if_op_disabled("Extensions.Enabled", conf.get_extensions_enabled())
            log_if_op_disabled("AutoUpdate.Enabled", conf.get_autoupdate_enabled())
            log_if_op_disabled("AutoUpdate.UpdateToLatestVersion", conf.get_auto_update_to_latest_version())

            if conf.is_present("AutoUpdate.Enabled") and conf.get_autoupdate_enabled() != conf.get_auto_update_to_latest_version():
                msg = "AutoUpdate.Enabled property is **Deprecated** now but it's set to different value from AutoUpdate.UpdateToLatestVersion. Please consider removing it if added by mistake"
                logger.warn(msg)
                add_event(AGENT_NAME, op=WALAEventOperation.ConfigurationChange, message=msg)

            if conf.enable_firewall():
                log_if_int_changed_from_default("OS.EnableFirewallPeriod", conf.get_enable_firewall_period())

            if conf.get_autoupdate_enabled():
                log_if_int_changed_from_default("Autoupdate.Frequency", conf.get_autoupdate_frequency())

            if conf.get_enable_fast_track():
                log_if_op_disabled("Debug.EnableFastTrack", conf.get_enable_fast_track())

            if conf.get_lib_dir() != "/var/lib/waagent":
                log_event("lib dir is in an unexpected location: {0}".format(conf.get_lib_dir()))

            log_if_agent_versioning_feature_disabled()

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

    def _ensure_readonly_files(self):
        for g in READONLY_FILE_GLOBS:
            for path in glob.iglob(os.path.join(conf.get_lib_dir(), g)):
                # Owner should retain write permissions for signing certificate
                if path == get_microsoft_signing_certificate_path():
                    continue
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

    def _get_pid_parts(self):
        pid_file = conf.get_agent_pid_file_path()
        pid_dir = os.path.dirname(pid_file)
        pid_name = os.path.basename(pid_file)
        pid_re = re.compile(r"(\d+)_{0}".format(re.escape(pid_name)))
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
        return [GuestAgent.from_installed_agent(agent_dir)
                for agent_dir in glob.iglob(path) if os.path.isdir(agent_dir)]

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

    def _send_heartbeat_telemetry(self, agent_update_handler):
        if self._last_telemetry_heartbeat is None:
            self._last_telemetry_heartbeat = datetime.now(UTC) - UpdateHandler.TELEMETRY_HEARTBEAT_PERIOD

        if datetime.now(UTC) >= (self._last_telemetry_heartbeat + UpdateHandler.TELEMETRY_HEARTBEAT_PERIOD):
            auto_update_enabled = 1 if conf.get_auto_update_to_latest_version() else 0
            update_mode = agent_update_handler.get_current_update_mode()

            # Note: When we add new values to the heartbeat message, please add a semicolon at the end of the value.
            # This helps to parse the message easily in kusto queries with regex
            heartbeat_msg = "HeartbeatCounter: {0};HeartbeatId: {1};UpdateGSErrors: {2};AutoUpdate: {3};UpdateMode: {4};".format(
            	self._heartbeat_counter, self._heartbeat_id, self._heartbeat_update_goal_state_error_count, auto_update_enabled, update_mode)

            # Write Heartbeat events/logs
            add_event(name=AGENT_NAME, version=CURRENT_VERSION, op=WALAEventOperation.HeartBeat, is_success=True,
                      message=heartbeat_msg, log_event=False)
            logger.info(u"[HEARTBEAT] Agent {0} is running as the goal state agent [DEBUG {1}]", CURRENT_AGENT, heartbeat_msg)

            # Update/Reset the counters
            self._heartbeat_counter += 1
            self._heartbeat_update_goal_state_error_count = 0
            self._last_telemetry_heartbeat = datetime.now(UTC)

    def _check_agent_memory_usage(self):
        """
        This checks the agent current memory usage and safely exit the process if agent reaches the memory limit
        """
        try:
            if conf.get_enable_agent_memory_usage_check() and self._extensions_summary.converged:
                # we delay first attempt memory usage check, so that current agent won't get blacklisted due to multiple restarts(because of memory limit reach) too frequently
                if (self._initial_attempt_check_memory_usage and time.time() - self._last_check_memory_usage_time > CHILD_LAUNCH_INTERVAL) or \
                        (not self._initial_attempt_check_memory_usage and time.time() - self._last_check_memory_usage_time > conf.get_cgroup_check_period()):
                    self._last_check_memory_usage_time = time.time()
                    self._initial_attempt_check_memory_usage = False
                    CGroupConfigurator.get_instance().check_agent_memory_usage()
        except AgentMemoryExceededException as exception:
            msg = "Check on agent memory usage:\n{0}".format(ustr(exception))
            logger.info(msg)
            add_event(AGENT_NAME, op=WALAEventOperation.AgentMemory, is_success=True, message=msg)
            raise ExitException("Agent {0} is reached memory limit -- exiting".format(CURRENT_AGENT))
        except Exception as exception:
            if self._check_memory_usage_last_error_report == datetime_min_utc or (self._check_memory_usage_last_error_report + timedelta(hours=6)) > datetime.now(UTC):
                self._check_memory_usage_last_error_report = datetime.now(UTC)
                msg = "Error checking the agent's memory usage: {0} --- [NOTE: Will not log the same error for the 6 hours]".format(ustr(exception))
                logger.warn(msg)
                add_event(AGENT_NAME, op=WALAEventOperation.AgentMemory, is_success=False, message=msg)

    @staticmethod
    def _ensure_extension_telemetry_state_configured_properly(protocol):
        etp_enabled = get_supported_feature_by_name(SupportedFeatureNames.ExtensionTelemetryPipeline).is_supported
        for name, path in list_agent_lib_directory(skip_agent_package=True):

            try:
                handler_instance = ExtHandlersHandler.get_ext_handler_instance_from_path(name=name, path=path,  protocol=protocol)
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
    def _initialize_firewall(wire_server_address):
        try:
            if not conf.enable_firewall():
                event.info(WALAEventOperation.Firewall, "Skipping firewall initialization, since OS.EnableFirewall=False")
                return

            firewall_manager = FirewallManager.create(wire_server_address)
            firewall_manager.verbose = True

            try:
                firewall_manager.remove_legacy_rule()
            except Exception as error:
                event.error(WALAEventOperation.Firewall, "Unable to remove legacy firewall rule. Error: {0}", ustr(error))

            logger.info("Checking state of the firewall")
            try:
                if firewall_manager.check():
                    event.info(WALAEventOperation.Firewall, "The firewall rules for Azure Fabric are already setup:\n{0}", firewall_manager.get_state())
                else:
                    firewall_manager.setup()
                    event.info(WALAEventOperation.Firewall, "Created firewall rules for Azure Fabric:\n{0}", firewall_manager.get_state())
            except IptablesInconsistencyError as e:
                event.warn(WALAEventOperation.FirewallInconsistency, "{0}", ustr(e))
            except FirewallStateError as e:
                event.warn(WALAEventOperation.Firewall, "The firewall rules for Azure Fabric are not setup correctly (the environment thread will fix it): {0}. Current state:\n{1}", ustr(e), firewall_manager.get_state())

            #
            # Ensure firewall rules are persisted across reboots
            #
            event.info(WALAEventOperation.PersistFirewallRules, "Setting up persistent firewall rules")
            try:
                PersistFirewallRulesHandler(dst_ip=wire_server_address).setup()
            except Exception as error:
                event.error(WALAEventOperation.PersistFirewallRules, "Unable to setup the persistent firewall rules: {0}", ustr(error))

        except Exception as e:
            event.error(WALAEventOperation.Firewall, "Error initializing firewall: {0}", ustr(e))
