#!/usr/bin/env python3

# Microsoft Azure Linux Agent
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

#
# Validates that the ext-handler shuts down gracefully on the natural exit paths
# (AgentUpgradeExitException / ExitException). The agent's UpdateHandler.run() loop catches these
# exceptions, calls UpdateHandler._shutdown() and then sys.exit(0). _shutdown() must signal every
# worker thread to stop and wait (with a bounded timeout) for each of them to finish.
#
# How the test works:
#   1. We use the same self-update setup as the AgentUpdate suite: a custom older agent package is
#      built, installed on the VM, and AutoUpdate.UpdateToLatestVersion=y is configured. The setup
#      script also rotates /var/log/waagent.log so we capture only logs from this test run.
#   2. We enable log collection (Logs.Collect=y) so the CollectLogsHandler thread is started in
#      addition to the four threads always launched by run() (MonitorHandler, EnvHandler,
#      SendTelemetryHandler, TelemetryEventsCollector).
#   3. We wait for the agent to self-upgrade to the latest published version. The upgrade path
#      raises AgentUpgradeExitException, which run() catches and which triggers _shutdown().
#   4. We read /var/log/waagent.log and validate that, around the upgrade event, each worker
#      thread has both a "Signaling X thread to stop..." line and a terminal line
#      ("X thread stopped successfully" or "X thread did not stop within the timeout").
#

import re

from typing import Any, Dict, List

from assertpy import fail

from azurelinuxagent.ga.thread_handler_base import ThreadHandlerBase

from tests_e2e.tests.agent_update.self_update import SelfUpdateBvt
from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


# Threads always started by UpdateHandler.run().
_ALWAYS_RUNNING_THREADS = [
    "MonitorHandler",
    "EnvHandler",
    "SendTelemetryHandler",
    "TelemetryEventsCollector",
]

# Started only when log collection is enabled.
_LOG_COLLECTOR_THREAD = "CollectLogsHandler"

# Emitted by collect_logs.is_log_collection_allowed() during agent startup. The agent logs
#   "Log collection is supported. All three conditions must be met: ..."     when allowed
#   "Log collection is not supported. All three conditions must be met: ..." when not allowed
_LOG_COLLECTION_ALLOWED_RE = re.compile(r"Log collection is supported\.")

# AgentUpgradeExitException reason produced by self_update_version_updater.proceed_with_update().
# We use this as an anchor in the log to locate the AgentUpgrade-driven shutdown sequence.
_UPGRADE_MARKER_RE = re.compile(
    r"completed all update checks, exiting current process to upgrade to the new Agent version")

# Patterns emitted by UpdateHandler._shutdown(); see azurelinuxagent/ga/update.py.
_SIGNAL_LINE_RE = re.compile(r"Signaling (\S+) thread to stop\.\.\.")
_STOPPED_OK_RE = re.compile(r"(\S+) thread stopped successfully")
_STOPPED_TIMEOUT_RE = re.compile(r"(\S+) thread did not stop within the timeout")

# Upper bound on how long the entire shutdown sequence should take, measured from the first
# "Signaling X thread to stop..." line to the last terminal line.
#
# Derivation, based on UpdateHandler._shutdown() and ThreadHandlerBase._THREAD_JOIN_TIMEOUT:
#   Phase 1 (sequential) stops TelemetryEventsCollector and then SendTelemetryHandler one at a
#       time, each bounded by _THREAD_JOIN_TIMEOUT -> up to 2 * 5s = 10s.
#   Phase 2/3 (parallel) signals every remaining handler at once and then joins them in parallel,
#       so the slowest single join determines the wall-clock cost -> up to 1 * 5s = 5s.
#   Baseline worst case: 3 * _THREAD_JOIN_TIMEOUT = 15s.
#
# A 10s buffer is added for log I/O latency
_MAX_SHUTDOWN_DURATION_SECS = 3 * ThreadHandlerBase._THREAD_JOIN_TIMEOUT + 10  # pylint: disable=protected-access


class AgentGracefulShutdown(SelfUpdateBvt):
    """
    Verifies the graceful-shutdown sequence emitted by UpdateHandler._shutdown() when the
    ext-handler exits via AgentUpgradeExitException (the self-update path).
    """

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        # Timestamps of the first "Signaling ... to stop" line and the last terminal line in the
        # shutdown sequence. Populated by _check_shutdown_sequence() on success and consumed by
        # _verify_shutdown_duration().
        self._first_signal_ts = None
        self._last_terminal_ts = None

    def run(self):
        log.info("Setting up the VM with a custom older-version agent package...")
        # _test_setup() is provided by SelfUpdateBvt. It rotates /var/log/waagent.log, installs
        # the custom older-version pkg, and configures AutoUpdate.UpdateToLatestVersion=y so the
        # agent will self-upgrade on the next iteration.
        self._test_setup()

        log.info("Enabling log collection so the CollectLogsHandler thread is started...")
        # Reduce the initial delay so the log collector thread has time to start before the
        # self-upgrade fires. 60s is the smallest value that still allows a single collection
        # cycle if the agent runs long enough; if it does not, we still validate the four threads
        # that are always started by run().
        self._ssh_client.run_command(
            "update-waagent-conf Logs.Collect=y Debug.LogCollectorInitialDelay=60",
            use_sudo=True)

        log.info("Waiting for the agent to self-upgrade to the latest published version...")
        # _verify_agent_updated_to_latest_version() polls waagent --version until the running
        # agent matches the latest version on the manifest. This is what guarantees that the
        # AgentUpgradeExitException path was taken on the original (custom) agent process and
        # therefore _shutdown() has run.
        self._verify_agent_updated_to_latest_version()

        log.info("Verifying the graceful-shutdown sequence in /var/log/waagent.log...")
        self._verify_shutdown_sequence()

    def _verify_shutdown_sequence(self) -> None:
        # Allow a short retry window in case the upgrade marker has not been flushed yet.
        success = retry_if_false(self._check_shutdown_sequence, attempts=5, delay=15)
        if not success:
            fail("Did not find the expected graceful-shutdown sequence in /var/log/waagent.log "
                 "after the agent self-upgraded. See the logs above for details.")

        # Now verify the sequence completed within the bound
        # dictated by the per-thread join timeout.
        self._verify_shutdown_duration()

    def _verify_shutdown_duration(self) -> None:
        """
        Verifies that the entire shutdown sequence completed within _MAX_SHUTDOWN_DURATION_SECS.

        The duration is measured from the first "Signaling X thread to stop..." line (the start
        of UpdateHandler._shutdown()) to the last "thread stopped successfully" or "thread did
        not stop within the timeout" line (the end of the join phase). Both timestamps were
        captured by _check_shutdown_sequence().
        """
        if self._first_signal_ts is None or self._last_terminal_ts is None:
            fail("Internal: shutdown markers were present but "
                 "AgentLogRecord.timestamp returned None for at least one of them.")
            return

        duration = (self._last_terminal_ts - self._first_signal_ts).total_seconds()
        log.info(
            "Shutdown duration: %.2fs (first signal=%s, last terminal=%s, bound=%ds).",
            duration, self._first_signal_ts, self._last_terminal_ts,
            _MAX_SHUTDOWN_DURATION_SECS)

        if duration > _MAX_SHUTDOWN_DURATION_SECS:
            fail(
                "Graceful shutdown took {0:.2f}s, which exceeds the {1}s upper bound of threads shutdown time".format(
                    duration, _MAX_SHUTDOWN_DURATION_SECS))

    def _check_shutdown_sequence(self) -> bool:
        contents = self._ssh_client.run_command("cat /var/log/waagent.log", use_sudo=True)
        records = list(AgentLog(contents=contents).read())

        # Find the AgentUpgrade marker; if it is not yet present the upgrade has not started.
        upgrade_indices = [i for i, r in enumerate(records) if _UPGRADE_MARKER_RE.search(r.message)]
        if not upgrade_indices:
            log.info("AgentUpgrade marker not found yet in waagent.log; will retry.")
            return False

        # Take the slice of records starting from the upgrade marker. The shutdown sequence is
        # emitted between this marker and the call to sys.exit(0), so anything after the marker
        # (and before the next agent process starts logging) is the shutdown.
        shutdown_section = records[upgrade_indices[0]:]

        signaled = set()
        terminal = set()  # threads that either stopped successfully or were reported as timed out
        first_signal_ts = None
        last_terminal_ts = None
        for record in shutdown_section:
            m = _SIGNAL_LINE_RE.search(record.message)
            if m:
                signaled.add(m.group(1))
                if first_signal_ts is None:
                    first_signal_ts = record.timestamp
                continue
            m = _STOPPED_OK_RE.search(record.message)
            if m:
                terminal.add(m.group(1))
                last_terminal_ts = record.timestamp
                continue
            m = _STOPPED_TIMEOUT_RE.search(record.message)
            if m:
                terminal.add(m.group(1))
                last_terminal_ts = record.timestamp
                continue

        # Decide which threads we expect in the shutdown sequence. The four threads in
        # _ALWAYS_RUNNING_THREADS are launched unconditionally by UpdateHandler.run(), so we
        # always require them. CollectLogsHandler is launched only when is_log_collection_allowed()
        # returns True at startup (controlled by configuration AND runtime preconditions like
        # cgroup support, supported python, etc.). We asked for it via configuration, but if the
        # runtime preconditions are not met the thread will not be started and will not appear in
        # the shutdown sequence at all. So we look for the agent's startup log line
        # "Log collection is supported." to decide whether it is expected.
        expected_threads = set(_ALWAYS_RUNNING_THREADS)
        log_collection_allowed = any(_LOG_COLLECTION_ALLOWED_RE.search(r.message) for r in records)
        if log_collection_allowed:
            expected_threads.add(_LOG_COLLECTOR_THREAD)
        else:
            log.info(
                "Log collection is not allowed on this VM (no 'Log collection is supported.' entry "
                "in waagent.log); CollectLogsHandler is not expected in the shutdown sequence.")

        missing_signals = expected_threads - signaled
        missing_terminal = expected_threads - terminal

        log.info(
            "Graceful-shutdown sequence:\n"
            "    expected threads      : %s\n"
            "    signaled to stop      : %s\n"
            "    stopped or timed out  : %s",
            sorted(expected_threads), sorted(signaled), sorted(terminal))

        if missing_signals:
            log.info("Missing 'Signaling ... to stop' entries for: %s", sorted(missing_signals))
            return False
        if missing_terminal:
            log.info("Missing terminal ('stopped successfully' or 'did not stop within the timeout') "
                     "entries for: %s", sorted(missing_terminal))
            return False

        log.info("All expected threads were signaled and either stopped or timed out as expected.")
        # Stash timestamps for the duration check performed by _verify_shutdown_duration().
        self._first_signal_ts = first_signal_ts
        self._last_terminal_ts = last_terminal_ts
        return True

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        # _shutdown() emits a WARNING when a thread does not exit within the join timeout. That is
        # an expected outcome under load (the worker may be busy when the signal arrives) and the
        # test treats it as a successful "did stop or timed out" result, so silence it in the log
        # error scan.
        return [
            {
                "message": r"\S+ thread did not stop within the timeout",
                "if": lambda r: r.level == "WARNING",
            },
        ]


if __name__ == "__main__":
    AgentGracefulShutdown.run_from_command_line()
