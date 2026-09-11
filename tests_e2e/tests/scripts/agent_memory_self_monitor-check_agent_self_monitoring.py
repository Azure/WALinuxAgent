#!/usr/bin/env pypy3
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
"""
End-to-end validation of the agent's anon-memory self-monitoring + clean-exit
mitigation flow.

Approach
--------
1. Force the agent into a "always breach" configuration:
     - Debug.AgentAnonMemoryQuota=1 (bytes)             -> any anon usage breaches
     - Debug.AgentMemoryConsecutiveBreachCount=2    -> exit after 2 consecutive
     - Debug.CgroupCheckPeriod=30                   -> ~30s between samples
     - Debug.AgentMemoryMinRestartIntervalSeconds=300  -> block re-restart shortly
     - Debug.AgentMemoryMaxRestartsPerVersion=1     -> guardrail after first exit
     - Debug.EnableAgentMemoryUsageCheck=y
2. Restart the agent and wait for extensions to converge.
3. Verify the log shows two consecutive breach records, then a "sustained anon
   memory breach ... exiting" line.
4. Verify the persisted restart-history file exists and contains an entry for
   the current agent version.
5. Wait for the daemon to relaunch the ext-handler; verify the next breach
   cycle emits the "self-restart skipped" line (guardrails block it).
6. Cleanup: reset all Debug knobs and restart the agent service.
"""
import datetime
import json
import os
import re
import sys

from assertpy import fail

from azurelinuxagent.common.future import UTC
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.ga import state_dir
from azurelinuxagent.ga.agent_memory_restart_history import HISTORY_FILE_NAME
from azurelinuxagent.ga.update import CHILD_LAUNCH_INTERVAL
from azurelinuxagent.common.version import CURRENT_VERSION

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.cgroup_helpers import check_log_message, using_cgroupv2, \
    skip_if_memory_controller_is_not_enabled
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
from tests_e2e.tests.lib.retry import retry_if_false


# -----------------------------------------------------------------------------
# Config knobs used to force a deterministic breach in a short window.
# -----------------------------------------------------------------------------
_TEST_CONF = [
    "Debug.AgentAnonMemoryQuota=1",
    "Debug.AgentMemoryConsecutiveBreachCount=2",
    "Debug.AgentMemoryMaxRestartsPerVersion=1",
    "Debug.AgentMemoryMinRestartIntervalSeconds=300",
    "Debug.CgroupCheckPeriod=30",
    "Debug.CgroupLogMetrics=y",
]

_REMOVE_CONF = [
    "Debug.AgentAnonMemoryQuota",
    "Debug.AgentMemoryConsecutiveBreachCount",
    "Debug.AgentMemoryMaxRestartsPerVersion",
    "Debug.AgentMemoryMinRestartIntervalSeconds",
    "Debug.CgroupCheckPeriod",
    "Debug.CgroupLogMetrics"
]


def _skip_if_unsupported():
    if not using_cgroupv2():
        log.info("Skipping anon-memory self-monitor e2e test: distro is not cgroup v2")
        sys.exit(0)


def _apply_conf(kv_pairs, remove=False):
    log.info("Applying waagent.conf overrides: %s", kv_pairs)
    if remove:
        shellutil.run_command(["remove-waagent-conf"] + kv_pairs)
    else:
        shellutil.run_command(["update-waagent-conf"] + kv_pairs)


def _restart_agent():
    log.info("Restarting the agent service")
    shellutil.run_command(["agent-service", "restart"])


def _wait_for_agent_startup(after):
    log.info("Waiting for the agent to be up (enabling cgroups) after %s", after.isoformat())
    if not retry_if_false(lambda: check_log_message("Agent cgroups enabled: True", after_timestamp=after)):
        fail("The agent did not report 'Agent cgroups enabled: True' after restart")


def verify_consecutive_breach_events(after):
    log.info("** Verifying that consecutive breach events are logged")
    # The first breach can only appear after CHILD_LAUNCH_INTERVAL has elapsed
    # since agent start (gate in _check_agent_memory_usage) plus one
    # CgroupCheckPeriod.
    first_breach_attempts = (CHILD_LAUNCH_INTERVAL // 60) + 4  # + headroom
    if not retry_if_false(lambda: check_log_message(r"Agent anon memory breach 1/2", after_timestamp=after),
                          attempts=first_breach_attempts, delay=60):
        fail("Did not observe the first anon-memory breach log line")
    if not retry_if_false(lambda: check_log_message(r"Agent anon memory breach 2/2", after_timestamp=after)):
        fail("Did not observe the second anon-memory breach log line")
    log.info("Successfully observed 2 consecutive breach log lines")


def _get_ext_handler_pid():
    """
    Returns the PID of the running ext-handler process, or None if not found.
    The ext-handler is the child that the daemon launches with '-run-exthandlers'.
    """
    try:
        # -o = oldest match (avoid transient forks); -f matches the full cmdline.
        out = shellutil.run_command(["pgrep", "-o", "-f", "run-exthandlers"]).strip()
        return int(out) if out else None
    except Exception:
        return None


def _wait_for_ext_handler_pid(exclude_pid=None):
    """
    Wait until an ext-handler process exists whose PID != exclude_pid.
    Returns the new PID, or None if we time out.
    """
    def _new_pid_up():
        pid = _get_ext_handler_pid()
        return pid is not None and pid != exclude_pid

    if not retry_if_false(_new_pid_up, attempts=5, delay=10):
        return None
    return _get_ext_handler_pid()


def verify_agent_exited_due_to_breach(after, previous_pid):
    log.info("** Verifying that the agent exited due to sustained anon memory breach")
    if not retry_if_false(
            lambda: check_log_message(r"sustained anon memory breach", after_timestamp=after),
            delay=15):
        fail("The agent did not log the 'sustained anon memory breach' exit reason")
    log.info("Successfully observed the ExitException reason in the agent log")

    # Log line alone is not enough -- confirm the process actually exited and
    # the daemon relaunched a fresh ext-handler with a different PID.
    log.info("** Verifying that the ext-handler process exited and was relaunched (previous PID=%s)", previous_pid)
    new_pid = _wait_for_ext_handler_pid(exclude_pid=previous_pid)
    if new_pid is None:
        fail("The ext-handler did not restart with a new PID after the sustained-breach exit "
             "(previous PID was {0})".format(previous_pid))
    if previous_pid is not None and new_pid == previous_pid:
        fail("The ext-handler PID did not change after the sustained-breach exit "
             "(still {0}); the process did not actually exit".format(previous_pid))
    log.info("Ext-handler was relaunched: old PID=%s, new PID=%s", previous_pid, new_pid)
    return new_pid


def verify_restart_history_recorded():
    log.info("** Verifying the persisted restart-history file")
    history_path = os.path.join(state_dir.get_state_dir(), HISTORY_FILE_NAME)

    def _exists():
        return os.path.exists(history_path)

    if not retry_if_false(_exists, delay=10):
        fail("Restart history file was not created at {0}".format(history_path))

    with open(history_path) as f:
        data = json.load(f)

    versions = data.get("versions") or {}
    if not versions:
        fail("Restart history file has no 'versions' entries: {0}".format(data))

    # Baseline test: history was deleted in cleanup() of any prior run, and we
    # only trigger a single self-exit here. So the file must contain exactly
    # one version key (the currently-running agent) with exactly one recorded
    # restart entry.
    expected_version = str(CURRENT_VERSION)
    if list(versions.keys()) != [expected_version]:
        fail("Restart history must contain exactly one version entry for {0}; got keys={1}"
             .format(expected_version, list(versions.keys())))

    entries = versions[expected_version]
    if len(entries) != 1:
        fail("Restart history for {0} must contain exactly one recorded restart; got {1} entries: {2}"
             .format(expected_version, len(entries), entries))

    sample = entries[0]
    if "timestamp" not in sample or "anon_bytes" not in sample:
        fail("Restart history entry is missing required fields: {0}".format(sample))
    log.info("Restart history file OK: %s", data)


def _count_log_message(pattern, after_timestamp=None):
    """
    Return the number of records in the full agent log whose message matches
    `pattern` (regex). If `after_timestamp` is given, only records with a
    strictly newer timestamp are counted.
    """
    count = 0
    for record in AgentLog().read():
        if after_timestamp is not None and record.timestamp <= after_timestamp:
            continue
        if re.search(pattern, record.message, flags=re.DOTALL) is not None:
            count += 1
    return count


def verify_exit_message_logged_exactly_once(after):
    """
    The 'sustained anon memory breach ... exiting' log line must appear
    exactly once for this test run. More than one means either the guardrail
    failed to block the second cycle, or the exit path is being taken from
    multiple sites.
    """
    log.info("** Verifying the sustained-breach exit message appears exactly once")
    count = _count_log_message(r"sustained anon memory breach", after_timestamp=after)
    if count != 1:
        fail("Expected exactly one 'sustained anon memory breach' log line, found {0}. "
             "The guardrail must prevent additional self-restart exits within the same run."
             .format(count))
    log.info("Sustained-breach exit message occurred exactly once, as expected")


def verify_guardrail_blocks_second_restart(after):
    """
    With MaxRestartsPerVersion=1 already recorded, the next breach cycle after
    the daemon relaunches the ext-handler must NOT exit again -- instead it must
    log the "self-restart skipped" reason from the guardrail check.
    """
    attempts = (CHILD_LAUNCH_INTERVAL // 60) + 4  # + headroom
    log.info("** Verifying that the guardrail blocks a second self-restart")
    if not retry_if_false(
            lambda: check_log_message(r"self-restart skipped", after_timestamp=after),
            attempts=attempts, delay=60):
        fail("The guardrail did not block the second breach cycle (no 'self-restart skipped' log)")
    log.info("Successfully observed the guardrail 'self-restart skipped' log")


def cleanup():
    log.info("Cleaning up: restoring default waagent.conf values and deleting restart history")
    history_path = os.path.join(state_dir.get_state_dir(), HISTORY_FILE_NAME)
    try:
        if os.path.exists(history_path):
            os.remove(history_path)
    except Exception as e:
        log.warning("Failed to remove %s: %s", history_path, e)
    _apply_conf(_REMOVE_CONF, remove=True)
    _restart_agent()

    _wait_for_agent_startup(datetime.datetime.now(UTC))


def main():
    _skip_if_unsupported()
    skip_if_memory_controller_is_not_enabled()

    try:
        # Baseline: nothing recorded, capture the timestamp so all log assertions
        # ignore any prior test noise.
        start = datetime.datetime.now(UTC)

        _apply_conf(_TEST_CONF)
        _restart_agent()
        _wait_for_agent_startup(start)

        # Capture the ext-handler PID before we trigger the breach so we can
        # confirm the process actually exited (not just that it logged the
        # exit reason).
        pre_breach_pid = _wait_for_ext_handler_pid()
        if pre_breach_pid is None:
            fail("Could not find the ext-handler PID after agent restart")
        log.info("Ext-handler PID before breach: %s", pre_breach_pid)

        verify_consecutive_breach_events(start)
        new_pid = verify_agent_exited_due_to_breach(start, pre_breach_pid)
        verify_restart_history_recorded()

        # From here on, the daemon has relaunched the ext-handler. The new
        # process must observe the guardrail block on its next breach cycle.
        after_first_exit = datetime.datetime.now(UTC)
        verify_guardrail_blocks_second_restart(after_first_exit)

        # After the guardrail has blocked the second cycle, the exit-reason line
        # must still have appeared exactly once across the full run. Anything
        # higher would mean the guardrail failed to short-circuit the exit.
        verify_exit_message_logged_exactly_once(start)

        # Sanity: guardrail path must NOT exit the process, so the PID from
        # after the first exit must still be running.
        current_pid = _get_ext_handler_pid()
        if current_pid != new_pid:
            fail("Ext-handler PID changed unexpectedly after the guardrail block "
                 "(expected {0}, found {1}); the guardrail path should not exit the process"
                 .format(new_pid, current_pid))

    finally:
        cleanup()


run_remote_test(main)
