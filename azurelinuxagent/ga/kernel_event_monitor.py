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
# Requires Python 2.6+ and Openssl 1.0+
#

"""
This module monitors kernel events (CPU soft lockups) by parsing dmesg output
and reports them via telemetry. This helps Azure detect and diagnose VM health issues.

CPU soft lockups occur when a CPU is stuck in kernel code for more than the configured
threshold (typically 20+ seconds), indicating potential system issues.

Telemetry is sent here on a best-effort basis. Failure to send does not affect any
agent functionality.
"""

import datetime
import json
import os
import re

from azurelinuxagent.ga import state_dir
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.shellutil import run_command, run_command_get_output
from azurelinuxagent.common.version import AGENT_NAME
from azurelinuxagent.ga.periodic_operation import PeriodicOperation


class MonitorKernelSoftLockup(PeriodicOperation):
    """
    Periodic operation to monitor dmesg for CPU soft lockup events.
    
    CPU soft lockup events indicate that a CPU core has been stuck in kernel code 
    for an extended period (typically 20+ seconds).
    
    This class parses dmesg output, aggregates events, and sends 
    summarized telemetry to avoid overwhelming the telemetry pipeline.
    """

    # Regex to detect kernel soft lockup events and extract CPU ID + stuck duration.
    #
    # Matches the message printed by kernel/watchdog.c:
    #   "BUG: soft lockup - CPU#<id> stuck for <seconds>s! [<process>:<pid>]"
    #
    # The prefix before "BUG:" varies by kernel version (e.g., "watchdog:", "NMI watchdog:")
    # but re.search() handles that, no prefix matching needed.
    _SOFT_LOCKUP_PATTERN = re.compile(
        r'BUG:\s*soft lockup\s*-\s*CPU#(?P<cpu_id>\d+)\s+stuck for (?P<stuck_seconds>\d+)s',
        re.IGNORECASE
    )
    
    # Pattern to extract the kernel monotonic timestamp from a dmesg line.
    #
    # Kernel printk format: "[%5lu.%06lu]" e.g. "[   12.345678]", "[8640000.123456]"
    # Seconds are space-padded, microseconds are zero-padded to 6 digits.
    # Matches raw dmesg output only (not dmesg -T or syslog formats).
    _DMESG_TIMESTAMP_PATTERN = re.compile(
        r'\[\s*(?P<timestamp>\d+\.\d+)\]'
    )
    
    # File to persist the last processed dmesg timestamp across agent restarts
    _STATE_FILE_NAME = "kernel_soft_lockup_state.json"

    # Path to the kernel boot ID, a unique UUID generated on each boot
    _BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"

    # Returned when boot_id cannot be read; triggers a watermark reset
    _UNKNOWN_BOOT_ID = ""

    # Default timestamp watermark
    _DEFAULT_TIMESTAMP = 0.0

    # Maximum number of affected CPUs to include in telemetry details; if exceeded, details will be truncated with a flag.
    _MAX_CPU_DETAILS = 50

    # Attach soft lockup logs for a limited number of occurrences, preferring distinct CPUs
    # but falling back to repeat CPUs when fewer are available.
    _MAX_CONTEXT_LINES_PER_TRACE = 50
    _MAX_STACK_TRACES = 4

    # Combined budget for all captured traces, well under the 64 KB telemetry event limit; a single
    # dmesg line can be long ("Modules linked in:" runs into the hundreds of characters).
    _MAX_STACK_TRACES_BYTES = 32 * 1024

    _PERIOD_SECONDS = 43200  # 12 hours

    @staticmethod
    def _is_dmesg_available():
        """Check if dmesg is available on this system."""
        try:
            run_command(['which', 'dmesg'])
            return True
        except Exception:
            return False

    def __init__(self):
        period = datetime.timedelta(seconds=self._PERIOD_SECONDS)
        super(MonitorKernelSoftLockup, self).__init__(period)
        self._boot_id = self._get_boot_id()
        self._event_aggregates = {}
        self._stack_traces = []
        self._stack_traces_bytes = 0
        self._state_file_path = os.path.join(state_dir.get_state_dir(), self._STATE_FILE_NAME)
        self._last_processed_timestamp = self._get_saved_timestamp(self._boot_id, self._state_file_path)
        self._curr_scan_baseline_timestamp = self._last_processed_timestamp
        logger.info("KernelSoftLockup: Initialized - period={0}, watermark={1}, boot_id={2}".format(
            period, self._last_processed_timestamp, self._boot_id))

    @staticmethod
    def _get_boot_id():
        """
        Read the current boot ID from /proc/sys/kernel/random/boot_id.
        This is a unique UUID generated by the kernel on each boot.
        Returns _UNKNOWN_BOOT_ID on failure (will cause a watermark reset).
        """
        try:
            with open(MonitorKernelSoftLockup._BOOT_ID_PATH, 'r') as f:
                return f.read().strip()
        except Exception as e:
            logger.warn("KernelSoftLockup: Failed to read boot_id: {0}".format(ustr(e)))
            return MonitorKernelSoftLockup._UNKNOWN_BOOT_ID

    @staticmethod
    def _get_saved_timestamp(boot_id, state_file_path):
        """
        Return the persisted timestamp watermark from the state file.
        Returns _DEFAULT_TIMESTAMP (i.e. rescan from the beginning) if the state file is missing,
        the boot ID changed (reboot), or the state cannot be read.
        """
        try:
            if not os.path.exists(state_file_path):
                return MonitorKernelSoftLockup._DEFAULT_TIMESTAMP

            with open(state_file_path, 'r') as f:
                state = json.load(f)

            saved_boot_id = state.get("boot_id", MonitorKernelSoftLockup._UNKNOWN_BOOT_ID)

            # Reset if either boot ID is unknown
            if saved_boot_id == MonitorKernelSoftLockup._UNKNOWN_BOOT_ID or boot_id == MonitorKernelSoftLockup._UNKNOWN_BOOT_ID:
                logger.info("KernelSoftLockup: Unable to read Boot ID (saved={0}, current={1}). "
                            "Resetting timestamp watermark.".format(
                                ustr(saved_boot_id), ustr(boot_id)))
                return MonitorKernelSoftLockup._DEFAULT_TIMESTAMP

            # Dmesg timestamps are monotonic (seconds since boot) and reset to 0 on reboot.
            # A stale watermark from a previous boot would skip all new events, so reset it.
            if saved_boot_id != boot_id:
                logger.info("KernelSoftLockup: Boot ID changed (saved={0}, current={1}). "
                            "Resetting timestamp watermark due to reboot.".format(
                                ustr(saved_boot_id), ustr(boot_id)))
                return MonitorKernelSoftLockup._DEFAULT_TIMESTAMP

            return float(state.get("last_timestamp", MonitorKernelSoftLockup._DEFAULT_TIMESTAMP))
        except Exception as e:
            logger.warn("KernelSoftLockup: Failed to load state: {0}".format(ustr(e)))
            return MonitorKernelSoftLockup._DEFAULT_TIMESTAMP

    def _save_state(self):
        """Persist state to disk including boot_id to detect reboots."""
        try:
            state = {
                "last_timestamp": self._last_processed_timestamp,
                "boot_id": self._boot_id
            }
            tmp_path = self._state_file_path + ".tmp"
            with open(tmp_path, 'w') as f:
                json.dump(state, f)
            os.rename(tmp_path, self._state_file_path)
        except Exception as e:
            logger.warn("KernelSoftLockup: Failed to save state: {0}".format(ustr(e)))

    def _read_and_parse_dmesg(self):
        """
        Stream dmesg output line by line and parse soft lockup events.
        """
        try:
            run_command_get_output(['dmesg'], on_output_line=self._parse_and_aggregate_soft_lockup_events)
        except Exception as e:
            logger.warn("KernelSoftLockup: Failed to read dmesg output: {0}".format(ustr(e)))

    def _append_line_to_stack_traces(self, line):
        for trace in self._stack_traces:
            if trace["closed"] or len(trace["logLines"]) >= self._MAX_CONTEXT_LINES_PER_TRACE:
                continue
            # Out of byte budget: end this trace instead of only skipping the line.
            if self._stack_traces_bytes + len(line) > self._MAX_STACK_TRACES_BYTES:
                trace["closed"] = True
                continue
            trace["logLines"].append(line)
            self._stack_traces_bytes += len(line)

    def _index_of_last_repeat_cpu_trace(self):
        # Index of the last captured trace whose CPU already appears earlier in the list,
        # or None when every captured trace is for a distinct CPU.
        seen_cpu_ids = set()
        last_repeat_index = None
        for index, trace in enumerate(self._stack_traces):
            if trace["cpuId"] in seen_cpu_ids:
                last_repeat_index = index
            seen_cpu_ids.add(trace["cpuId"])
        return last_repeat_index

    def _start_log_context_capture(self, cpu_id, line):
        # Keep up to _MAX_STACK_TRACES traces, preferring distinct CPUs. When full, a new distinct CPU
        # evicts the last repeat-CPU trace (if one exists); otherwise the new occurrence is dropped.
        if len(self._stack_traces) >= self._MAX_STACK_TRACES:
            if cpu_id in [trace["cpuId"] for trace in self._stack_traces]:
                return
            repeat_index = self._index_of_last_repeat_cpu_trace()
            if repeat_index is None:
                return
            # Budget freed by the eviction is available to the new trace, so check it before evicting.
            reclaimed_bytes = sum(len(evicted_line) for evicted_line in self._stack_traces[repeat_index]["logLines"])
            if self._stack_traces_bytes - reclaimed_bytes + len(line) > self._MAX_STACK_TRACES_BYTES:
                return
            self._stack_traces.pop(repeat_index)
            self._stack_traces_bytes -= reclaimed_bytes
        elif self._stack_traces_bytes + len(line) > self._MAX_STACK_TRACES_BYTES:
            return

        self._stack_traces.append({
            "cpuId": cpu_id,
            "logLines": [line],
            "closed": False
        })
        self._stack_traces_bytes += len(line)

    def _get_kernel_stack_traces(self):
        return [{
            "cpuId": trace["cpuId"],
            "logLines": trace["logLines"]
        } for trace in self._stack_traces]

    def _parse_and_aggregate_soft_lockup_events(self, line):
        """
        Parse a single dmesg line for CPU soft lockup events,
        aggregate events by CPU ID, and advance the watermark.
        """
        timestamp_match = self._DMESG_TIMESTAMP_PATTERN.match(line)
        if timestamp_match is None:
            return

        kernel_timestamp = float(timestamp_match.group('timestamp'))
        if kernel_timestamp <= self._curr_scan_baseline_timestamp:
            return

        self._last_processed_timestamp = kernel_timestamp
        self._append_line_to_stack_traces(line)
        lockup_match = self._SOFT_LOCKUP_PATTERN.search(line)
        if lockup_match is None:
            return

        cpu_id = int(lockup_match.group('cpu_id'))
        stuck_seconds = int(lockup_match.group('stuck_seconds'))

        if cpu_id not in self._event_aggregates:
            self._event_aggregates[cpu_id] = {
                "count": 0,
                "max_stuck_seconds": 0
            }

        agg = self._event_aggregates[cpu_id]
        agg["count"] += 1
        agg["max_stuck_seconds"] = max(agg["max_stuck_seconds"], stuck_seconds)
        agg["last_timestamp"] = kernel_timestamp
        self._start_log_context_capture(cpu_id, line)

    def _report_events(self):
        """Report aggregated soft lockup events via telemetry."""
        if len(self._event_aggregates) == 0:
            return

        try:
            per_cpu = []
            total_events = 0
            for cpu_id, agg in sorted(self._event_aggregates.items()):
                total_events += agg["count"]
                per_cpu.append({
                    "cpuId": cpu_id,
                    "count": agg["count"],
                    "maxStuckTimeSec": agg["max_stuck_seconds"],
                    "lastKernelTimestamp": agg["last_timestamp"]
                })
            affected_cpus = len(per_cpu)
            
            payload = {
                "totalSoftLockups": total_events,
                "affectedCpuCount": affected_cpus,
                "cpuDetailsTruncated": affected_cpus > self._MAX_CPU_DETAILS,
                "cpuDetails": per_cpu[:self._MAX_CPU_DETAILS],
                "kernelStackTraces": self._get_kernel_stack_traces()
            }
            message = json.dumps(payload, separators=(',', ':'))

            logger.warn("KernelSoftLockup: {0} soft lockup(s) on {1} CPU(s)".format(
                total_events, affected_cpus))

            add_event(
                AGENT_NAME,
                op=WALAEventOperation.KernelSoftLockup,
                is_success=True,
                message=message,
                log_event=False
            )
        except Exception as e:
            logger.warn("KernelSoftLockup: Failed to send telemetry event: {0}".format(ustr(e)))
        finally:
            self._event_aggregates = {}
            self._stack_traces = []
            self._stack_traces_bytes = 0

    def _operation(self):
        """
        Main operation: parse dmesg, aggregate new soft lockup events, and report.
        Exceptions are caught and logged by the base class (PeriodicOperation.run).
        """
        # Use the previous scan's watermark as a fixed baseline for this scan: each dmesg line is compared
        # against this baseline rather than the watermark that advances as lines are processed. This ensures
        # consecutive lines sharing the same kernel timestamp are all captured (not just the first), while the
        # watermark still advances during the scan and is persisted below to skip these lines on the next scan.
        self._curr_scan_baseline_timestamp = self._last_processed_timestamp
        self._read_and_parse_dmesg()
        self._report_events()

        if self._last_processed_timestamp != self._curr_scan_baseline_timestamp:
            self._save_state()
