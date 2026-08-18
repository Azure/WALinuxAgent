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

import json
import os

from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.ga.kernel_event_monitor import MonitorKernelSoftLockup
from tests.lib.tools import AgentTestCase, patch


class TestMonitorKernelSoftLockup(AgentTestCase):
    """
    Tests for MonitorKernelSoftLockup.

    AgentTestCase provides self.tmp_dir and mocks get_state_dir.
    We additionally mock _get_boot_id so tests work on Windows.
    """

    _TEST_BOOT_ID = "abcdef01-2345-6789-abcd-ef0123456789"

    SAMPLE_DMESG_WITH_LOCKUPS = (
        "[    0.000000] Linux version 5.4.0-42-generic\n"
        "[12345.123456] BUG: soft lockup - CPU#0 stuck for 22s! [kworker/0:1:1234]\n"
        "[12345.234567] Modules linked in: module1 module2\n"
        "[12346.345678] BUG: soft lockup - CPU#0 stuck for 23s! [kworker/0:1:1234]\n"
        "[12347.456789] watchdog: BUG: soft lockup - CPU#2 stuck for 25s! [process:5678]\n"
        "[12350.567890] Normal kernel message\n"
        "[12351.678901] BUG: soft lockup - CPU#1 stuck for 21s! [another:9999]\n"
    )

    SAMPLE_DMESG_NO_LOCKUPS = (
        "[    0.000000] Linux version 5.4.0-42-generic\n"
        "[12345.123456] Normal kernel message\n"
        "[12347.345678] eth0: link up\n"
    )

    @staticmethod
    def _get_soft_lockup_events(add_event_mock):
        return [kwargs for _, kwargs in add_event_mock.call_args_list if kwargs.get("op") == WALAEventOperation.KernelSoftLockup]

    @staticmethod
    def _create_monitor(boot_id=None):
        if boot_id is None:
            boot_id = TestMonitorKernelSoftLockup._TEST_BOOT_ID
        with patch.object(MonitorKernelSoftLockup, "_get_boot_id", return_value=boot_id):
            monitor = MonitorKernelSoftLockup()
        return monitor

    @staticmethod
    def _feed_dmesg(monitor, dmesg_output):
        """Feed dmesg lines into the parser (no mocking needed)."""
        for line in dmesg_output.strip().split('\n'):
            monitor._parse_and_aggregate_soft_lockup_events(line)

    @staticmethod
    def _format_dmesg_line(timestamp, message):
        return "[{0:12.6f}] {1}".format(timestamp, message)

    # -- Regex ---------------------------------------------------------------

    def test_soft_lockup_regex_should_match_and_extract_groups(self):
        line = "[12345.123456] BUG: soft lockup - CPU#0 stuck for 22s! [kworker/0:1:1234]"
        match = MonitorKernelSoftLockup._SOFT_LOCKUP_PATTERN.search(line)
        self.assertIsNotNone(match, "Soft lockup regex should match a standard kernel soft lockup line")
        self.assertEqual(match.group('cpu_id'), "0", "CPU id should be extracted from the soft lockup line")
        self.assertEqual(match.group('stuck_seconds'), "22", "Stuck duration should be extracted from the soft lockup line")

    def test_timestamp_regex_should_match_kernel_monotonic_format(self):
        match = MonitorKernelSoftLockup._DMESG_TIMESTAMP_PATTERN.match("[    0.000000] Linux version")
        self.assertIsNotNone(match, "Timestamp regex should match the kernel monotonic timestamp format")
        self.assertEqual(match.group('timestamp'), "0.000000", "Timestamp value should be extracted from the dmesg line")

    # -- Parse and aggregate -------------------------------------------------

    def test_parse_should_detect_and_aggregate_lockup_events(self):
        monitor = self._create_monitor()
        self._feed_dmesg(monitor, self.SAMPLE_DMESG_WITH_LOCKUPS)

        # 4 lockup events across 3 CPUs: CPU#0 (x2), CPU#2 (x1), CPU#1 (x1)
        self.assertEqual(len(monitor._event_aggregates), 3, "Aggregates should contain one entry per affected CPU")
        for key in monitor._event_aggregates:
            self.assertIsInstance(key, int, "Aggregate keys should be integer CPU ids")

        self.assertEqual(monitor._event_aggregates[0]["count"], 2, "CPU#0 should have 2 lockup events aggregated")
        self.assertEqual(monitor._event_aggregates[0]["max_stuck_seconds"], 23,
                         "CPU#0 max stuck seconds should be the highest seen for that CPU")
        self.assertEqual(monitor._event_aggregates[1]["count"], 1, "CPU#1 should have 1 lockup event aggregated")
        self.assertEqual(monitor._event_aggregates[2]["max_stuck_seconds"], 25,
                         "CPU#2 max stuck seconds should be the highest seen for that CPU")
        self.assertAlmostEqual(monitor._last_processed_timestamp, 12351.678901, places=4,
                               msg="Watermark should advance to the latest dmesg timestamp seen")

    def test_parse_should_skip_events_before_watermark(self):
        monitor = self._create_monitor()
        monitor._curr_scan_baseline_timestamp = 12346.0
        self._feed_dmesg(monitor, self.SAMPLE_DMESG_WITH_LOCKUPS)

        self.assertEqual(monitor._event_aggregates[0]["count"], 1,
                         "Only events after the watermark should be aggregated for CPU#0")
        self.assertEqual(monitor._event_aggregates[0]["max_stuck_seconds"], 23,
                         "Max stuck seconds should reflect only post-watermark events for CPU#0")

    def test_parse_should_advance_watermark_even_without_lockups(self):
        monitor = self._create_monitor()
        self._feed_dmesg(monitor, self.SAMPLE_DMESG_NO_LOCKUPS)

        self.assertEqual(len(monitor._event_aggregates), 0,
                         "No aggregates should be produced when dmesg has no lockup lines")
        self.assertAlmostEqual(monitor._last_processed_timestamp, 12347.345678, places=4,
                               msg="Watermark should advance even when no lockup events are present")

    def test_parse_should_capture_bounded_log_context_starting_at_the_lockup_line(self):
        monitor = self._create_monitor()
        context_lines = MonitorKernelSoftLockup._MAX_CONTEXT_LINES_PER_TRACE
        dmesg_lines = [self._format_dmesg_line(200.0, "BUG: soft lockup - CPU#0 stuck for 22s! [test:1]")]
        for index in range(context_lines + 5):
            dmesg_lines.append(self._format_dmesg_line(201.0 + index, "after-{0}".format(index)))

        self._feed_dmesg(monitor, "\n".join(dmesg_lines))

        log_context = monitor._get_kernel_stack_traces()[0]["logLines"]
        self.assertEqual(len(log_context), context_lines,
                         "Log context should be capped at the per-trace line limit")
        self.assertIn("BUG: soft lockup", log_context[0],
                      "Log context should start at the soft lockup line")
        self.assertIn("after-{0}".format(context_lines - 2), log_context[-1],
                      "Log context should include the following dmesg lines up to the limit")

    def test_parse_should_capture_lines_that_share_a_kernel_timestamp(self):
        monitor = self._create_monitor()
        self._feed_dmesg(monitor, "\n".join([
            self._format_dmesg_line(200.0, "BUG: soft lockup - CPU#0 stuck for 22s! [test:1]"),
            self._format_dmesg_line(200.0, "Modules linked in: mod_a mod_b"),
            self._format_dmesg_line(200.0, "RIP: 0010:some_func+0x10/0x20"),
        ]))

        log_context = monitor._get_kernel_stack_traces()[0]["logLines"]
        self.assertEqual(len(log_context), 3,
                 "Context lines sharing a kernel timestamp should all be captured, not skipped")

    def test_parse_should_capture_repeated_lockup_contexts_on_same_cpu_when_slots_are_available(self):
        monitor = self._create_monitor()
        self._feed_dmesg(monitor, "\n".join([
            self._format_dmesg_line(200.0, "BUG: soft lockup - CPU#0 stuck for 22s! [test:1]"),
            self._format_dmesg_line(203.0, "BUG: soft lockup - CPU#0 stuck for 33s! [test:2]"),
        ]))

        traces = monitor._get_kernel_stack_traces()
        self.assertEqual(len(traces), 2,
                 "Repeated lockups on the same CPU should each capture a stack trace while slots remain")
        self.assertIn("stuck for 22s", traces[0]["logLines"][0],
                 "The first trace should start at the first lockup line")
        self.assertIn("stuck for 33s", traces[1]["logLines"][0],
                 "The second trace should start at the second lockup line")

    def test_parse_should_prefer_distinct_cpu_stack_traces_over_duplicate_cpu_candidates(self):
        monitor = self._create_monitor()
        max_traces = MonitorKernelSoftLockup._MAX_STACK_TRACES
        dmesg_lines = [self._format_dmesg_line(200.0 + index, "BUG: soft lockup - CPU#0 stuck for 22s! [test:{0}]".format(index))
                       for index in range(max_traces)]
        dmesg_lines.append(self._format_dmesg_line(300.0, "BUG: soft lockup - CPU#1 stuck for 23s! [distinct]"))
        dmesg_lines.append(self._format_dmesg_line(400.0, "BUG: soft lockup - CPU#0 stuck for 24s! [repeat]"))

        self._feed_dmesg(monitor, "\n".join(dmesg_lines))

        traces = monitor._get_kernel_stack_traces()
        expected_markers = ["[test:{0}]".format(index) for index in range(max_traces - 1)] + ["[distinct]"]
        self.assertEqual([trace["logLines"][0].split()[-1] for trace in traces], expected_markers,
                 "A distinct CPU should evict the newest same-CPU trace, while a CPU already captured is dropped")
        self.assertEqual(monitor._stack_traces_bytes,
                 sum(len(line) for trace in traces for line in trace["logLines"]),
                 "Evicting a trace should release the size budget it was holding")

    def test_parse_should_truncate_rather_than_leave_gaps_when_size_capped(self):
        monitor = self._create_monitor()
        monitor._MAX_STACK_TRACES_BYTES = 1500

        dmesg_lines = [self._format_dmesg_line(200.0, "BUG: soft lockup - CPU#0 stuck for 22s! [test]")]
        timestamp = 201.0
        for index in range(20):
            # Alternate long and short lines: a long line that does not fit must stop the capture
            # instead of being skipped in favour of the short line that follows it.
            dmesg_lines.append(self._format_dmesg_line(
                timestamp, "line-{0} {1}".format(index, "x" * (900 if index % 2 == 0 else 10))))
            timestamp += 1.0

        self._feed_dmesg(monitor, "\n".join(dmesg_lines))

        captured_lines = monitor._get_kernel_stack_traces()[0]["logLines"]
        self.assertLess(len(captured_lines), len(dmesg_lines),
                 "The byte budget should have truncated the trace for this test to be meaningful")
        self.assertEqual(captured_lines, dmesg_lines[:len(captured_lines)],
                 "A size-capped trace should be truncated, never missing lines from the middle")

    def test_parse_should_not_start_a_trace_when_size_budget_is_exhausted(self):
        monitor = self._create_monitor()
        monitor._MAX_STACK_TRACES_BYTES = 1500

        dmesg_lines = [self._format_dmesg_line(200.0, "BUG: soft lockup - CPU#0 stuck for 22s! [test]")]
        timestamp = 201.0
        for _ in range(20):
            dmesg_lines.append(self._format_dmesg_line(timestamp, "x" * 300))
            timestamp += 1.0
        dmesg_lines.append(self._format_dmesg_line(
            timestamp, "BUG: soft lockup - CPU#1 stuck for 22s! [test] {0}".format("y" * 300)))

        self._feed_dmesg(monitor, "\n".join(dmesg_lines))

        self.assertEqual(len(monitor._get_kernel_stack_traces()), 1,
                 "A lockup on a new CPU should not start a trace once the size budget is exhausted")

    def test_parse_should_not_evict_an_existing_trace_when_new_trace_exceeds_size_budget(self):
        monitor = self._create_monitor()
        monitor._MAX_STACK_TRACES_BYTES = 1500
        max_traces = MonitorKernelSoftLockup._MAX_STACK_TRACES

        dmesg_lines = [self._format_dmesg_line(200.0 + index, "BUG: soft lockup - CPU#0 stuck for 22s! [test]")
                       for index in range(max_traces)]
        dmesg_lines.append(self._format_dmesg_line(
            300.0, "BUG: soft lockup - CPU#9 stuck for 22s! [distinct] {0}".format("y" * 1350)))

        self._feed_dmesg(monitor, "\n".join(dmesg_lines))

        traces = monitor._get_kernel_stack_traces()
        self.assertEqual(len(traces), max_traces,
                 "The trace list should be full for this test to be meaningful")
        self.assertNotIn(9, [trace["cpuId"] for trace in traces],
                 "A distinct CPU should not evict a trace when the freed budget still cannot fit its line")
        self.assertLessEqual(monitor._stack_traces_bytes, monitor._MAX_STACK_TRACES_BYTES,
                 "Evicting to make room should never push the captured size over the budget")

    # -- Report events -------------------------------------------------------

    def test_report_should_send_correct_telemetry_and_clear_aggregates(self):
        monitor = self._create_monitor()
        monitor._event_aggregates = {
            0: {"count": 2, "max_stuck_seconds": 23, "last_timestamp": 12346.345678},
            1: {"count": 1, "max_stuck_seconds": 21, "last_timestamp": 12351.678901},
        }

        with patch("azurelinuxagent.ga.kernel_event_monitor.add_event") as mock_add_event:
            monitor._report_events()

            events = self._get_soft_lockup_events(mock_add_event)
            self.assertEqual(len(events), 1, "Exactly one KernelSoftLockup telemetry event should be sent")
            call_kwargs = events[0]
            self.assertEqual(call_kwargs["op"], WALAEventOperation.KernelSoftLockup,
                             "Telemetry event op should be KernelSoftLockup")
            self.assertTrue(call_kwargs["is_success"], "Telemetry event should be marked as success")
            self.assertFalse(call_kwargs["log_event"], "Telemetry event should not be written to the agent log")

            payload = json.loads(call_kwargs["message"])
            self.assertEqual(payload["totalSoftLockups"], 3,
                             "Payload totalSoftLockups should be the sum of per-CPU counts")
            self.assertEqual(payload["affectedCpuCount"], 2,
                             "Payload affectedCpuCount should be the number of CPUs with lockups")
            self.assertEqual(payload["cpuDetails"][0]["cpuId"], 0,
                             "cpuDetails should be sorted by cpuId ascending; CPU#0 should appear first")
            self.assertEqual(payload["cpuDetails"][0]["count"], 2,
                             "First cpuDetails count should match the aggregated count for CPU#0")
            self.assertEqual(payload["cpuDetails"][0]["maxStuckTimeSec"], 23,
                             "First cpuDetails maxStuckTimeSec should match the aggregated max for CPU#0")
            self.assertNotIn("logLines", payload["cpuDetails"][0],
                             "Stack traces should be reported separately from aggregate CPU details")

        self.assertEqual(len(monitor._event_aggregates), 0, "Aggregates should be cleared after reporting")

    def test_report_should_include_kernel_stack_traces_separately_when_available(self):
        monitor = self._create_monitor()
        lockup_line = self._format_dmesg_line(12345.0, "BUG: soft lockup - CPU#0 stuck for 22s!")
        self._feed_dmesg(monitor, lockup_line)

        with patch("azurelinuxagent.ga.kernel_event_monitor.add_event") as mock_add_event:
            monitor._report_events()

        payload = json.loads(self._get_soft_lockup_events(mock_add_event)[0]["message"])
        self.assertNotIn("logLines", payload["cpuDetails"][0],
                         "Aggregate CPU details should not include stack trace context")
        self.assertEqual(payload["kernelStackTraces"], [{"cpuId": 0, "logLines": [lockup_line]}],
                         "Reported stack traces should carry the cpu id and captured log lines, and nothing else")

    def test_report_should_clear_stack_traces_and_release_size_budget(self):
        monitor = self._create_monitor()
        self._feed_dmesg(monitor, self.SAMPLE_DMESG_WITH_LOCKUPS)
        self.assertGreater(monitor._stack_traces_bytes, 0,
                 "The sample dmesg should have captured stack traces for this test to be meaningful")

        with patch("azurelinuxagent.ga.kernel_event_monitor.add_event"):
            monitor._report_events()

        self.assertEqual(monitor._get_kernel_stack_traces(), [],
                         "Stack traces should be cleared after reporting so they are not sent again")
        self.assertEqual(monitor._stack_traces_bytes, 0,
                         "The size budget should be released after reporting, otherwise it shrinks every cycle")

    def test_report_should_clear_state_even_on_failure(self):
        monitor = self._create_monitor()
        self._feed_dmesg(monitor, self.SAMPLE_DMESG_WITH_LOCKUPS)

        with patch("azurelinuxagent.ga.kernel_event_monitor.add_event", side_effect=Exception("send failed")):
            monitor._report_events()

        self.assertEqual(len(monitor._event_aggregates), 0,
                         "Aggregates should be cleared even when telemetry sending raises an exception")
        self.assertEqual(len(monitor._stack_traces), 0,
                         "Stack traces should be cleared even when telemetry sending raises an exception")
        self.assertEqual(monitor._stack_traces_bytes, 0,
                         "The size budget should be released even when telemetry sending raises an exception")

    def test_report_should_not_send_if_no_events(self):
        monitor = self._create_monitor()
        with patch("azurelinuxagent.ga.kernel_event_monitor.add_event") as mock_add_event:
            monitor._report_events()
            mock_add_event.assert_not_called()

    # -- State persistence ---------------------------------------------------

    def test_save_and_get_saved_timestamp_should_preserve_watermark(self):
        monitor = self._create_monitor()
        self.assertEqual(monitor._last_processed_timestamp, 0.0,
                         "Watermark should default to 0.0 when no state file exists")

        monitor._last_processed_timestamp = 12345.678
        monitor._save_state()

        monitor2 = self._create_monitor()
        self.assertEqual(monitor2._last_processed_timestamp, 12345.678,
                         "Watermark should be restored from the saved state file")

    def test_get_saved_timestamp_should_reset_watermark_on_boot_id_change(self):
        monitor = self._create_monitor(boot_id="old-boot-id-0000-0000-000000000000")
        monitor._last_processed_timestamp = 99999.0
        monitor._save_state()

        monitor2 = self._create_monitor(boot_id="new-boot-id-1111-1111-111111111111")
        self.assertEqual(monitor2._last_processed_timestamp, 0.0,
                         "Watermark should reset to 0.0 when the boot id changes")

    def test_get_saved_timestamp_should_reset_watermark_when_boot_id_is_unknown(self):
        """Empty boot_id in saved state should reset watermark."""
        monitor = self._create_monitor()
        state = {"last_timestamp": 99999.0, "boot_id": ""}
        with open(monitor._state_file_path, 'w') as f:
            json.dump(state, f)

        monitor2 = self._create_monitor()
        self.assertEqual(monitor2._last_processed_timestamp, 0.0,
                         "Watermark should reset to 0.0 when the saved boot id is empty/unknown")

    def test_get_saved_timestamp_should_handle_corrupt_state_file(self):
        monitor = self._create_monitor()
        with open(monitor._state_file_path, 'w') as f:
            f.write("{invalid json")

        monitor2 = self._create_monitor()
        self.assertEqual(monitor2._last_processed_timestamp, 0.0,
                         "Watermark should reset to 0.0 when the saved state file is corrupt")

    # -- dmesg read ------------------------------------------------------------

    def test_read_and_parse_dmesg_should_parse_on_success(self):
        monitor = self._create_monitor()
        dmesg_lines = [
            "[12345.123456] BUG: soft lockup - CPU#0 stuck for 22s! [kworker/0:1:1234]"
        ]

        def fake_run_command_get_output(_command, on_output_line):
            for line in dmesg_lines:
                on_output_line(line)

        with patch("azurelinuxagent.ga.kernel_event_monitor.run_command_get_output", side_effect=fake_run_command_get_output):
            monitor._read_and_parse_dmesg()
            self.assertEqual(monitor._event_aggregates[0]["count"], 1,
                             "_read_and_parse_dmesg should aggregate the lockup line returned by dmesg")

    def test_read_and_parse_dmesg_should_not_crash_on_failure(self):
        monitor = self._create_monitor()
        with patch("azurelinuxagent.ga.kernel_event_monitor.run_command_get_output", side_effect=Exception("command failed")):
            monitor._read_and_parse_dmesg()
        self.assertEqual(len(monitor._event_aggregates), 0,
                         "Aggregates should remain empty when dmesg invocation raises an exception")

    # -- Full operation ------------------------------------------------------

    def test_operation_should_parse_and_report(self):
        monitor = self._create_monitor()
        with patch.object(monitor, "_read_and_parse_dmesg",
                          side_effect=lambda: self._feed_dmesg(monitor, self.SAMPLE_DMESG_WITH_LOCKUPS)):
            with patch("azurelinuxagent.ga.kernel_event_monitor.add_event") as mock_add_event:
                monitor._operation()
                events = self._get_soft_lockup_events(mock_add_event)
                self.assertEqual(len(events), 1,
                                 "Exactly one KernelSoftLockup telemetry event should be sent per operation")
                payload = json.loads(events[0]["message"])
                self.assertEqual(payload["totalSoftLockups"], 4,
                                 "Payload totalSoftLockups should reflect all lockups in the dmesg sample")
                self.assertEqual(payload["affectedCpuCount"], 3,
                                 "Payload affectedCpuCount should reflect all distinct CPUs in the dmesg sample")

    def test_operation_watermark_persists_across_runs(self):
        """Second run with same dmesg should not report -- watermark filters old events."""
        monitor = self._create_monitor()
        feed = lambda: self._feed_dmesg(monitor, self.SAMPLE_DMESG_WITH_LOCKUPS)
        with patch.object(monitor, "_read_and_parse_dmesg", side_effect=feed):
            with patch("azurelinuxagent.ga.kernel_event_monitor.add_event"):
                monitor._operation()

        with patch.object(monitor, "_read_and_parse_dmesg", side_effect=feed):
            with patch("azurelinuxagent.ga.kernel_event_monitor.add_event") as mock_add_event:
                monitor._operation()
                self.assertEqual(len(self._get_soft_lockup_events(mock_add_event)), 0,
                                 "Subsequent runs with the same dmesg should not re-report previously seen events")

    # -- _is_dmesg_available -------------------------------------------------

    def test_is_dmesg_available_should_return_false_when_dmesg_not_found(self):
        with patch("azurelinuxagent.ga.kernel_event_monitor.run_command", side_effect=Exception("not found")):
            self.assertFalse(MonitorKernelSoftLockup._is_dmesg_available(),
                             "_is_dmesg_available should return False when invoking dmesg fails")

    # -- _get_boot_id --------------------------------------------------------

    def test_get_boot_id_should_return_unknown_on_failure(self):
        with patch.object(MonitorKernelSoftLockup, "_BOOT_ID_PATH", "/nonexistent/boot_id"):
            self.assertEqual(MonitorKernelSoftLockup._get_boot_id(), MonitorKernelSoftLockup._UNKNOWN_BOOT_ID,
                             "_get_boot_id should return the unknown sentinel when the boot id file cannot be read")

    # -- _save_state failure -------------------------------------------------

    def test_save_state_should_log_warning_on_failure(self):
        monitor = self._create_monitor()
        monitor._state_file_path = os.path.join(self.tmp_dir, "no", "such", "dir", "state.json")
        with patch("azurelinuxagent.ga.kernel_event_monitor.logger.warn") as mock_warn:
            monitor._save_state()
            self.assertIn("Failed to save state", mock_warn.call_args[0][0],
                          "_save_state should log a warning containing 'Failed to save state' when writing fails")

    # -- _parse_and_aggregate_soft_lockup_events edge cases ------------------

    def test_parse_should_skip_lines_without_timestamp(self):
        monitor = self._create_monitor()
        monitor._parse_and_aggregate_soft_lockup_events("no timestamp here")
        self.assertEqual(len(monitor._event_aggregates), 0,
                         "Lines without a kernel timestamp should be skipped without aggregating")
