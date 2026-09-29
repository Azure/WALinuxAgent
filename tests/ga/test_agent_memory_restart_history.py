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

import json
import os
from datetime import datetime, timedelta

from azurelinuxagent.common.future import UTC
from azurelinuxagent.common.utils import timeutil
from azurelinuxagent.ga.agent_memory_restart_history import (
    AgentMemoryRestartHistory,
    HISTORY_FILE_NAME,
    SCHEMA_VERSION,
    MAX_VERSIONS_RETAINED,
)
from tests.lib.tools import AgentTestCase, patch


VERSION = "2.13.1.1"
OTHER_VERSION = "2.13.1.2"


class AgentRestartHistoryTestCase(AgentTestCase):
    """
    Unit tests for azurelinuxagent.ga.agent_memory_restart_history.AgentMemoryRestartHistory.
    """

    def setUp(self):
        AgentTestCase.setUp(self)
        self.history_path = os.path.join(self.tmp_dir, HISTORY_FILE_NAME)

    def _new(self):
        return AgentMemoryRestartHistory(path=self.history_path)

    @staticmethod
    def _ts(dt):
        return timeutil.create_utc_timestamp(dt)

    def _seed(self, entries_by_version, schema_version=SCHEMA_VERSION):
        """
        Write a history file with the given {version: [(datetime, anon_bytes), ...]}
        contents so we can exercise the load path.
        """
        versions = {}
        for ver, entries in entries_by_version.items():
            versions[ver] = [
                {"timestamp": self._ts(dt), "anon_bytes": anon}
                for dt, anon in entries
            ]
        with open(self.history_path, "w") as f:
            json.dump({"schema_version": schema_version, "versions": versions}, f)

    def test_missing_file_starts_empty(self):
        hist = self._new()
        self.assertEqual([], hist.get_version_restarts(VERSION))
        self.assertIsNone(hist.get_version_latest_restart_time(VERSION))
        self.assertFalse(os.path.exists(self.history_path),
                         "Just constructing the object must not create the file")

    def test_load_reads_existing_entries(self):
        now = datetime.now(UTC)
        self._seed({VERSION: [(now - timedelta(days=1), 400 * 1024 * 1024)]})
        hist = self._new()
        entries = hist.get_version_restarts(VERSION)
        self.assertEqual(1, len(entries))
        self.assertEqual(400 * 1024 * 1024, entries[0]["anon_bytes"])

    def test_corrupt_file_is_backed_up_and_state_is_empty(self):
        with open(self.history_path, "w") as f:
            f.write("{not valid json")
        hist = self._new()
        self.assertEqual([], hist.get_version_restarts(VERSION),
                         "State must fall back to empty when the file is corrupt")
        self.assertTrue(os.path.exists(self.history_path + ".corrupt"),
                        "The corrupt file must be renamed with a .corrupt suffix")

    def test_load_ignores_file_with_unexpected_shape(self):
        # A JSON file that parses but does not match the schema is treated as empty.
        with open(self.history_path, "w") as f:
            json.dump(["not", "a", "dict"], f)
        hist = self._new()
        self.assertEqual([], hist.get_version_restarts(VERSION))

    def test_load_ignores_versions_key_of_wrong_type(self):
        with open(self.history_path, "w") as f:
            json.dump({"schema_version": SCHEMA_VERSION, "versions": ["oops"]}, f)
        hist = self._new()
        self.assertEqual([], hist.get_version_restarts(VERSION))

    def test_record_restart_creates_file_with_expected_schema(self):
        hist = self._new()
        hist.record_restart(VERSION, 314572800)

        self.assertTrue(os.path.exists(self.history_path))
        with open(self.history_path) as f:
            data = json.load(f)

        self.assertEqual(SCHEMA_VERSION, data["schema_version"])
        self.assertIn(VERSION, data["versions"])
        entry = data["versions"][VERSION][0]
        self.assertEqual(314572800, entry["anon_bytes"])
        # Must match timeutil.create_utc_timestamp format exactly: ends with 'Z'
        self.assertTrue(entry["timestamp"].endswith("Z"))
        # And be parseable back.
        parsed = datetime.strptime(entry["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
        self.assertIsNotNone(parsed)

    def test_record_restart_appends_within_same_version(self):
        hist = self._new()
        hist.record_restart(VERSION, 1)
        hist.record_restart(VERSION, 2)
        entries = self._new().get_version_restarts(VERSION)
        self.assertEqual([1, 2], [e["anon_bytes"] for e in entries])

    def test_record_restart_isolates_versions(self):
        hist = self._new()
        hist.record_restart(VERSION, 1)
        hist.record_restart(OTHER_VERSION, 2)
        reloaded = self._new()
        self.assertEqual(1, len(reloaded.get_version_restarts(VERSION)))
        self.assertEqual(1, len(reloaded.get_version_restarts(OTHER_VERSION)))

    def test_record_restart_accepts_non_string_version(self):
        # AgentMemoryRestartHistory keys by str(version) so callers can pass FlexibleVersion.
        hist = self._new()
        hist.record_restart(2, 1)
        self.assertEqual(1, len(self._new().get_version_restarts("2")))

    def test_record_restart_coerces_anon_bytes_to_int(self):
        hist = self._new()
        hist.record_restart(VERSION, 3.7)
        self.assertEqual(3, self._new().get_version_restarts(VERSION)[0]["anon_bytes"])

    def test_history_survives_across_instances(self):
        first = self._new()
        first.record_restart(VERSION, 500)
        second = self._new()
        self.assertEqual([500], [e["anon_bytes"] for e in second.get_version_restarts(VERSION)])

    def test_get_version_latest_restart_time_none_when_no_entries(self):
        self.assertIsNone(self._new().get_version_latest_restart_time(VERSION))

    def test_get_version_latest_restart_time_returns_latest(self):
        old = datetime.now(UTC) - timedelta(days=10)
        mid = datetime.now(UTC) - timedelta(days=5)
        new = datetime.now(UTC) - timedelta(days=1)
        # Intentionally seed out of chronological order to verify max() logic.
        self._seed({VERSION: [(mid, 1), (old, 2), (new, 3)]})
        last = self._new().get_version_latest_restart_time(VERSION)
        self.assertIsNotNone(last)
        self.assertEqual(new, last)

    def test_get_version_latest_restart_time_raises_when_timestamps_unparseable(self):
        # An unparseable timestamp must propagate rather than silently return
        # None; otherwise a corrupt history could allow unbounded self-restarts.
        with open(self.history_path, "w") as f:
            json.dump({"schema_version": SCHEMA_VERSION,
                       "versions": {VERSION: [{"timestamp": "not-a-time", "anon_bytes": 1}]}}, f)
        self.assertRaises(ValueError, self._new().get_version_latest_restart_time, VERSION)

    def test_can_restart_allowed_when_history_empty(self):
        allowed, reason = self._new().version_can_restart(VERSION, max_per_version=5,
                                                  min_interval_seconds=3 * 86400)
        self.assertTrue(allowed)
        self.assertEqual("allowed", reason)

    def test_can_restart_blocked_when_max_per_version_reached(self):
        long_ago = datetime.now(UTC) - timedelta(days=30)
        self._seed({VERSION: [(long_ago, 1)] * 5})
        allowed, reason = self._new().version_can_restart(VERSION, max_per_version=5,
                                                  min_interval_seconds=3 * 86400)
        self.assertFalse(allowed)
        self.assertIn("max restarts", reason)

    def test_can_restart_blocked_within_min_interval(self):
        recent = datetime.now(UTC) - timedelta(hours=1)
        self._seed({VERSION: [(recent, 1)]})
        allowed, reason = self._new().version_can_restart(VERSION, max_per_version=5,
                                                  min_interval_seconds=3 * 86400)
        self.assertFalse(allowed)
        self.assertIn("within min interval", reason)

    def test_can_restart_allowed_after_min_interval(self):
        far_past = datetime.now(UTC) - timedelta(days=5)
        self._seed({VERSION: [(far_past, 1)]})
        allowed, _ = self._new().version_can_restart(VERSION, max_per_version=5,
                                             min_interval_seconds=3 * 86400)
        self.assertTrue(allowed)

    def test_can_restart_treats_negative_delta_as_zero(self):
        # A "future" timestamp (clock rolled back) must NOT bypass the min-interval.
        future = datetime.now(UTC) + timedelta(days=1)
        self._seed({VERSION: [(future, 1)]})
        allowed, reason = self._new().version_can_restart(VERSION, max_per_version=5,
                                                  min_interval_seconds=60)
        self.assertFalse(allowed,
                         "A future last-restart timestamp must not be treated as 'long ago'")
        self.assertIn("within min interval", reason)

    def test_can_restart_guardrails_are_per_version(self):
        # Fill up VERSION but leave OTHER_VERSION empty. OTHER_VERSION must still be allowed.
        long_ago = datetime.now(UTC) - timedelta(days=30)
        self._seed({VERSION: [(long_ago, 1)] * 5})
        allowed, _ = self._new().version_can_restart(OTHER_VERSION, max_per_version=5,
                                             min_interval_seconds=3 * 86400)
        self.assertTrue(allowed)

    def test_record_restart_prunes_to_max_versions_retained(self):
        # Pre-seed with more than MAX_VERSIONS_RETAINED versions, each with a
        # distinct last-restart timestamp so the pruning order is deterministic.
        now = datetime.now(UTC)
        seeded = {
            "2.10.0.0": [(now - timedelta(days=40), 1)],
            "2.11.0.0": [(now - timedelta(days=30), 1)],
            "2.12.0.0": [(now - timedelta(days=20), 1)],
            "2.13.0.0": [(now - timedelta(days=10), 1)],
        }
        self._seed(seeded)
        hist = self._new()
        # Recording a new version stamps it with 'now', so it will be retained
        # along with the two most-recently-active seeded versions.
        hist.record_restart("2.14.0.0", 42)

        kept = set(self._new()._data["versions"].keys())
        self.assertEqual(MAX_VERSIONS_RETAINED, len(kept),
                         "History must be pruned to exactly MAX_VERSIONS_RETAINED entries")
        self.assertEqual(set(["2.14.0.0", "2.13.0.0", "2.12.0.0"]), kept,
                         "The N versions with the most recent restarts must be retained")

    def test_record_restart_does_not_prune_when_under_limit(self):
        old_ts = datetime.now(UTC) - timedelta(days=100)
        self._seed({"2.10.0.0": [(old_ts, 1)]})
        hist = self._new()
        hist.record_restart("2.11.0.0", 1)
        hist.record_restart("2.12.0.0", 1)
        kept = set(self._new()._data["versions"].keys())
        self.assertEqual(set(["2.10.0.0", "2.11.0.0", "2.12.0.0"]), kept,
                         "Nothing should be pruned when count <= MAX_VERSIONS_RETAINED")

    def test_prune_keeps_recently_active_versions_even_when_version_is_older(self):
        # Downgrade scenario: newer versions were active long ago; the
        # currently-running (older) version has fresh activity. It must be
        # retained because pruning is driven by last-active timestamp, not by
        # version number.
        very_recent = datetime.now(UTC) - timedelta(seconds=1)
        very_old_newer = datetime.now(UTC) - timedelta(days=365)
        very_old_older = datetime.now(UTC) - timedelta(days=400)
        self._seed({
            "2.10.0.0": [(very_recent, 1)],
            "2.11.0.0": [(very_recent, 1)],
            "2.14.0.0": [(very_old_newer, 1)],
            "2.15.0.0": [(very_old_older, 1)],
        })
        hist = self._new()
        # Record another restart on an old version - it becomes the freshest.
        hist.record_restart("2.10.0.0", 1)
        kept = set(self._new()._data["versions"].keys())
        self.assertEqual(set(["2.10.0.0", "2.11.0.0", "2.14.0.0"]), kept,
                         "Older versions with newer activity must beat newer versions with older activity")

    def test_prune_preserves_entries_of_retained_versions(self):
        # Use distinct timestamps so that 2.13/2.14/2.15 are the retained set.
        now = datetime.now(UTC)
        self._seed({
            "2.10.0.0": [(now - timedelta(days=40), 1)],
            "2.11.0.0": [(now - timedelta(days=30), 1)],
            "2.13.0.0": [(now - timedelta(days=20), 11), (now - timedelta(days=15), 22)],
            "2.14.0.0": [(now - timedelta(days=10), 33)],
        })
        hist = self._new()
        hist.record_restart("2.15.0.0", 44)
        reloaded = self._new()
        # Historical entries of retained versions must be preserved intact.
        self.assertEqual([11, 22], [e["anon_bytes"] for e in reloaded.get_version_restarts("2.13.0.0")])
        self.assertEqual([33], [e["anon_bytes"] for e in reloaded.get_version_restarts("2.14.0.0")])
        self.assertEqual([44], [e["anon_bytes"] for e in reloaded.get_version_restarts("2.15.0.0")])

    def test_load_treats_unknown_schema_version_as_not_our_format(self):
        # Strict-validation policy: a file whose schema_version does not match
        # the current SCHEMA_VERSION is not something this writer produced,
        # so we cannot safely interpret it. The loader must discard the
        # in-memory state (start fresh) and the next save must overwrite the
        # file with the current schema. This is the accepted tradeoff for
        # not silently misinterpreting fields from a different schema.
        now = datetime.now(UTC)
        future_schema = SCHEMA_VERSION + 999
        self._seed({VERSION: [(now - timedelta(days=1), 123)]}, schema_version=future_schema)

        hist = self._new()
        # Existing entries from a mismatched schema must NOT leak into memory.
        self.assertEqual([], hist.get_version_restarts(VERSION),
                         "A schema_version mismatch must reset in-memory state")

        # The next save overwrites the file with the current schema.
        hist.record_restart(VERSION, 456)
        with open(self.history_path) as f:
            data = json.load(f)
        self.assertEqual(SCHEMA_VERSION, data["schema_version"])
        self.assertEqual([456], [e["anon_bytes"] for e in data["versions"][VERSION]],
                         "Only entries written under the current schema must survive")

    def test_load_treats_missing_schema_version_as_not_our_format(self):
        # A file with no schema_version tag at all is indistinguishable from
        # a file written by a different (non-tagged) writer; strict policy
        # discards it.
        with open(self.history_path, "w") as f:
            json.dump({"versions": {VERSION: [{"timestamp": "x", "anon_bytes": 1}]}}, f)
        hist = self._new()
        self.assertEqual([], hist.get_version_restarts(VERSION),
                         "A missing schema_version must be treated as 'not our format'")
        hist.record_restart(VERSION, 1)
        with open(self.history_path) as f:
            data = json.load(f)
        self.assertEqual(SCHEMA_VERSION, data["schema_version"])
        self.assertEqual([1], [e["anon_bytes"] for e in data["versions"][VERSION]])

    def test_record_restart_swallows_prune_failure_and_still_saves(self):
        # A corrupt historical timestamp can make _prune_versions() raise.
        # That must NOT propagate: dropping the record_restart() call would
        # let the agent bypass the max-restarts guardrail on the next cycle.
        # We accept that the file may temporarily hold more than
        # MAX_VERSIONS_RETAINED entries; a later successful prune fixes that.
        now = datetime.now(UTC)
        self._seed({
            "2.10.0.0": [(now - timedelta(days=40), 1)],
            "2.11.0.0": [(now - timedelta(days=30), 1)],
            "2.12.0.0": [(now - timedelta(days=20), 1)],
            "2.13.0.0": [(now - timedelta(days=10), 1)],
        })
        hist = self._new()

        with patch.object(hist, "_prune_versions", side_effect=ValueError("bad timestamp")):
            with patch("azurelinuxagent.ga.agent_memory_restart_history.logger.warn") as patch_warn:
                # Must NOT raise even though pruning failed.
                hist.record_restart("2.14.0.0", 42)

        # The failure must be surfaced through logger.warn so it is observable
        # in the agent log, and the message must reference pruning.
        self.assertTrue(patch_warn.called,
                        "A prune failure must be logged via logger.warn")
        warn_args = patch_warn.call_args[0]
        self.assertTrue(any("prune" in str(a).lower() for a in warn_args),
                        "The warn message must reference pruning; got: {0}".format(warn_args))

        # The new restart must have been persisted (guardrail integrity),
        # and no versions must have been dropped (best-effort pruning).
        reloaded = self._new()
        self.assertEqual([42], [e["anon_bytes"] for e in reloaded.get_version_restarts("2.14.0.0")],
                         "The freshly-recorded restart must be persisted even when pruning fails")
        kept = set(reloaded._data["versions"].keys())
        self.assertEqual(
            set(["2.10.0.0", "2.11.0.0", "2.12.0.0", "2.13.0.0", "2.14.0.0"]), kept,
            "When pruning fails, all existing versions must be retained (best-effort)")

    def test_record_restart_reraises_when_save_fails(self):
        # A save failure must propagate so callers can abort the restart; otherwise
        # the agent could self-restart on every cycle, bypassing the guardrails.
        hist = self._new()
        with patch("azurelinuxagent.ga.agent_memory_restart_history.os.rename",
                   side_effect=IOError("disk full")):
            self.assertRaises(IOError, hist.record_restart, VERSION, 123)

        # Nothing must have been persisted, and the tmp file must be cleaned up.
        self.assertFalse(os.path.exists(self.history_path),
                         "History file must not be created when save fails")
        self.assertFalse(os.path.exists(self.history_path + ".tmp"),
                         "Temporary file must be cleaned up on save failure")
        # A fresh instance sees an empty history, so guardrails still block correctly.
        self.assertEqual([], self._new().get_version_restarts(VERSION))



