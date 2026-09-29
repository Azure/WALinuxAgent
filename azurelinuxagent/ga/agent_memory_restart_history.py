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
from datetime import datetime, timedelta

from azurelinuxagent.ga import state_dir

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import UTC, ustr
from azurelinuxagent.common.utils import timeutil


HISTORY_FILE_NAME = "agent_memory_restart_history.json"

# ---------------------------------------------------------------------------
# On-disk schema contract
# ---------------------------------------------------------------------------
#
# SCHEMA_VERSION is stamped into every file we write and describes the shape
# of the JSON *this writer* produces. On read, the loader validates the
# on-disk tag against SCHEMA_VERSION strictly: any mismatch (or missing tag)
# means the file was written by a different writer and we cannot safely
# interpret it, so we log a warning and start with an empty in-memory state.
# The malformed file is left in place for inspection; the next successful
# save overwrites it with the current schema.
#
# Current file layout (SCHEMA_VERSION = 1)::
#
#     {
#       "schema_version": 1,
#       "versions": {
#         "<agent version string>": [
#           {"timestamp": "<UTC iso8601 with 'Z'>", "anon_bytes": <int>},
#           ...
#         ],
#         ...
#       }
#     }
#
# Loader behavior:
#
#   * Missing file                        -> start with empty state.
#   * Unreadable JSON                     -> rename to '<path>.corrupt',
#                                            start with empty state.
#   * Missing / non-int 'schema_version'  -> not our format; start fresh.
#   * 'schema_version' != SCHEMA_VERSION  -> not our format; start fresh.
#   * 'versions' not a dict               -> not our format; start fresh.
#
# Downgrade / upgrade implication:
#
#   Because the loader is strict, a downgrade that finds a file written by
#   a newer schema will discard it and start fresh to start tracking memory monitoring. The per-version restart
#   guardrails therefore reset on schema mismatch. This is an accepted
#   tradeoff: preserving unknown data would let an older agent silently
#   misinterpret fields it does not understand.
#
# When to bump SCHEMA_VERSION:
#
#   Bump it any time the file shape changes in a way an older agent would
#   misread -- e.g. renaming a key, changing a value type, removing a
#   field an older agent depends on, or adding a top-level field a newer
#   agent needs.
#
# When NOT to bump:
#
#   Optional additive fields inside each restart entry (e.g. a new key
#   alongside "timestamp" / "anon_bytes") do not require a bump; older
#   readers ignore them and newer writers must tolerate their absence.
#
# Every time you bump, update the "Current file layout" example above and
# describe what changed, so a future maintainer can see the history.
# ---------------------------------------------------------------------------
SCHEMA_VERSION = 1
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # matches timeutil.create_utc_timestamp
# Retain restart history only for the N most-recently-active agent versions;
# older versions are pruned on every save so the file cannot grow without bound.
MAX_VERSIONS_RETAINED = 3


class AgentMemoryRestartHistory(object):
    """
    Load/append/save restart records. Not thread-safe; intended to be used from
    the ext-handler main thread only.

    File schema::

        {
          "schema_version": 1,
          "versions": {
            "<version>": [
              {"timestamp": "<iso8601 UTC>", "anon_bytes": <int>}
            ]
          }
        }
    """

    def __init__(self, path=None):
        self._path = path if path is not None else os.path.join(state_dir.get_state_dir(), HISTORY_FILE_NAME)
        self._data = self._load()

    def _load(self):
        default = {"schema_version": SCHEMA_VERSION, "versions": {}}
        if not os.path.exists(self._path):
            return default
        try:
            with open(self._path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                file_schema = data.get("schema_version")
                if isinstance(file_schema, int) and file_schema == SCHEMA_VERSION:
                    if isinstance(data.get("versions"), dict):
                        versions = data["versions"]
                        return {
                            "schema_version": SCHEMA_VERSION,
                            "versions": versions,
                        }

            logger.warn("Agent memory restart history at {0} is not in the expected format. Starting fresh.", self._path)
            return default
        except Exception as e:
            logger.warn("Corrupt agent memory restart history at {0}: {1}. Starting fresh.", self._path, ustr(e))
            try:
                os.rename(self._path, self._path + ".corrupt")
            except Exception as rename_error:
                logger.warn("Failed to rename corrupt agent memory restart history {0} to .corrupt: {1}",
                            self._path, ustr(rename_error))
            return default

    def _save(self):
        tmp = self._path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(self._data, f)
            # os.rename is atomic on POSIX; the agent does not run on Windows.
            os.rename(tmp, self._path)
        except Exception as e:
            logger.warn("Failed to persist agent memory restart history: {0}", ustr(e))
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
            raise

    def get_version_restarts(self, version):
        # 'version' may be a str or a FlexibleVersion; it is coerced to str
        # since the history file keys versions by their string form.
        return list(self._data.get("versions", {}).get(str(version), []))

    def get_version_latest_restart_time(self, version):
        # 'version' may be a str or a FlexibleVersion (see get_version_restarts).
        entries = self.get_version_restarts(version)
        if len(entries) == 0:
            return None
        # Parse every timestamp to a datetime and take the max.
        parsed = [
            datetime.strptime(e.get("timestamp", ""), _TIMESTAMP_FORMAT).replace(tzinfo=UTC)
            for e in entries
        ]
        return max(parsed)

    def version_can_restart(self, version, max_per_version, min_interval_seconds):
        """
        Returns (allowed: bool, reason: str).

        'version' may be a str or a FlexibleVersion (see get_version_restarts).
        """
        entries = self.get_version_restarts(version)
        if len(entries) >= max_per_version:
            return False, "max restarts ({0}) reached for version {1}".format(max_per_version, version)
        last = self.get_version_latest_restart_time(version)
        if last is not None:
            delta = datetime.now(UTC) - last
            if delta < timedelta(0):
                # Clock skew: treat as zero elapsed time.
                delta = timedelta(0)
            min_interval = timedelta(seconds=min_interval_seconds)
            if delta < min_interval:
                return False, "last restart {0} ago is within min interval {1}".format(delta, min_interval)
        return True, "allowed"

    def record_restart(self, version, anon_bytes):
        # 'version' may be a str or a FlexibleVersion (see get_version_restarts)
        entry = {
            "timestamp": timeutil.create_utc_timestamp(datetime.now(UTC)),
            "anon_bytes": int(anon_bytes),
        }
        # _load() guarantees self._data always contains a "versions" dict, so
        # we can index directly rather than defaulting here.
        versions = self._data["versions"]
        versions.setdefault(str(version), []).append(entry)

        # Pruning is best-effort: if it fails (e.g. a historical entry has a
        # corrupt timestamp we cannot parse), we still want to persist the
        # freshly-recorded restart -- losing that would let the agent bypass
        # the max-restarts guardrail on the next cycle. The worst case is the
        # file temporarily holds more than MAX_VERSIONS_RETAINED entries; a
        # subsequent successful prune will bring it back down.
        try:
            self._prune_versions()
        except Exception as e:
            msg = "Failed to prune agent memory restart history; keeping current versions dict. Error: {0}".format(ustr(e))
            logger.warn(msg)
        self._save()

    def _prune_versions(self):
        """
        Keep only the MAX_VERSIONS_RETAINED most-recently-active agent
        versions (based on the latest restart timestamp per version); drop
        the rest.
        """
        versions = self._data["versions"]
        if len(versions) <= MAX_VERSIONS_RETAINED:
            return

        def _latest_ts(entries):
            # Empty entry list -> min epoch, so such versions are pruned first.
            # Any parse error propagates to record_restart, which treats
            # pruning as best-effort and emits telemetry.
            if len(entries) == 0:
                return datetime.min.replace(tzinfo=UTC)
            return max(
                datetime.strptime(e.get("timestamp", ""), _TIMESTAMP_FORMAT).replace(tzinfo=UTC)
                for e in entries
            )

        # Sort descending by latest restart timestamp and keep the top N.
        ranked = sorted(versions.items(), key=lambda item: _latest_ts(item[1]), reverse=True)
        self._data["versions"] = dict(ranked[:MAX_VERSIONS_RETAINED])

