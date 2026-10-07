# Archive Operations


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/archive-operations.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `archive.py` preserves diagnostic snapshots of Guest Agent goal state under the state directory's `history` folder. It moves selected state into timestamped directories, compacts snapshots into ZIP files, and retains at most 50 archives.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/archive-operations.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Goal-state files are replaced as the fabric advances to a new incarnation. Keeping bounded historical snapshots makes prior state available for diagnostics without allowing the agent's persistent state directory to grow indefinitely.

The archive utility centralizes three concerns:

- Preserve relevant state before current files are replaced.
- Reduce historical directories to portable ZIP snapshots.
- Enforce a fixed retention limit while leaving files used by other components untouched.

## What

### Archive lifecycle

The archive root is `history` beneath the agent state directory, which defaults to `/var/lib/waagent`. Snapshot names use ISO 8601 timestamps. Current names replace time colons with hyphens and include an incarnation range; recognition patterns also accept legacy timestamp, `_incarnation_N`, and `N-M` forms, with or without `.zip`.

| Stage | Responsibility |
|---|---|
| Flush | Move matching state files into a new timestamped history directory when an incarnation changes. |
| Archive | Convert pending history directories into same-named ZIP files, then remove the source directories. |
| Purge | Sort ZIP archives by timestamp in descending order, keep the newest 50, and delete older entries. |

`State` represents an archive-state entry identified from the history path and naming scheme. Archive discovery must continue to recognize both current and legacy names so upgrades do not orphan existing history.

### State-file selection

`_CACHE_PATTERNS` defines the files eligible for historical capture:

- Versioned `VmSettings.<n>.json` payloads.
- Versioned agent manifests and `manifest.xml` files.
- Versioned XML goal-state artifacts.
- `HostingEnvironmentConfig.xml` and `RemoteAccess.xml`.
- Versioned `waagent_status.<n>.json` records.

`SharedConfig.xml` is deliberately excluded because AzSec and Singularity/HPC InfiniBand consume it outside the archive workflow. `_PLACEHOLDER_FILE_NAME` retains the compatibility placeholder `GoalState.1.xml` until the associated legacy behavior can be removed.

### Retention and failure boundaries

`_MAX_ARCHIVED_STATES` fixes retention at 50 ZIP snapshots. Filesystem work uses `glob`, `os`, `shutil`, and `zipfile`; errors are interpreted with `errno` and reported through the shared `logger`. Path and file operations are delegated to `fileutil` where the common utility contract applies.

## How

### Processing flow

1. Goal-state processing detects an incarnation change.
2. The utility creates a timestamped directory beneath `history`.
3. It matches current state files against `_CACHE_PATTERNS` and moves eligible files into the snapshot.
4. Historical snapshot directories are periodically written as ZIP archives.
5. Successfully archived directories are removed.
6. ZIP files are ordered newest-first; entries beyond `_MAX_ARCHIVED_STATES` are purged.

The move-before-compress sequence keeps the active state directory ready for the new incarnation while isolating archival work from newly written state.

### Change guidance

- Update `_CACHE_PATTERNS` when a new goal-state artifact must survive incarnation changes; avoid broad patterns that capture unrelated persistent data.
- Do not add `SharedConfig.xml` unless all external consumers can tolerate it being moved.
- Preserve legacy archive-name recognition when changing current naming conventions.
- Delete a snapshot directory only after its ZIP archive is created successfully.
- Keep retention ordering based on archive timestamps, not arbitrary filesystem enumeration.
- Treat `_MAX_ARCHIVED_STATES` as the disk-bounding invariant when changing purge behavior.
- Remove `_PLACEHOLDER_FILE_NAME` only with the corresponding `GoalState.1.xml` compatibility path.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Goal-state snapshot, compression, and retention | `azurelinuxagent/common/utils/archive.py` | `State`; `State.__init__`; `ARCHIVE_DIRECTORY_NAME`; `_CACHE_PATTERNS`; `_MAX_ARCHIVED_STATES` |
| Archive naming and compatibility matching | `azurelinuxagent/common/utils/archive.py` | `_ARCHIVE_BASE_PATTERN`; `_ARCHIVE_PATTERNS_DIRECTORY`; `_ARCHIVE_PATTERNS_ZIP`; `_PLACEHOLDER_FILE_NAME` |
| Archived artifact names | `azurelinuxagent/common/utils/archive.py` | `_GOAL_STATE_FILE_NAME`; `_VM_SETTINGS_FILE_NAME`; `_CERTIFICATES_FILE_NAME`; `_HOSTING_ENV_FILE_NAME`; `_REMOTE_ACCESS_FILE_NAME`; `_EXT_CONF_FILE_NAME`; `_MANIFEST_FILE_NAME`; `AGENT_STATUS_FILE`; `SHARED_CONF_FILE_NAME` |
| Common filesystem helpers | `azurelinuxagent/common/utils/fileutil.py` | File and directory utility operations |
| Configuration and diagnostics | `azurelinuxagent/common/conf.py`; `azurelinuxagent/common/logger.py` | Agent state-directory configuration; shared logging API |

## Related Components

- [Goal-State Domain Models](../L1-conceptual/goal-state-domain-models.md) — describes the protocol state whose prior incarnations are retained for diagnostics and fallback analysis.
- [Agent Logging Service](agent-logging-service.md) — reports archive and filesystem failures through the shared logging path.
