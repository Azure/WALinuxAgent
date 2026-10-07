# File I/O Utilities


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/file-io-utilities.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `fileutil.py` centralizes byte-safe file reads and writes, optional text decoding and BOM removal, append behavior, and small path/content helpers. Callers choose binary or text semantics explicitly while ordinary filesystem errors remain visible to the caller.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/file-io-utilities.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The agent reads and writes protocol state, configuration, logs, and diagnostic artifacts across supported Python and Linux environments. A shared utility keeps encoding boundaries, BOM handling, append modes, path handling, and recognized infrastructure-level I/O failures consistent instead of duplicating subtly different file logic in each subsystem.

## What

### Read and write contract

| Operation | Responsibility | Important options |
|---|---|---|
| `read_file` | Read a file in binary mode, then return bytes or decoded text. | `asbin`; `remove_bom`; `encoding` |
| `write_file` | Encode text when needed and write or append using binary file modes. | `asbin`; `encoding`; `append` |
| `append_file` | Provide the append-oriented entry point over the shared write behavior. | `asbin`; `encoding` |
| `base_name` | Return the final name portion of a path. | `path` |
| `get_line_startingwith` | Locate content by a line prefix. | Prefix-oriented text lookup |

`read_file` always opens the source as bytes. With `asbin=True`, it returns those bytes unchanged. Otherwise it can remove a byte-order mark through `textutil.remove_bom` before converting the data to a Unicode string with `ustr` and the requested encoding.

`write_file` uses `wb` by default and `ab` when appending. Text content is encoded before writing; `asbin=True` requires the caller to supply binary content and bypasses encoding.

### Recognized I/O failures

`KNOWN_IOERRORS` identifies infrastructure and resource failures that callers may need to classify consistently:

- General and remote I/O errors.
- Memory, process file-descriptor, and system file-table exhaustion.
- Disk-space exhaustion.
- Overlong names and excessive symbolic-link traversal.

Remote I/O uses numeric error `121` because `errno.EREMOTEIO` is not available on every supported Python runtime.

### Dependencies

- `textutil.remove_bom` owns BOM stripping; `fileutil` applies it only when requested for text reads.
- `future.ustr` provides the repository's encoding-aware bytes-to-text conversion.
- The shared `logger` and standard filesystem modules support the module's broader utility surface and error reporting.

## How

### Reading safely

1. Call `read_file` with `asbin=True` when exact bytes must be preserved.
2. For text, leave `asbin=False` and provide the file's actual `encoding` when it is not UTF-8.
3. Set `remove_bom=True` only when BOM normalization is desired; removal occurs before decoding.
4. Handle filesystem and decoding failures at the boundary that has enough context to report or recover from them.

### Writing safely

1. Pass text with `asbin=False`; `write_file` encodes it using the selected encoding.
2. Pass bytes with `asbin=True`; do not rely on implicit conversion.
3. Use `append_file` or `write_file(..., append=True)` only when preserving existing content is intentional.
4. Do not treat `KNOWN_IOERRORS` as proof that an operation is recoverable; it is a shared classification set for callers to apply according to their workflow.

### Change guidance

- Preserve the binary-open-first read path so BOM processing happens on bytes and decoding remains explicit.
- Keep read and write encoding defaults aligned unless a repository-wide compatibility change requires otherwise.
- Extend `KNOWN_IOERRORS` only for portable, infrastructure-level conditions that callers should classify together.
- Avoid swallowing `IOError`, `OSError`, or encoding exceptions in these primitives; higher-level consumers own retry, fallback, and user-facing diagnostics.
- Prefer these helpers over local open/encode/decode implementations when their contract fits, but use direct filesystem APIs when atomic replacement, permissions, ownership, or locking requires stronger semantics.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Text and binary reads | `azurelinuxagent/common/utils/fileutil.py` | `read_file` |
| Writes and append behavior | `azurelinuxagent/common/utils/fileutil.py` | `write_file`; `append_file` |
| Path and line helpers | `azurelinuxagent/common/utils/fileutil.py` | `base_name`; `get_line_startingwith` |
| Shared I/O error classification | `azurelinuxagent/common/utils/fileutil.py` | `KNOWN_IOERRORS` |
| BOM normalization | `azurelinuxagent/common/utils/textutil.py` | `remove_bom` |
| Bytes-to-text compatibility conversion | `azurelinuxagent/common/future.py` | `ustr` |

## Related Components

- [Agent Logging Service](agent-logging-service.md) — provides the shared diagnostics path used by platform utilities.
- [Archive Operations](archive-operations.md) — consumes common filesystem helpers while preserving and compacting goal-state history.
