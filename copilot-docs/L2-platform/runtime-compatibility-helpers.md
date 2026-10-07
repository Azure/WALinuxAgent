# Runtime Compatibility Helpers


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/runtime-compatibility-helpers.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `azurelinuxagent.common.future` provides a stable import and behavior surface across supported Python runtimes and Linux distributions. It normalizes text, buffers, standard-library APIs, UTC values, distro discovery, missing-file checks, subprocess null output, and array serialization so callers avoid version branches.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/runtime-compatibility-helpers.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The agent runs on Linux images with different Python versions, standard-library layouts, distribution metadata providers, and platform quirks. Scattering runtime checks across protocol, OS, logging, and update code would produce inconsistent behavior and make compatibility changes difficult to audit.

This module concentrates those differences behind import-compatible aliases and small helpers. Callers use one API while the module selects the runtime-specific implementation at import or call time.

## What

### Cross-version aliases

| Stable name | Normalized behavior |
|---|---|
| `httpclient` | Selects the runtime's HTTP client module. |
| `urlparse` | Selects the runtime's URL parser. |
| `Queue`, `Empty` | Expose queue types from the correct standard-library location. |
| `OrderedDict` | Uses the standard implementation when available and the legacy backport on older runtimes. |
| `ustr` | Represents the Unicode string type used for text conversion. |
| `bytebuffer` | Represents the runtime's zero-copy byte-buffer view. |
| `range`, `int` | Normalize lazy ranges and unbounded integer behavior. |

Unsupported Python major versions fail immediately with `ImportError` rather than exposing a partially initialized compatibility surface.

### Encoding compatibility

`BACKSLASH_REPLACE` names the error handler callers should use when arbitrary bytes or Unicode must remain representable. Modern runtimes use the built-in `backslashreplace`; older runtimes register `__waagent_backslashreplace__`, which emits escaped byte or Unicode code-point sequences and advances past the failing input.

### UTC and sentinel values

`UTC` resolves to the best available timezone implementation: `datetime.UTC`, `datetime.timezone.utc`, or the local `_UTC` fallback. `_UTC.utcoffset`, `_UTC.tzname`, and `_UTC.dst` implement a zero-offset timezone on legacy runtimes.

`datetime_min_utc` and `datetime_max_utc` attach this timezone to the standard datetime limits. They are comparable, timezone-aware sentinels used by update, protocol, telemetry, and test flows; they are not timestamps for the current time.

### Distribution discovery

`get_linux_distribution` preserves the legacy distribution tuple contract while adapting to runtime and platform differences:

1. It tries `platform.linux_distribution` when available and extends its supported distribution set.
2. It reads `/etc/openwrt_release` through `get_openwrt_platform` for OpenWRT, whose metadata is not detected reliably by the legacy API.
3. It falls back to `get_linux_distribution_from_distro` when the legacy API is absent or returns no data.
4. It appends the unshortened distribution name expected by downstream version and OS-selection logic.

`get_linux_distribution_from_distro` deliberately does not hide a missing or broken `distro` dependency. For Mariner, it requests the provider's most precise version to avoid truncated release data.

### Focused runtime adapters

- `is_file_not_found_error` recognizes the runtime-specific missing-file exception shape.
- `subprocess_dev_null` yields `subprocess.DEVNULL` where available or manages an `os.devnull` file handle on legacy runtimes.
- `array_to_bytes` selects `array.tobytes` or the removed `array.tostring` API according to runtime support.

## How

### Usage model

1. Import stable names from `azurelinuxagent.common.future`; do not duplicate version checks at call sites.
2. Treat aliases as compatibility contracts, not as opportunities to depend on one runtime's concrete type.
3. Use `UTC` for aware timestamps and the UTC extrema only when a sentinel is required.
4. Obtain distribution data through `get_linux_distribution` so OpenWRT, Mariner, legacy platform APIs, and the `distro` fallback remain consistent.
5. Use the context-managed `subprocess_dev_null` so legacy file handles are closed.

### Change guidance

- Preserve import-time availability of exported aliases; they are consumed broadly across agent subsystems.
- Keep failures explicit when a required compatibility dependency is broken. A fabricated distribution result can select the wrong OS adapter.
- Add runtime branching here only for genuine API or semantic differences, not for subsystem policy.
- Preserve the distribution result shape when changing detection logic; version and platform selection depend on it.
- Keep UTC values timezone-aware and comparable across every supported runtime.
- Do not replace `array_to_bytes` with an unconditional modern API while older runtimes remain supported.
- When changing an alias, audit all importers because callers may rely on behavior beyond its nominal type.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Standard-library, text, buffer, integer, and collection aliases | `azurelinuxagent/common/future.py` | `httpclient`; `urlparse`; `Queue`; `Empty`; `OrderedDict`; `ustr`; `bytebuffer`; `range`; `int` |
| Encoding error compatibility | `azurelinuxagent/common/future.py` | `BACKSLASH_REPLACE`; `__waagent_backslashreplace__` |
| UTC compatibility and datetime sentinels | `azurelinuxagent/common/future.py` | `UTC`; `_UTC`; `_UTC.utcoffset`; `_UTC.tzname`; `_UTC.dst`; `datetime_min_utc`; `datetime_max_utc` |
| Distribution and OpenWRT discovery | `azurelinuxagent/common/future.py` | `get_linux_distribution`; `get_linux_distribution_from_distro`; `get_openwrt_platform` |
| Missing-file, null-output, and array adapters | `azurelinuxagent/common/future.py` | `is_file_not_found_error`; `subprocess_dev_null`; `array_to_bytes` |

## Related Components

- [Distribution OS Adapters](distribution-os-adapters.md) — consume normalized distribution identity and isolate OpenWRT and other platform-specific behavior.
- [Agent Packaging and Platform Factories](agent-packaging-factories.md) — use distribution metadata to select platform implementations.
- [File I/O Utilities](file-io-utilities.md) — use `ustr` for explicit bytes-to-text conversion.
