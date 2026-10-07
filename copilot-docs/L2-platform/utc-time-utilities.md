# UTC Time Utilities


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/utc-time-utilities.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `create_utc_timestamp` converts a timezone-aware UTC `datetime` into the agent's canonical ISO-8601 timestamp with a `Z` suffix. It rejects naive and non-UTC values so callers cannot silently serialize ambiguous or offset-local times.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/utc-time-utilities.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Agent protocols, logs, telemetry, and persisted state need a stable UTC representation that is independent of local timezone settings. Accepting naive datetimes or silently converting arbitrary offsets would hide caller errors and could make event ordering and time comparisons unreliable.

This utility establishes a narrow serialization boundary: callers must supply an already normalized UTC value, and the formatter emits one predictable wire representation.

## What

### Timestamp contract

| Property | Behavior |
|---|---|
| Input | A timezone-aware `datetime` whose UTC offset is zero. |
| Output | ISO-8601 date and time with a `Z` UTC designator. |
| Precision | Microseconds are retained; zero microseconds are emitted explicitly as six zeroes. |
| Naive datetime | Rejected with `ValueError`. |
| Non-zero UTC offset | Rejected with `ValueError`; the utility does not convert timezones. |

The resulting shape is `YYYY-MM-DDTHH:MM:SS.ffffffZ`. Using `Z` instead of an explicit zero offset gives protocol consumers a single canonical UTC form.

### Compatibility behavior

`create_utc_timestamp` uses `datetime.isoformat` after removing only the timezone marker from the validated UTC value. This avoids the historical lower-year limitation of `strftime` on older Python versions while retaining microsecond precision.

The function is a formatter, not a clock source or timezone normalizer. Creation of aware UTC values belongs to callers, typically through the shared `UTC` compatibility object.

## How

### Serialization flow

1. Verify that the input has timezone information.
2. Verify that its effective offset is exactly zero.
3. Remove timezone metadata from the validated value.
4. Serialize with `datetime.isoformat`.
5. Add explicit zero microseconds when absent, then append `Z`.

### Usage and change guidance

- Normalize values to UTC before calling `create_utc_timestamp`; do not pass a non-zero offset and expect conversion.
- Prefer the shared `UTC` provider when constructing aware datetimes across supported Python runtimes.
- Preserve `ValueError` for invalid inputs so timezone mistakes fail at the serialization boundary.
- Preserve fixed six-digit fractional seconds, including for whole-second values; downstream consumers may depend on the stable shape.
- Keep the implementation compatible with dates that older Python `strftime` implementations cannot format.
- Do not broaden this helper into parsing, current-time acquisition, or local-time policy; those are separate responsibilities.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Canonical UTC timestamp validation and formatting | `azurelinuxagent/common/utils/timeutil.py` | `create_utc_timestamp` |
| Cross-runtime UTC timezone provider | `azurelinuxagent/common/future.py` | `UTC`; `_UTC` |

## Related Components

- [Runtime Compatibility Helpers](runtime-compatibility-helpers.md) — provides `UTC`, the cross-version zero-offset timezone used to construct aware values safely.
- [Periodic Operation Runner](../L1-conceptual/periodic-operation-runner.md) — relies on timezone-aware UTC values for elapsed-time decisions.
