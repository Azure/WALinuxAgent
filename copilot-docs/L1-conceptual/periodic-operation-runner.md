# Periodic Operation Runner


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/periodic-operation-runner.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `PeriodicOperation` is a lightweight base class for polling-loop tasks that should run no more often than a configured interval. It isolates operation failures, advances the next run even after errors, and suppresses repeated identical warnings for one hour.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/periodic-operation-runner.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Long-running agent loops need to perform maintenance work periodically without giving every task its own timing, exception, and log-throttling logic. A failed maintenance action must not terminate its caller or flood logs on every loop iteration.

`PeriodicOperation` provides that shared lifecycle while leaving the actual work to subclasses.

## What

An instance tracks:

| State | Purpose |
|---|---|
| Operation name | Uses the subclass name in execution and warning messages. |
| Period | Accepts a `datetime.timedelta` or a numeric number of seconds. |
| Next run time | Starts at the current UTC time, so a new operation is immediately eligible. |
| Last warning | Identifies repeated error text. |
| Last warning time | Enforces the one-hour duplicate-warning suppression window. |

The base class calls the subclass-provided `PeriodicOperation._operation` only when the operation is due. `PeriodicOperation.run` is intentionally safe to invoke repeatedly from a polling loop: early calls are no-ops, while exceptions are converted to warnings rather than propagated.

## How

### Execution lifecycle

1. Construct the operation with its interval; numeric values are converted to `datetime.timedelta`.
2. Repeatedly call `PeriodicOperation.run` from the owning loop.
3. `run` compares `PeriodicOperation.next_run_time` with the current UTC time.
4. When due, it emits a verbose execution message and invokes `PeriodicOperation._operation`.
5. A `finally` block schedules the next run from the current time plus the configured period, even when the operation fails.
6. Any exception is formatted with `ustr` and considered for warning output.

Because the next run is based on the time after execution rather than the previous deadline, long-running operations do not trigger immediate catch-up runs. The schedule favors spacing and stability over fixed-rate cadence.

### Failure and logging contract

- Exceptions from `_operation` do not escape `run`.
- The warning includes the operation name and normalized exception text.
- A changed warning is logged immediately.
- An identical warning is logged again only when no prior warning time exists or at least `_LOG_WARNING_PERIOD` (60 minutes) has elapsed.
- Successful execution still advances the next run but does not require callers to reset warning state.

### Coordinating multiple operations

`PeriodicOperation.sleep_until_next_operation` is the shared coordination point for callers managing a collection of periodic operations. It allows an owner to sleep until upcoming work rather than busy-waiting; use each operation's `next_run_time` when integrating it into such a loop.

### Change guidance

- Implement task-specific behavior in `_operation`; keep scheduling and exception containment in the base class.
- Call `run` frequently enough for the required responsiveness, but do not expect exact wall-clock execution at the deadline.
- Preserve the `finally`-based rescheduling when changing execution flow, or failures can cause tight retry loops.
- Use timezone-aware UTC timestamps consistently with `UTC`.
- Do not remove warning deduplication without considering persistent-failure log volume.
- Choose another scheduler when fixed-rate execution, catch-up semantics, cancellation, or concurrent execution is required.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Periodic scheduling and failure isolation | `azurelinuxagent/ga/periodic_operation.py` | `PeriodicOperation`; `PeriodicOperation.__init__`; `PeriodicOperation.run`; `PeriodicOperation._operation` |
| Scheduling visibility and loop coordination | `azurelinuxagent/ga/periodic_operation.py` | `PeriodicOperation.next_run_time`; `PeriodicOperation.sleep_until_next_operation` |
| Warning and verbose logging | `azurelinuxagent/common/logger.py` | `verbose`; `warn` |
| UTC and exception-text compatibility | `azurelinuxagent/common/future.py` | `UTC`; `ustr` |

## Related Components

- **Agent polling loops:** Own the repeated calls to `PeriodicOperation.run` and can coordinate several instances through `PeriodicOperation.sleep_until_next_operation`.
- **Common logging:** `azurelinuxagent.common.logger` records execution diagnostics while the runner controls duplicate-warning frequency.
- **Compatibility utilities:** `azurelinuxagent.common.future.UTC` keeps comparisons timezone-aware, and `ustr` normalizes exception text across supported Python versions.
