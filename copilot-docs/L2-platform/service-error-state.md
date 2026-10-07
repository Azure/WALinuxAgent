# Service Error State


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/service-error-state.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `ErrorState` tracks when a continuous failure period began and becomes triggered after a configured duration. The Host Plugin uses this state to distinguish transient transport failures from sustained service degradation.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/service-error-state.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Agent operations can fail briefly while local or Azure services recover. Reacting to every individual failure would cause premature fallback, noisy telemetry, and unstable protocol behavior, while ignoring repeated failures would hide persistent outages.

`ErrorState` provides a small shared state machine that answers a narrower question: has the current uninterrupted failure period lasted long enough to require escalation? Callers remain responsible for deciding what action a triggered state should cause.

## What

### Duration-based failure state

An `ErrorState` contains:

| State | Meaning |
|---|---|
| `min_timedelta` | Minimum continuous failure duration before the state triggers. |
| `count` | Number of failures recorded in the current failure period. |
| `timestamp` | UTC time of the first failure in that period, or `None` when healthy/reset. |

`ErrorState.incr` sets `timestamp` only on the first failure and then increments `count`. `ErrorState.is_triggered` compares elapsed UTC time with `min_timedelta`; the count itself does not trigger the state. This preserves the start of a continuous failure window across subsequent failures.

`ErrorState.reset` clears both count and timestamp. It must be called after recovery so a later failure starts a new window rather than inheriting stale elapsed time.

### Timing profiles

| Constant | Duration | Intended profile |
|---|---:|---|
| `ERROR_STATE_DELTA_DEFAULT` | 15 minutes | General sustained failures. |
| `ERROR_STATE_DELTA_INSTALL` | 5 minutes | Installation failures requiring faster escalation. |
| `ERROR_STATE_HOST_PLUGIN_FAILURE` | 5 minutes | Sustained Host Plugin failures. |

Callers can pass another `timedelta` to `ErrorState.__init__` when these shared profiles do not fit.

### Diagnostic duration

`ErrorState.fail_time` formats the current failure duration as minutes below one hour and hours thereafter. Before any failure it returns `unknown`. This value is diagnostic text, not a stable duration type and not the trigger condition.

### Host Plugin integration

`azurelinuxagent.common.protocol.hostplugin` imports `ErrorState` with `ERROR_STATE_HOST_PLUGIN_FAILURE` alongside protocol exceptions, health reporting, telemetry, and goal-state parsing dependencies. At this boundary, sustained local Host Plugin failures can be treated differently from one-off HTTP or protocol errors while retaining the original failure start time.

## How

### State lifecycle

1. Construct `ErrorState` with the timeout appropriate to the operation.
2. On each failure, call `ErrorState.incr`.
3. Check `ErrorState.is_triggered` when deciding whether to escalate or switch behavior.
4. Use `ErrorState.fail_time` only when a human-readable duration is needed.
5. On successful recovery, call `ErrorState.reset`.

### Behavioral invariants

- The first failure owns the timestamp; later failures must not extend the trigger deadline.
- Triggering depends on elapsed wall-clock duration, not failure count or call frequency.
- A state with no timestamp is never triggered.
- All timestamps use timezone-aware UTC through `azurelinuxagent.common.future.UTC`.
- Recovery must clear both timestamp and count.

### Change guidance

- Do not turn `count` into an implicit retry threshold; introduce that policy explicitly at the caller if needed.
- Preserve the `>=` boundary in `ErrorState.is_triggered` so the state triggers exactly at its configured duration.
- Keep Host Plugin timing changes explicit by updating `ERROR_STATE_HOST_PLUGIN_FAILURE`, rather than changing the default for unrelated consumers.
- Do not parse `fail_time` for control flow; use `is_triggered` or timestamp arithmetic.
- Pair every failure-recording path with a confirmed-success reset path to preserve continuous-failure semantics.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Failure-window state and shared timing profiles | `azurelinuxagent/common/errorstate.py` | `ErrorState`; `ErrorState.__init__`; `ErrorState.incr`; `ErrorState.reset`; `ErrorState.is_triggered`; `ErrorState.fail_time`; `ERROR_STATE_DELTA_DEFAULT`; `ERROR_STATE_DELTA_INSTALL`; `ERROR_STATE_HOST_PLUGIN_FAILURE` |
| Host Plugin failure integration | `azurelinuxagent/common/protocol/hostplugin.py` | `ErrorState`; `ERROR_STATE_HOST_PLUGIN_FAILURE` |

## Related Components

- [Agent Event Reporting](agent-event-reporting.md) — reports operational failures and outcomes through `WALAEventOperation` and `add_event`.
- [Flexible Version Comparison](flexible-version-comparison.md) — supports Host Plugin API-version negotiation through `FlexibleVersion`.
- [Extension Goal State Factory](../L1-conceptual/extension-goal-state-factory.md) — creates extension goal state consumed by Host Plugin protocol paths.
- [Goal-State Domain Models](../L1-conceptual/goal-state-domain-models.md) — describes the goal-state data exchanged through protocol implementations.
- [Protocol Data Contracts](../L1-conceptual/protocol-data-contracts.md) — defines the status and protocol records surrounding Host Plugin communication.
