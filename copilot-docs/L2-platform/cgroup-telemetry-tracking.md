# Cgroup Telemetry Tracking


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/cgroup-telemetry-tracking.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `CGroupsTelemetry` is the thread-safe registry for cgroup controllers whose resource metrics the agent polls. It gives each controller a version-safe identity, initializes CPU baselines before collection, and centralizes registration, polling, removal, and reset behavior.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/cgroup-telemetry-tracking.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The agent creates multiple CPU and memory controllers and polls them from recurring monitoring work. Cgroup v2 can expose different controller types through the same filesystem path, so path-only registration would collapse distinct metric sources. Registration and polling can also overlap across worker activity, requiring one synchronized owner for mutable tracking state.

`CGroupsTelemetry` provides that boundary:

- Distinguishes controllers by both controller type and cgroup path.
- Prevents duplicate registration with constant-time dictionary lookup.
- Establishes an initial CPU reading before later usage deltas are calculated.
- Serializes access to process-wide tracking state with a reentrant lock.
- Gives monitoring code one operation for polling all registered controllers.

## What

### Tracking identity and state

`CGroupsTelemetry._get_tracking_id` formats an identity from `get_controller_type()` and `path`. Including the controller type is essential for cgroup v2, where CPU and memory controllers can share the same path.

The class-level `_tracked` dictionary holds controllers for the process, and `_rlock` protects all registry access. `is_tracked` checks the dictionary directly, preserving O(1) membership tests. Because the state is global, `reset` is the lifecycle and test-isolation boundary rather than construction of a new registry instance.

### Registration

`track_cgroup_controller` prepares CPU controllers before publishing them to the registry. For `_CpuController`, it calls `initialize_cpu_usage` so subsequent polling can calculate usage relative to a known baseline.

Under the lock, registration computes the tracking ID, skips an existing entry, stores a new controller, and records that tracking started. Duplicate calls are therefore idempotent and do not replace the registered object or reinitialize its tracking state.

### Polling and removal

`poll_all_tracked` is the aggregation surface used by resource monitoring. It traverses the synchronized registry and asks the tracked controllers for their current metrics, keeping controller discovery separate from metric reporting.

`stop_tracking` removes a controller from the registry when its lifecycle ends. Callers should use the class API rather than mutating `_tracked`; this preserves identity rules, locking, and consistent logging. The module uses periodic warnings for recurring polling failures so repeated faults remain visible without flooding logs, and normalizes exception text with `ustr`.

## How

### Lifecycle

1. Cgroup setup creates a resource controller.
2. `track_cgroup_controller` initializes the CPU baseline when applicable.
3. `_get_tracking_id` combines controller type and path.
4. The controller is added once to `_tracked` while `_rlock` is held.
5. Periodic monitoring calls `poll_all_tracked` and consumes the returned controller metrics.
6. `stop_tracking` removes controllers that are no longer active.
7. `reset` clears process-wide tracking state during teardown or test isolation.

### Change guidance

- Preserve the `controller_type:path` identity; a path-only key breaks cgroup v2 tracking.
- Initialize `_CpuController` usage before registration, not during the first reporting poll.
- Keep reads, writes, iteration, and reset operations under `_rlock`.
- Treat duplicate registration as a no-op rather than replacing active controller state.
- Keep metric collection in controllers and registry orchestration in `CGroupsTelemetry`.
- Use the existing periodic warning path for repeatable poll failures rather than emitting an unbounded warning on every cycle.
- Update monitoring consumers if the shape returned by `poll_all_tracked` changes.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Tracking registry and polling | `azurelinuxagent/ga/cgroupstelemetry.py` | `CGroupsTelemetry`; `track_cgroup_controller`; `poll_all_tracked`; `stop_tracking`; `reset` |
| CPU usage baseline | `azurelinuxagent/ga/cpucontroller.py` | `_CpuController`; `initialize_cpu_usage` |
| Logging and repeated-warning control | `azurelinuxagent/common/logger.py` | `info`; `periodic_warn` |
| Exception text normalization | `azurelinuxagent/common/future.py` | `ustr` |

## Related Components

- [Cgroup Resource Governance](cgroup-resource-governance.md) — configures the controllers registered here and connects polling to `MonitorHandler`.
- [Agent Event Reporting](agent-event-reporting.md) — reports operational cgroup outcomes beyond local metric polling.
- [Agent Logging Service](agent-logging-service.md) — provides local diagnostics and rate-limited warnings for tracking failures.
- [Periodic Operation Runner](../L1-conceptual/periodic-operation-runner.md) — supplies the recurring execution model used to poll tracked resource usage.
