# Cgroup Resource Governance


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/cgroup-resource-governance.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `CGroupConfigurator` places the agent, extensions, and log collector under systemd cgroup slices with CPU and memory controls. `MonitorHandler` then polls tracked cgroups for usage and containment violations, while log collection is enabled only when the platform can enforce its resource limits.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/cgroup-resource-governance.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Extension handlers and diagnostic collection execute beside the Guest Agent but must not be able to consume unbounded host resources or interfere with agent health. Resource governance therefore needs one boundary for configuring cgroups, another for deciding whether optional work is safe to run, and a monitoring path that turns runtime usage and violations into diagnostics.

This separation provides:

- Stable systemd slice ownership for the agent and extension processes.
- CPU and memory controllers selected through the active cgroup API.
- Explicit failure and telemetry paths when cgroups cannot be configured.
- Bounded log collection rather than unrestricted diagnostic work.
- Periodic resource metrics and detection of unexpected processes in the agent cgroup.

## What

### Cgroup configuration

`CGroupConfigurator` is the central setup and policy surface. It uses `create_cgroup_api` to select the supported cgroup implementation, then coordinates `CGroupUtil`, `SystemdCgroupApiv2`, `_CpuController`, and `_MemoryController`.

The systemd hierarchy is rooted at `AZURE_SLICE` (`azure.slice`). Extension workloads are grouped beneath the VM extensions slice derived from `EXTENSION_SLICE_PREFIX`; the generated slice-unit contents establish ordering before `slices.target`. Extension execution and completion handling can then associate resource-controller diagnostics with the relevant process outcome.

Configuration failures remain explicit. `InvalidCgroupMountpointException`, `SystemdRunError`, `CGroupsException`, and `AgentMemoryExceededException` distinguish unsupported layout, launch, controller, and memory-limit failures. `log_cgroup_info`, `log_cgroup_warning`, `CGroupsTelemetry`, and `add_event` expose setup and runtime outcomes without hiding errors behind a success path.

### Governed log collection

`CollectLogsHandler` runs log collection only when all required conditions are met:

- Periodic collection is enabled by configuration.
- The host uses cgroups for service management.
- The agent supports the resource-limiting behavior required by the detected cgroup version.

The handler obtains limits from `CGroupConfigurator`. Anonymous and cache memory limits apply to cgroup v1 and v2, while the v2 throttling threshold bounds repeated throttling events. Collection still uses the normal thread-handler lifecycle and reports command failures, elapsed time, archive outcome, and graceful-kill failures through the established logging and event paths.

### Runtime monitoring

`MonitorHandler` owns recurring health and telemetry work. Its `PollResourceUsage` operation:

- Polls resource usage for cgroups registered with `CGroupsTelemetry`.
- Reports measurements through `MetricValue`, `MetricsCategory`, `MetricsCounter`, and `report_metric`.
- Checks whether processes that do not belong to the agent have entered its cgroup.
- Routes cgroup warnings and operational failures through agent telemetry.

`PollResourceUsage` extends `PeriodicOperation`, so polling uses the common periodic scheduling and failure-isolation contract rather than a dedicated loop. The containing monitor follows `ThreadHandlerInterface` for start, liveness, stop, and restart behavior.

## How

### Governance flow

1. `CGroupConfigurator` detects systemd/cgroup support and creates the appropriate cgroup API.
2. It establishes `azure.slice` and the VM extensions slice, then wires CPU and memory controllers.
3. Agent and extension processes are assigned to their intended cgroups; process completion preserves controller and throttling diagnostics.
4. `CGroupsTelemetry` tracks governed cgroups and their metric counters.
5. `MonitorHandler` schedules `PollResourceUsage`, which samples usage, reports metrics, and verifies agent-cgroup membership.
6. `CollectLogsHandler` checks platform support before starting collection and applies the configured memory and throttling limits.
7. Setup, enforcement, or polling failures are logged and emitted under the appropriate `WALAEventOperation`.

### Change guidance

- Keep cgroup-version and systemd capability checks centralized in `CGroupConfigurator` and the cgroup API; consumers should not duplicate mount-layout detection.
- Preserve the `azure.slice` and extension-slice hierarchy when changing unit contents or process placement.
- Treat resource enforcement as a prerequisite for periodic log collection; do not silently run it unbounded when cgroup setup fails.
- Add resource measurements through `CGroupsTelemetry` and the existing metric types so monitor reporting remains uniform.
- Preserve explicit exception and event semantics for invalid mount points, systemd launch failures, memory exhaustion, and throttling.
- Keep polling in `PeriodicOperation` and worker lifecycle control in `ThreadHandlerInterface`.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Cgroup setup and resource policy | `azurelinuxagent/ga/cgroupconfigurator.py` | `CGroupConfigurator`; `AZURE_SLICE`; `_VMEXTENSIONS_SLICE`; log-collector limit constants |
| Cgroup API and systemd integration | `azurelinuxagent/ga/cgroupapi.py` | `CGroupUtil`; `SystemdCgroupApiv2`; `create_cgroup_api`; `SystemdRunError`; `InvalidCgroupMountpointException` |
| CPU and memory enforcement | `azurelinuxagent/ga/cpucontroller.py`; `azurelinuxagent/ga/memorycontroller.py` | `_CpuController`; `_MemoryController` |
| Resource metrics model | `azurelinuxagent/ga/cgroupcontroller.py` | `MetricValue`; `MetricsCategory`; `MetricsCounter`; `AGENT_NAME_TELEMETRY` |
| Tracked-cgroup telemetry | `azurelinuxagent/ga/cgroupstelemetry.py` | `CGroupsTelemetry` |
| Governed log collection | `azurelinuxagent/ga/collect_logs.py` | `CollectLogsHandler`; `get_collect_logs_handler`; `is_log_collection_allowed` |
| Resource polling and health monitoring | `azurelinuxagent/ga/monitor.py` | `MonitorHandler`; `PollResourceUsage`; `get_monitor_handler` |
| Extension process outcomes | `azurelinuxagent/ga/extensionprocessutil.py` | `handle_process_completion` |
| Governance exceptions | `azurelinuxagent/common/exception.py` | `CGroupsException`; `AgentMemoryExceededException`; `ExtensionErrorCodes` |
| Worker and scheduling contracts | `azurelinuxagent/ga/interfaces.py`; `azurelinuxagent/ga/periodic_operation.py` | `ThreadHandlerInterface`; `PeriodicOperation` |

## Related Components

- [Thread Handler Contract](../L1-conceptual/thread-handler-contract.md) — defines lifecycle management for monitor and log-collection workers.
- [Periodic Operation Runner](../L1-conceptual/periodic-operation-runner.md) — schedules and isolates recurring resource polling.
- [Agent Event Reporting](agent-event-reporting.md) — carries cgroup setup, throttling, process, and monitoring outcomes.
- [Agent Logging Service](agent-logging-service.md) — records local cgroup and log-collection diagnostics.
