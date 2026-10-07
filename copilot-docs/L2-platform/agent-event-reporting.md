# Agent Event Reporting


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/agent-event-reporting.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** Agent subsystems report operational outcomes through `add_event` and `WALAEventOperation`, while `SendTelemetryEventsHandler` batches queued records and sends them through the active protocol. This shared path makes provisioning, updates, extensions, networking, policy, and diagnostics observable without coupling those components to the telemetry transport.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/agent-event-reporting.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The agent performs long-running work across many independent subsystems. Failures and state transitions must be visible to Azure even when they occur outside the main goal-state loop, but each subsystem should not implement its own persistence, batching, or WireServer upload logic.

The event-reporting boundary separates those concerns:

- Producers identify the operation, outcome, message, and relevant context.
- The common event API normalizes records and supplies shared VM/protocol metadata.
- A dedicated Guest Agent handler controls batching and transport.
- Local logging remains available for diagnostics that should not become telemetry.

## What

### Shared reporting contract

`add_event` is the primary producer API. Callers classify records with `WALAEventOperation` rather than inventing operation names, and can report success, failure, duration, version, or diagnostic context as appropriate. `initialize_event_logger_vminfo_common_parameters_and_protocol` enriches events with VM identity and protocol data once that information is available.

Event reporting is intentionally cross-cutting. The source set includes these producer groups:

| Producer area | Representative operations |
|---|---|
| Agent lifecycle | Daemon startup, environment maintenance, Guest Agent loading, and fatal agent errors |
| Provisioning and resource disk | Provisioning duration/outcome, resource-disk activation, formatting, mounting, and swap |
| Agent update | Update selection, RSM and self-update attempts, version transitions, and failures |
| Extensions and cgroups | Process completion, timeout/throttling details, cgroup setup, and resource-controller diagnostics |
| Networking | Firewall setup/validation/persistence and MetadataServer migration cleanup |
| Goal state and policy | Extension configuration parsing, policy validation/enforcement, and remote-access processing |
| Diagnostics and trust | Log collection, signing-certificate creation, and related error conditions |

`WALAEventOperation` is the compatibility surface between producers and telemetry consumers. New operation values should be stable, specific enough to route or aggregate, and reused by all call sites representing the same activity.

### Delivery handler

`SendTelemetryEventsHandler` implements `ThreadHandlerInterface` and owns outbound event delivery. It obtains the current protocol from `protocol_util`, runs as the `SendTelemetryHandler` background worker, and balances prompt delivery with batching through:

- `_MAX_TIMEOUT`: bounds how long the worker waits for work.
- `_MIN_EVENTS_TO_BATCH`: allows immediate batching when queue volume is high.
- `_MIN_BATCH_WAIT_TIME`: gives low-volume events a short aggregation window.

The handler is lifecycle-managed like other Guest Agent workers: it can be started, checked for liveness, stopped, and restarted according to the thread-handler contract. `ServiceStoppedError` and send failures are reported explicitly instead of being converted into successful delivery.

## How

### End-to-end flow

1. A subsystem completes an operation or catches an operational failure.
2. It calls `add_event` with a `WALAEventOperation`, message, and outcome metadata.
3. Common event infrastructure enriches and stages the event independently of the producer's main control flow.
4. `SendTelemetryEventsHandler.run` waits for available telemetry, collecting a batch when volume or wait thresholds are met.
5. The handler uses the active protocol to send the batch to WireServer.
6. Delivery errors are logged/reported, while the worker lifecycle remains under Guest Agent supervision.

This design keeps producers transport-agnostic: update, firewall, provisioning, and extension code report facts but do not own endpoint selection or upload scheduling.

### Producer patterns

- **Report at an operation boundary.** Emit after the outcome and duration are known, not at every internal step.
- **Pair local logs with telemetry deliberately.** Use `logger` for detailed local diagnosis; use `add_event` for externally useful state and failures.
- **Normalize exception text.** Producers commonly use `ustr` or `textutil.format_exception` before adding exception details to messages.
- **Use bounded payloads.** Extension process output is constrained by `TELEMETRY_MESSAGE_MAX_LEN`; preserve truncation when including stdout or stderr.
- **Preserve outcome semantics.** Do not report success-shaped events from exception paths, and retain operation-specific error codes where available.
- **Avoid telemetry loops.** Sender failures should be handled through the established event/logging path without recursively generating unbounded send events.

### Initialization and shutdown

Event enrichment that depends on goal state or protocol identity must occur after protocol initialization. Daemon and log-collector entry points call `initialize_event_logger_vminfo_common_parameters_and_protocol` when enough VM information is available.

During shutdown, stop the telemetry handler through its `ThreadHandlerInterface` lifecycle. Producers should not assume an event is delivered synchronously merely because `add_event` returned.

### Change guidance

- Reuse an existing `WALAEventOperation` when the semantic operation already exists; add a new value only for a genuinely distinct reporting dimension.
- Keep producer calls outside tight loops unless rate limiting or deduplication is explicit.
- Preserve sender timeout and batching behavior when changing queue handling; low latency and bounded upload overhead are both intentional.
- Keep transport calls inside `SendTelemetryEventsHandler` or protocol abstractions, not in producer modules.
- Initialize shared VM/protocol fields before expecting fully enriched records.
- When changing extension process reporting, retain output length limits, timeout state, return/error codes, and CPU-throttling context.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Shared event API and operation taxonomy | `azurelinuxagent/common/event.py` | `add_event`; `WALAEventOperation`; `initialize_event_logger_vminfo_common_parameters_and_protocol`; `elapsed_milliseconds` |
| Telemetry dispatch worker | `azurelinuxagent/ga/send_telemetry_events.py` | `SendTelemetryEventsHandler`; `SendTelemetryEventsHandler.run`; `get_send_telemetry_events_handler` |
| Thread lifecycle contract | `azurelinuxagent/ga/interfaces.py` | `ThreadHandlerInterface` |
| Extension process result reporting | `azurelinuxagent/ga/extensionprocessutil.py` | `wait_for_process_completion_or_timeout`; `handle_process_completion`; `TELEMETRY_MESSAGE_MAX_LEN` |
| Cgroup diagnostics | `azurelinuxagent/ga/cgroupapi.py` | `log_cgroup_info`; `log_cgroup_warning`; `CGroupsTelemetry` |
| Agent update reporting | `azurelinuxagent/ga/agent_update_handler.py` | `AgentUpdateHandler`; `UpdateMode` |
| Update strategy reporting | `azurelinuxagent/ga/rsm_version_updater.py`; `azurelinuxagent/ga/self_update_version_updater.py` | `RSMVersionUpdater`; `SelfUpdateVersionUpdater`; `SelfUpdateType` |
| Guest Agent state and failures | `azurelinuxagent/ga/guestagent.py` | `GuestAgent`; `GuestAgentError`; `GuestAgentUpdateAttempt` |
| Firewall reporting | `azurelinuxagent/ga/firewall_manager.py`; `azurelinuxagent/ga/persist_firewall_rules.py` | `FirewallManager`; `IpTables`; `NfTables`; `PersistFirewallRulesHandler` |
| Provisioning and resource disk reporting | `azurelinuxagent/pa/provision/default.py`; `azurelinuxagent/daemon/resourcedisk/default.py` | `ProvisionHandler`; `ResourceDiskHandler` |
| Policy and remote-access reporting | `azurelinuxagent/ga/policy/policy_engine.py`; `azurelinuxagent/ga/remoteaccess.py` | `_PolicyEngine`; `RemoteAccessHandler` |
| Log-collection reporting | `azurelinuxagent/ga/logcollector.py` | Log collector entry points; `initialize_event_logger_vminfo_common_parameters_and_protocol` |

## Related Components

- [Thread Handler Contract](../L1-conceptual/thread-handler-contract.md) — defines how the Guest Agent starts, monitors, and stops `SendTelemetryEventsHandler`.
- [Periodic Operation Runner](../L1-conceptual/periodic-operation-runner.md) — provides timing and failure isolation for maintenance tasks that commonly emit events.
- [Protocol Data Contracts](../L1-conceptual/protocol-data-contracts.md) — defines telemetry event envelopes, schema field names, and protocol status records.
- [Goal-State Domain Models](../L1-conceptual/goal-state-domain-models.md) — supplies VM and goal-state identity used to enrich operational reporting.
- **Protocol transport** (`azurelinuxagent/common/protocol`) — provides the active channel used by the sender to upload telemetry.
