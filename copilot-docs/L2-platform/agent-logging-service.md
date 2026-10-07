# Agent Logging Service


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/agent-logging-service.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** The agent logging service centralizes formatted output, message throttling, prefixing, and sensitive SAS-token redaction. Platform code consumes its module-level logging API; cloud-init detection illustrates how provisioning diagnostics are routed through it.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/agent-logging-service.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Agent operations run continuously and across multiple platform paths, so diagnostics must be consistent without flooding logs or exposing credentials. The logging layer provides shared severity handling and time-based suppression, while callers retain enough context to explain platform decisions and failures.

## What

### Logging responsibilities

- `Logger` owns appenders, an optional prefix, silent-mode state, and the shared periodic-message timestamps.
- A child or facade logger can delegate periodic state through its `logger` reference, keeping throttling consistent across related logger instances.
- `set_prefix` adds component context without requiring each caller to alter every message.
- `reset_periodic` clears throttling history, allowing periodic messages to be emitted immediately again.
- `redact_sas_token` is applied by the logging path to prevent shared-access-signature credentials from reaching output.
- Module-level logging functions expose the service to callers that do not need to manage a `Logger` instance directly.

### Periodic logging

The module defines reusable intervals from one minute through one day:

`EVERY_MINUTE`, `EVERY_FIFTEEN_MINUTES`, `EVERY_HALF_HOUR`, `EVERY_HOUR`, `EVERY_SIX_HOURS`, `EVERY_HALF_DAY`, and `EVERY_DAY`.

`Logger._periodic` hashes the message format as its identity. It emits only when `Logger._is_period_elapsed` finds no prior timestamp or the requested UTC interval has elapsed, then records the new UTC timestamp. Arguments do not distinguish periodic messages that share the same format string.

### Provisioning diagnostics

Cloud-init detection uses the module-level `info` logger for expected platform uncertainty:

- `_cloud_init_is_enabled_systemd` checks `cloud-init-local.service` with `systemctl is-enabled`.
- `_cloud_init_is_enabled_service` probes the `cloud-init` and `cloudinit` service names on non-systemd systems.
- Failed probes are logged and treated as disabled for that probe.
- `cloud_init_is_enabled` combines both strategies and logs the final Boolean result.

## How

### Emission path

1. A caller invokes a module-level logging operation or a `Logger` severity method.
2. The logger formats the message with its arguments and component prefix.
3. Sensitive SAS-token material is redacted before output.
4. Unless silent mode suppresses output, configured appenders receive the message.
5. For periodic operations, emission occurs only after the selected interval has elapsed for the message-format hash.

### Working with periodic messages

- Reuse the interval constants rather than constructing ad hoc `timedelta` values.
- Keep format strings stable when repeated events should share one throttle window.
- Use distinct format strings when independently throttled events happen to use the same severity.
- Call `reset_periodic` only when intentionally restarting all periodic windows associated with the root logger.
- Remember that periodic state is based on `datetime.now(UTC)`, not local time.

### Failure semantics

Cloud-init detection is deliberately diagnostic rather than fatal. Command failures are logged with the exception text, then alternate detection is attempted. If neither systemd nor legacy service probing succeeds, the public result is `False`; consumers should not interpret a failed probe as an agent logging failure.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Logging service and periodic throttling | `azurelinuxagent/common/logger.py` | `Logger`; `Logger._periodic`; `Logger._is_period_elapsed`; `Logger.reset_periodic`; `Logger.set_prefix`; module-level `info` |
| Sensitive-value redaction | `azurelinuxagent/common/utils/textutil.py` | `redact_sas_token` |
| Cloud-init logging consumer | `azurelinuxagent/pa/provision/cloudinitdetect.py` | `cloud_init_is_enabled`; `_cloud_init_is_enabled_systemd`; `_cloud_init_is_enabled_service` |

## Related Components

- [Provision Handler Selection](../L1-conceptual/provision-handler-selection.md) — provisioning selects behavior based in part on whether cloud-init is available.
- [OS Service Management](../L1-conceptual/os-service-management.md) — cloud-init detection probes systemd and legacy service-management interfaces.
