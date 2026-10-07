# Platform Error Handling


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/platform-error-handling.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** WALinuxAgent uses typed exceptions to preserve the failing platform boundary—configuration, protocol, network, OS, storage, cgroups, crypto, update, or provisioning—while callers decide whether to retry, report, degrade, or terminate. Keep errors explicit and translate low-level failures only at the boundary that can add actionable context.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/platform-error-handling.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The agent crosses unreliable and platform-specific boundaries: configuration files, OVF and metadata documents, WireServer and IMDS HTTP calls, shell commands, OpenSSL, cgroup files, resource disks, and distribution services. A generic failure would lose the distinction between malformed input, a transient service outage, an unsupported platform, and an intentional process exit.

The error model provides:

- A common `AgentError` base with consistent type-prefixed messages and optional inner-error context.
- Domain exceptions that let orchestration code choose retry, telemetry, fallback, or fatal behavior.
- Explicit process-control exceptions separate from ordinary recoverable failures.
- Boundary-local logging and event reporting without converting failure into false success.
- Stable contracts across distribution adapters and protocol clients.

## What

### Exception families

| Family | Representative types | Meaning and expected handling |
|---|---|---|
| Process control | `ExitException`, `AgentUpgradeExitException` | Intentional agent termination; derives from `BaseException` so broad `Exception` handlers do not swallow it. |
| Agent lifecycle | `AgentError`, `AgentMemoryExceededException`, `AgentNetworkError`, `AgentUpdateError`, `AgentFamilyMissingError` | Agent-wide operational failures; retain the specific subtype for policy and telemetry. |
| Configuration and provisioning | `AgentConfigError`, `ProvisionError` | Invalid configuration or inability to complete provisioning; report with provisioning context. |
| Protocol and data | `ProtocolError` | Missing, malformed, or type-invalid host/guest data, including OVF and data-contract fields. |
| HTTP and service state | `HttpError`, `ResourceGoneError`, `InvalidContainerError` | Transport/status failures with special handling for retryable, throttled, or expired resources. |
| Platform operations | `OSUtilError`, `DhcpError`, `ResourceDiskError` | Host command, network bootstrap, or resource-disk failures scoped to the active platform adapter. |
| Security operations | `CryptError` | Certificate, key, hashing, or secret-decryption failure. |
| Resource governance | `CGroupsException` | Invalid cgroup layout, inaccessible counters, or failed resource-control operations. |

`AgentError` formats the concrete exception type into the message and can append an inner error. Preserve that behavior when wrapping lower-level failures so logs remain searchable by domain.

### Validation boundaries

Validation fails close to input:

- `ConfigurationProvider.load` raises `AgentConfigError` for empty configuration; typed getters reject malformed values rather than silently coercing them.
- `validate_param` and `set_properties` raise `ProtocolError` when data-contract shapes or field types do not match.
- `OvfEnv` and `_validate_ovf` reject absent or invalid provisioning data with `ValueError` or `ProtocolError`.
- `Observation` rejects missing required health fields before serialization.
- IMDS parsing separates successful metadata, service errors, connection errors, and internal failures through `MetadataResult`.

Unknown data-contract properties are warnings for forward compatibility; invalid known-property types remain errors.

### Recovery and translation

Recovery is owned by the layer with enough policy context:

| Boundary | Recovery contract |
|---|---|
| HTTP | `restutil` classifies status codes and transport exceptions, applies bounded retry/throttle delays, and raises typed HTTP/resource exceptions after policy is exhausted. |
| IMDS and health reporting | Clients convert HTTP failures into service-specific results or `HttpError`; callers decide whether metadata or health publication is optional. |
| DHCP | `DhcpHandler` waits for network readiness, discovers the WireServer endpoint, and raises `DhcpError` when bootstrap cannot continue. |
| OS adapters | Platform implementations may return command status, suppress a documented non-fatal command error, retry a known transient condition, or raise `OSUtilError`; preserve each method's contract. |
| Crypto | `CryptUtil` adds certificate/key operation context and raises `CryptError` where cryptographic output cannot be trusted. |
| Resource disk | Platform handlers reject unsupported filesystems, missing topology, and mount failures with `ResourceDiskError`. |
| Cgroups | Controllers distinguish missing optional counters from invalid or unusable cgroups; governance failures are logged and reported through cgroup telemetry. |
| Agent update | `GAVersionUpdater` raises `AgentUpdateError` for invalid update state while signature-validation failures retain their specialized types. |
| Provisioning | `CloudInitProvisionHandler.run` reports failure duration and readiness state, translating provisioning/protocol failures at the workflow boundary. |

### Observability

Handling an exception does not end its diagnostic lifecycle. Boundary code uses `logger`, `add_event`, `WALAEventOperation`, health observations, and subsystem telemetry to preserve operation, duration, and failure context. Recoverable failures should be visible at an appropriate severity; terminal failures should retain their original type and cause.

## How

### Failure flow

1. Validate external data or platform prerequisites at entry.
2. Raise the narrowest domain exception that describes the failed boundary.
3. Attach the original failure as inner context when translation adds useful domain meaning.
4. Let the policy-owning caller classify the error as retryable, degradable, reportable, or fatal.
5. Apply only bounded, subsystem-defined retries.
6. Log or emit an event once at the layer that knows the operation and outcome.
7. Re-raise terminal failures; never return a success-shaped value after an unhandled boundary failure.

### Change guidance

- Add new exceptions under the nearest existing family; avoid generic `Exception` when callers need policy decisions.
- Do not catch `BaseException`; `ExitException` must remain able to terminate or restart the process.
- Preserve inner-error context through the `AgentError` constructor when translating command, parse, or transport failures.
- Keep retry classification centralized in `restutil` or the owning subsystem; do not introduce unbounded retries in callers.
- Distinguish unsupported capability from transient failure. A documented no-op or warning is valid only when the platform contract explicitly permits it.
- Preserve forward-compatible warnings for unknown data-contract fields, but fail malformed known fields.
- Avoid duplicate telemetry at every stack frame; report where operation name, duration, and final outcome are known.
- Keep platform-specific command and return-code behavior in OS/resource-disk adapters rather than normalizing away meaningful differences.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Exception taxonomy and message wrapping | `azurelinuxagent/common/exception.py` | `ExitException`; `AgentUpgradeExitException`; `AgentError`; domain exception subclasses |
| Configuration validation | `azurelinuxagent/common/conf.py` | `ConfigurationProvider`; `ConfigurationProvider.load`; `ConfigurationProvider.get_switch`; `ConfigurationProvider.get_int` |
| Data-contract validation | `azurelinuxagent/common/datacontract.py` | `DataContract`; `DataContractList`; `validate_param`; `set_properties` |
| HTTP classification and retries | `azurelinuxagent/common/utils/restutil.py` | `HttpError`; `ResourceGoneError`; retry/status-code policies |
| IMDS result translation | `azurelinuxagent/common/protocol/imds.py` | `ImdsClient`; `MetadataResult`; `get_imds_client` |
| Health-report validation | `azurelinuxagent/common/protocol/healthservice.py` | `Observation`; `HealthService` |
| OVF validation | `azurelinuxagent/common/protocol/ovfenv.py` | `OvfEnv`; `OvfEnv.parse`; `_validate_ovf` |
| DHCP bootstrap failures | `azurelinuxagent/common/dhcp.py` | `DhcpHandler`; `DhcpHandler.run`; `DhcpHandler.send_dhcp_req` |
| OS operation errors | `azurelinuxagent/common/osutil/default.py` | `DefaultOSUtil`; `DefaultOSUtil._run_command_without_raising` |
| Cryptographic failures | `azurelinuxagent/common/utils/cryptutil.py` | `CryptUtil`; `CryptUtil.gen_transport_cert`; `CryptUtil.decrypt_secret` |
| Resource-disk platform failures | `azurelinuxagent/daemon/resourcedisk/freebsd.py`; `azurelinuxagent/daemon/resourcedisk/openbsd.py`; `azurelinuxagent/daemon/resourcedisk/openwrt.py` | `FreeBSDResourceDiskHandler`; `OpenBSDResourceDiskHandler`; `OpenWRTResourceDiskHandler` |
| Cgroup failures and metrics | `azurelinuxagent/ga/cgroupcontroller.py`; `azurelinuxagent/ga/cpucontroller.py`; `azurelinuxagent/ga/memorycontroller.py` | `_CgroupController`; `_CpuController`; `_MemoryController`; `CounterNotFound` |
| Update error policy | `azurelinuxagent/ga/ga_version_updater.py` | `GAVersionUpdater`; `GAVersionUpdater.is_update_allowed_this_time` |
| Provisioning failure reporting | `azurelinuxagent/pa/provision/cloudinit.py` | `CloudInitProvisionHandler`; `CloudInitProvisionHandler.run` |

## Related Components

- [Agent Event Reporting](agent-event-reporting.md) — emits operation-level failure and recovery telemetry.
- [Agent Logging Service](agent-logging-service.md) — records local exception and retry diagnostics.
- [Cgroup Resource Governance](cgroup-resource-governance.md) — applies cgroup-specific enforcement and failure reporting.
- [Distribution OS Adapters](distribution-os-adapters.md) — preserves platform-specific command and error semantics.
- [Network Route Utilities](network-route-utilities.md) — models strict route-data conversion used by network diagnostics.
