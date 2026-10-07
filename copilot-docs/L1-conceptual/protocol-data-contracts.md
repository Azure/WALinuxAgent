# Protocol Data Contracts


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/protocol-data-contracts.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** Protocol data contracts are the agent's shared in-memory vocabulary for goal state, extension configuration, status reporting, updates, remote access, and telemetry. They keep wire parsing, orchestration, serialization, and event processing aligned without coupling consumers to raw XML, JSON, or Kusto column names.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/protocol-data-contracts.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The agent exchanges related data with several boundaries: Azure goal state, extension handlers, status endpoints, update orchestration, remote-access provisioning, and telemetry ingestion. Each boundary has stable field names and state semantics that must survive parsing, internal processing, and serialization.

These contracts centralize those semantics. Protocol objects model operational state, while telemetry schemas centralize externally visible event keys. Consumers can therefore work with typed object graphs and symbolic field names rather than duplicating payload shapes or string literals.

## What

### Protocol domain model

Most serializable protocol records inherit `DataContract`; repeated nested records use `DataContractList`. Plain model classes are used where behavior or internal state matters more than direct serialization.

| Contract area | Primary types | Responsibility |
|---|---|---|
| VM identity | `VMInfo` | Carries subscription, VM, role, instance, and tenant identity. |
| Agent manifests | `VMAgentFamily` | Describes an agent family, versions, package URIs, RSM flags, and GA-version signature mappings. |
| Extension intent | `ExtensionState`; `ExtensionRequestedState`; `Extension`; `ExtensionSettings` | Represents handler state, runtime settings, manifests, signatures, and dependency ordering. |
| Goal-state metadata | `InVMGoalStateMetaData` | Preserves sequence, creation, activity, and correlation identifiers from CRP. |
| Extension packages | `ExtHandlerPackage`; `ExtHandlerPackageList` | Models installable versions, URIs, internal-package flags, and major-upgrade constraints. |
| Provisioning and extension status | `ProvisionStatus`; `ExtensionSubStatus`; `ExtensionStatus`; `ExtHandlerStatus` | Builds nested status records reported to Azure. |
| VM agent status | `VMAgentStatus`; `VMStatus`; `GoalStateAggregateStatus`; `VMArtifactsAggregateStatus` | Reports agent/platform details, extension handlers, aggregate goal-state processing, updates, and FastTrack support. |
| Remote access | `RemoteAccessUser`; `RemoteAccessUsersList` | Carries encrypted temporary-user requests. |
| Agent update status | `VMAgentUpdateStatuses`; `VMAgentUpdateStatus` | Describes expected version and update outcome. |

`VERSION_0` is the fallback protocol version. `VMAgentStatus` captures hostname, current agent version, distribution name/version, and initializes its extension-handler list and aggregate status.

### State and ordering semantics

- `ExtensionRequestedState` is the handler-level CRP intent: `enabled`, legacy `disabled`, or `uninstall`.
- `ExtensionState` is the per-configuration runtime state: `enabled` or `disabled`.
- `ExtensionSettings.dependency_level_sort_key()` orders enabled work by increasing dependency level, but disabled/uninstall work in reverse order.
- `Extension.dependency_level_sort_key()` derives a handler key from its lowest settings dependency and reverses it when the handler is not enabled.
- `Extension.is_invalid_setting` and `invalid_setting_reason` carry validation failure state without discarding the parsed handler.
- `VMAgentFamily` deliberately distinguishes absent values (`None`) from explicit booleans and uses an empty mapping when no signature mapping is supplied.
- `GoalStateAggregateStatus.processed_time` is fixed when the object is created, so serialization reports when processing completed rather than when status is uploaded.

### Telemetry contracts

Telemetry schema classes are namespaces for exact external field names:

| Schema | Adds |
|---|---|
| `CommonTelemetryEventSchema` | Process/thread, agent version, container, task/opcode/keyword, OS/execution mode, resources, and Azure VM identity fields. |
| `GuestAgentGenericLogsSchema` | Event name, capability, and three generic context fields. |
| `GuestAgentExtensionEventsSchema` | Extension identity, version, operation, success, message, and duration. |
| `GuestAgentPerfCounterEventsSchema` | Category, counter, instance, and value. |

`TelemetryEvent` is the event envelope: `eventId`, `providerId`, a `DataContractList` of `TelemetryEventParam`, and a `file_type`. It supports parameter-name membership checks, extracts the extension version, and classifies an event as extension-originated when its `Name` parameter exists and differs from the agent name.

## How

### Protocol lifecycle

1. Protocol adapters parse XML or JSON and instantiate these records.
2. Goal-state and extension orchestration consume `Extension`, `ExtensionSettings`, agent-family, and metadata objects.
3. Dependency sort keys determine safe enable versus disable/uninstall ordering.
4. Provisioning, extension, aggregate, and update results are assembled into nested status contracts.
5. The data-contract serializer emits the object graph expected by Azure.

### Telemetry lifecycle

1. Producers select names from the appropriate schema instead of spelling external keys locally.
2. Each name/value pair becomes a `TelemetryEventParam`.
3. Parameters are appended to `TelemetryEvent.parameters`.
4. Telemetry processing uses `TelemetryEvent.__contains__()`, `is_extension_event()`, and `get_version()` for routing and enrichment.
5. The event contract is serialized or transformed for the corresponding Guest Agent telemetry table.

### Change rules

- Treat attribute names, schema-key values, state strings, and list nesting as wire contracts; rename only with coordinated producer and consumer changes.
- Use `DataContractList(ElementType)` for serializable repeated children so element typing survives object construction and serialization.
- Preserve `None` versus `False` and empty collection semantics; they represent absent, explicit, and initialized states differently.
- Update both dependency sort functions when changing extension ordering semantics.
- Add shared telemetry fields to `CommonTelemetryEventSchema`; add table-specific fields only to the matching derived schema.
- Keep `TelemetryEvent.is_extension_event()` aligned with the agent-name convention used by telemetry producers.
- Do not put transport parsing into these records; protocol adapters should construct the domain objects.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Protocol and status contracts | `azurelinuxagent/common/protocol/restapi.py` | `VMInfo`; `VMAgentFamily`; `Extension`; `ExtensionSettings`; `InVMGoalStateMetaData`; `ExtHandlerPackage`; `ExtensionStatus`; `ExtHandlerStatus`; `VMAgentStatus`; `VMStatus`; `GoalStateAggregateStatus`; `RemoteAccessUser`; `VMAgentUpdateStatus` |
| Telemetry schemas and event envelope | `azurelinuxagent/common/telemetryevent.py` | `CommonTelemetryEventSchema`; `GuestAgentGenericLogsSchema`; `GuestAgentExtensionEventsSchema`; `GuestAgentPerfCounterEventsSchema`; `TelemetryEventParam`; `TelemetryEvent`; `TelemetryEvent.is_extension_event`; `TelemetryEvent.get_version` |
| Serialization primitives | `azurelinuxagent/common/datacontract.py` | `DataContract`; `DataContractList` |

## Related Components

- [Goal-State Domain Models](goal-state-domain-models.md) — normalize WireServer and HostGAPlugin payloads into these REST protocol objects.
- [Extension Goal State Factory](extension-goal-state-factory.md) — selects the source-specific adapter that constructs extension contracts.
- [Agent Feature Capabilities](agent-feature-capabilities.md) — publishes supported features through VM status and validates goal-state requirements.
- **Wire protocol and status serialization** (`azurelinuxagent/common/protocol/wire.py`) — parses protocol payloads and emits the status object graph.
- **Extension handling** (`azurelinuxagent/ga/exthandlers.py`) — consumes extension intent, settings, ordering, and status contracts.
- **Telemetry collection** (`azurelinuxagent/ga/collect_telemetry_events.py`) — routes and uploads events represented by the telemetry contracts.
