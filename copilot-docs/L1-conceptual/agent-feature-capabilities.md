# Agent Feature Capabilities


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/agent-feature-capabilities.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** The agent keeps a small, centralized capability registry and publishes different feature sets to Azure CRP and extension processes. Protocol, extension, telemetry, and update components consume that registry to advertise support, reject incompatible goal states, and enable capability-dependent behavior.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/agent-feature-capabilities.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Feature capabilities form a compatibility contract between the Linux Guest Agent and external actors:

- **CRP** needs to know which control-plane behaviors the running agent supports.
- **Extensions** need to know which host-provided facilities they may use.
- **Goal-state processing** must fail predictably when required capabilities are unavailable.
- **Agent subsystems** need one authoritative switch for capability-dependent behavior.

Keeping names, versions, and support state in one registry prevents protocol payloads, extension environments, and internal behavior from drifting apart.

## What

### Capability model

`AgentSupportedFeature` is an immutable value object exposing a capability's `name`, protocol `version`, and `is_supported` state. `SupportedFeatureNames` defines the wire-visible identifiers.

| Capability | Published to | Meaning and gating |
|---|---|---|
| `MultipleExtensionsPerHandler` (`MultiConfig`) | CRP | Always advertises support for multiple extension configurations per handler. |
| `ExtensionTelemetryPipeline` | Extensions | Always advertises the extension telemetry facility and gates telemetry collection/setup. |
| `VersioningGovernance` (`GAVersioningGovernance`) | CRP | Advertised only when update-to-latest and GA versioning configuration are both enabled. |
| `FastTrack` | CRP status only | Added dynamically when the current VM status reports FastTrack support; it is not stored in either registry. |

The registry deliberately separates two audiences:

- `get_agent_supported_features_list_for_crp()` returns supported control-plane capabilities.
- `get_agent_supported_features_list_for_extensions()` returns supported extension-facing capabilities.
- `get_supported_feature_by_name()` resolves a known capability from either registry and raises `NotImplementedError` for unknown names.

### Consumers and responsibilities

| Consumer | Capability use |
|---|---|
| Wire status serialization | Converts CRP capabilities to `{"Key": name, "Value": version}` entries in `supportedFeatures`; appends FastTrack from runtime VM status. |
| Extension goal-state handler | Compares goal-state `required_features` against CRP-advertised names and fails the aggregate goal state before extension processing when any are unsupported. |
| Extension command launcher | Serializes extension-facing capabilities into the `ExtensionSupportedFeatures` environment variable. |
| Telemetry collector | Adds extension-event processing to its periodic work only when `ExtensionTelemetryPipeline` is supported. |
| Update handler | Reports version-governance configuration state and rebuilds extension handler environments so telemetry capability changes take effect after startup/update. |

## How

### Publication path

1. Concrete feature classes instantiate stable name/version/support triples.
2. Private CRP and extension registries assign each feature to its intended audience.
3. Registry accessors filter out unsupported entries and apply configuration gates.
4. `vm_status_to_v1()` serializes CRP features into the status payload; FastTrack is derived separately from `vmAgent.supports_fast_track`.
5. `ExtHandlerInstance.run_cmd()` serializes extension features into the child process environment.

### Enforcement path

Before handling extensions, `ExtHandlersHandler.__get_unsupported_features()` reads the extension goal state's required features and compares them with the CRP registry. If any requirement is absent, extension processing is skipped and the goal state is reported failed with `GoalStateUnsupportedRequiredFeatures`.

This comparison is name-based: the registry's dictionary keys are the compatibility boundary. Renaming a feature therefore changes the external contract.

### Runtime activation

Capability advertisement and behavior activation use the same registry:

- `CollectTelemetryEventsHandler.daemon()` starts `_ProcessExtensionEvents` only when the telemetry feature is enabled.
- `ExtHandlerInstance.create_handler_env()` and command execution expose the telemetry contract to extensions.
- `UpdateHandler._ensure_extension_telemetry_state_configured_properly()` recreates handler environments for installed extensions, aligning their runtime configuration with the current capability state.
- `UpdateHandler._emit_changes_in_default_configuration()` detects when GA versioning is not being advertised and emits a configuration event.

### Change rules

When adding or changing a capability:

1. Define its external name in `SupportedFeatureNames` and represent it with `AgentSupportedFeature`.
2. Place it in exactly the registry matching its consumer: CRP or extensions.
3. Add configuration gating in the accessor, not independently in each publisher.
4. Wire behavior checks through `get_supported_feature_by_name()` so advertised support and runtime activation remain consistent.
5. Preserve existing wire names and versions unless the external compatibility contract intentionally changes.
6. Treat FastTrack as a special runtime status capability unless its protocol ownership is redesigned.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Capability definitions and registries | `azurelinuxagent/common/agent_supported_feature.py` | `SupportedFeatureNames`; `AgentSupportedFeature`; `_MultiConfigFeature`; `_ETPFeature`; `_GAVersioningGovernanceFeature`; `get_supported_feature_by_name()`; `get_agent_supported_features_list_for_crp()`; `get_agent_supported_features_list_for_extensions()` |
| CRP status publication | `azurelinuxagent/common/protocol/wire.py` | `vm_status_to_v1()`; `WireProtocol`; `StatusBlob` |
| Telemetry activation | `azurelinuxagent/ga/collect_telemetry_events.py` | `CollectTelemetryEventsHandler.daemon()`; `_ProcessExtensionEvents`; `_CollectAndEnqueueEvents` |
| Goal-state enforcement and extension publication | `azurelinuxagent/ga/exthandlers.py` | `ExtHandlersHandler.__get_unsupported_features()`; `ExtHandlerInstance.run_cmd()`; `ExtHandlerInstance.create_handler_env()`; `ExtCommandEnvVariable` |
| Update/startup reconciliation | `azurelinuxagent/ga/update.py` | `UpdateHandler._emit_changes_in_default_configuration()`; `UpdateHandler._ensure_extension_telemetry_state_configured_properly()` |

## Related Components

- **Goal-state and protocol contracts** (`azurelinuxagent/common/protocol/`) supply required-feature declarations and carry advertised capabilities to Azure.
- **Extension handling** (`azurelinuxagent/ga/exthandlers.py`) enforces required capabilities and exposes extension-facing features.
- **Telemetry and event reporting** (`azurelinuxagent/ga/collect_telemetry_events.py`, `azurelinuxagent/common/event.py`) activate the extension telemetry pipeline and report failures or configuration changes.
- **Periodic operations and thread lifecycle** (`azurelinuxagent/ga/periodic_operation.py`, `azurelinuxagent/ga/interfaces.py`) provide the execution framework for capability-gated telemetry work.
- **Update and resource governance** (`azurelinuxagent/ga/update.py`, `azurelinuxagent/ga/cgroupconfigurator.py`) reconcile capability-dependent runtime state during agent startup and update.
