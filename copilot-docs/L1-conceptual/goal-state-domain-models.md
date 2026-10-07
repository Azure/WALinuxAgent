# Goal-State Domain Models


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/goal-state-domain-models.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** The goal-state model gives extension handling one source-independent contract for empty, WireServer `ExtensionsConfig`, and HostGAPlugin `vmSettings` state. It preserves source identity and tracing metadata while normalizing extensions, agent manifests, status upload details, feature requirements, and Confidential VM capabilities.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/goal-state-domain-models.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Azure can deliver extension configuration through the legacy WireServer path or the HostGAPlugin FastTrack path. Their payload formats and identifiers differ, but extension orchestration must consume the same concepts without branching on XML versus JSON throughout the agent.

These models create that compatibility boundary. They also retain enough provenance to detect stale state, correlate operations, upload status correctly, redact diagnostics, and gate features that depend on HostGAPlugin or Confidential VM support.

## What

### Unified contract

`ExtensionsGoalState` defines the fields and behaviors expected by downstream extension processing:

| Concern | Contract |
|---|---|
| Identity and ordering | `id`, `svd_sequence_number`, `created_on_timestamp`, `is_outdated` |
| Provenance | `channel`, `source`, `activity_id`, `correlation_id` |
| Agent and extension policy | `required_features`, `on_hold`, `agent_families`, `extensions` |
| Status reporting | `status_upload_blob`, `status_upload_blob_type` |
| Safe diagnostics | `get_redacted_text()` |
| Confidential VM support | `supports_encoded_signature()`, `supports_agent_signature_mapping()` |

`GoalStateChannel` records the transport (`WireServer`, `HostGAPlugin`, or `Empty`), while `GoalStateSource` records the origin (`Fabric`, `FastTrack`, or `Empty`). Keep these dimensions distinct: a HostGAPlugin payload can describe state originating from Fabric or FastTrack.

### Concrete representations

| Representation | Identity | Behavior |
|---|---|---|
| `EmptyExtensionsGoalState` | `incarnation_<n>` | Immutable neutral object with empty collections, zero GUIDs, no status endpoint, and no signature support. |
| `ExtensionsGoalStateFromExtensionsConfig` | Incarnation-based | Adapts WireServer XML and wire-client resources to the common contract. |
| `ExtensionsGoalStateFromVmSettings` | `etag_<etag>` | Parses HostGAPlugin JSON into REST domain objects and retains ETag, schema version, HGAP version, and correlation metadata. |

`ExtensionsGoalStateFactory` is the only construction boundary. It selects the empty, ExtensionsConfig-backed, or VM settings-backed implementation without taking ownership of source-specific parsing.

### Shared runtime context

`AgentGlobals` stores process-wide values learned during goal-state processing. The current container ID is refreshed with goal state so telemetry uses current VM context. Confidential VM state starts uninitialized; `get_is_cvm()` fails until `ConfidentialVMInfo` explicitly initializes it, preventing an unknown value from being treated as `False`.

## How

### Acquisition and normalization

1. `WireProtocol.detect()` and `WireClient.update_goal_state()` acquire current protocol state and update HostGAPlugin context.
2. The protocol chooses the matching `ExtensionsGoalStateFactory` method for absent configuration, ExtensionsConfig XML, or `vmSettings` JSON.
3. The concrete model parses its payload and exposes the common `ExtensionsGoalState` contract.
4. `ExtensionsGoalStateFromVmSettings._parse_vm_settings()` reads scalar metadata, status upload configuration, required features, agent manifests, and extension definitions.
5. `_CaseFoldedDict` makes JSON object-key lookup case-insensitive while parsed handlers and settings become `VMAgentFamily`, `Extension`, and `ExtensionSettings` domain objects.
6. `ExtensionsGoalState._do_common_validations()` normalizes an invalid status blob type to `BlockBlob`; missing IDs and timestamps become stable zero/minimum defaults.
7. Consumers use the normalized model for extension sequencing, required-feature checks, agent updates, and status publication.

### Freshness and fallback

`is_outdated` marks a previously fetched state that must no longer drive extension processing, such as when FastTrack support disappears and acquisition falls back to WireServer. Compare goal states by their source-specific identity and sequence metadata rather than assuming ETags and incarnations are interchangeable.

### Validation, privacy, and capability gates

- Malformed `vmSettings` raises `VmSettingsParseError` with the ETag and redacted payload context.
- `get_redacted_text()` removes status-upload query credentials and extension protected settings before diagnostics or events are emitted.
- VM settings support for encoded extension signatures and agent signature mappings requires both Confidential VM context and the relevant minimum HostGAPlugin version.
- Parsing and fallback failures are reported through `add_event()` and `WALAEventOperation`; event reporting is an integration surface, not part of the domain contract.

### Change rules

- Add common consumer-facing fields to `ExtensionsGoalState` and implement them consistently in every concrete representation.
- Keep XML and JSON parsing inside their concrete adapters; do not leak payload-shape checks into extension handlers.
- Construct models through `ExtensionsGoalStateFactory`.
- Preserve redaction when adding secrets or credential-bearing URLs.
- Treat channel, source, identity, sequence, and correlation fields as protocol semantics, not interchangeable labels.
- Update HGAP version thresholds and Confidential VM checks together when introducing signature-dependent fields.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Common goal-state contract and empty model | `azurelinuxagent/common/protocol/extensions_goal_state.py` | `GoalStateChannel`; `GoalStateSource`; `VmSettingsParseError`; `ExtensionsGoalState`; `EmptyExtensionsGoalState` |
| VM settings adapter and parser | `azurelinuxagent/common/protocol/extensions_goal_state_from_vm_settings.py` | `ExtensionsGoalStateFromVmSettings`; `_CaseFoldedDict`; `ExtensionsGoalStateFromVmSettings._parse_vm_settings`; `ExtensionsGoalStateFromVmSettings.get_redacted_text` |
| ExtensionsConfig adapter | `azurelinuxagent/common/protocol/extensions_goal_state_from_extensions_config.py` | `ExtensionsGoalStateFromExtensionsConfig` |
| Construction boundary | `azurelinuxagent/common/protocol/extensions_goal_state_factory.py` | `ExtensionsGoalStateFactory`; `ExtensionsGoalStateFactory.create_empty`; `ExtensionsGoalStateFactory.create_from_extensions_config`; `ExtensionsGoalStateFactory.create_from_vm_settings` |
| Goal-state acquisition and fallback | `azurelinuxagent/common/protocol/wire.py` | `WireProtocol`; `WireClient`; `WireProtocol.detect`; `WireClient.update_goal_state`; `WireClient.update_host_plugin_from_goal_state` |
| Process-wide goal-state context | `azurelinuxagent/common/AgentGlobals.py` | `AgentGlobals`; `AgentGlobals.get_container_id`; `AgentGlobals.update_container_id`; `AgentGlobals.get_is_cvm`; `AgentGlobals.update_is_cvm` |
| Parse and protocol event reporting | `azurelinuxagent/common/event.py` | `WALAEventOperation`; `EventLogger`; `LogEvent`; `add_event`; `report_event` |

## Related Components

- [Extension Goal State Factory](extension-goal-state-factory.md) — focused construction map for all concrete goal-state representations.
- [Agent Feature Capabilities](agent-feature-capabilities.md) — defines the required-feature contract enforced against normalized goal state.
- **REST API domain objects** (`azurelinuxagent/common/protocol/restapi.py`) — hold parsed agent-family, extension, settings, and requested-state values.
- **HostGAPlugin protocol** (`azurelinuxagent/common/protocol/hostplugin.py`) — supplies `vmSettings` and signals when FastTrack support is unavailable or stops.
- **Confidential VM information** (`azurelinuxagent/ga/confidential_vm_info.py`) — initializes CVM context used by signature capability checks.
- **Goal-state history** (`azurelinuxagent/common/utils/archive.py`) — archives protocol state for diagnostics and fallback analysis.
