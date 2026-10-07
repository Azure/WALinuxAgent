# Extension Goal State Factory


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/extension-goal-state-factory.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `ExtensionsGoalStateFactory` is the centralized construction boundary for extension goal states. It selects an empty, ExtensionsConfig-backed, or VM settings-backed implementation while passing each source's identity and payload data unchanged.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/extension-goal-state-factory.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Extension processing can receive goal-state information in different forms. Callers need a single construction API that maps each input source to the correct representation without depending directly on concrete constructors.

The factory keeps this selection explicit and prevents source-specific initialization details from spreading across protocol consumers.

## What

`ExtensionsGoalStateFactory` exposes three static creation methods:

| Input form | Factory method | Result |
|---|---|---|
| No extension configuration | `ExtensionsGoalStateFactory.create_empty` | `EmptyExtensionsGoalState` |
| ExtensionsConfig XML | `ExtensionsGoalStateFactory.create_from_extensions_config` | `ExtensionsGoalStateFromExtensionsConfig` |
| VM settings JSON | `ExtensionsGoalStateFactory.create_from_vm_settings` | `ExtensionsGoalStateFromVmSettings` |

Each method is a direct constructor adapter:

- `create_empty` preserves the goal-state `incarnation`.
- `create_from_extensions_config` passes `incarnation`, `xml_text`, and `wire_client`.
- `create_from_vm_settings` passes `etag`, `json_text`, and `correlation_id`.

The factory does not parse payloads or normalize identifiers; those responsibilities remain with the selected concrete goal-state class.

## How

### Construction flow

1. Determine whether the extension state is empty, ExtensionsConfig XML, or VM settings JSON.
2. Call the corresponding `ExtensionsGoalStateFactory` static method.
3. The factory instantiates the matching concrete implementation with the supplied source metadata and payload.
4. The returned object owns source-specific interpretation and behavior.

### Change guidance

- Add new construction paths to `ExtensionsGoalStateFactory` when introducing another extension goal-state source.
- Keep source-specific parsing and validation in the concrete implementation, not in the factory.
- Preserve argument identity: `incarnation` identifies legacy goal states, while `etag` and `correlation_id` identify and trace VM settings.
- Use `create_empty` rather than manufacturing a placeholder payload when no extension configuration exists.
- Update callers and factory coverage together if a concrete constructor signature changes.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Goal-state construction boundary | `azurelinuxagent/common/protocol/extensions_goal_state_factory.py` | `ExtensionsGoalStateFactory`; `ExtensionsGoalStateFactory.create_empty`; `ExtensionsGoalStateFactory.create_from_extensions_config`; `ExtensionsGoalStateFactory.create_from_vm_settings` |
| Empty goal state | `azurelinuxagent/common/protocol/extensions_goal_state.py` | `EmptyExtensionsGoalState` |
| ExtensionsConfig-backed goal state | `azurelinuxagent/common/protocol/extensions_goal_state_from_extensions_config.py` | `ExtensionsGoalStateFromExtensionsConfig` |
| VM settings-backed goal state | `azurelinuxagent/common/protocol/extensions_goal_state_from_vm_settings.py` | `ExtensionsGoalStateFromVmSettings` |

## Related Components

- **Extension goal-state model:** `azurelinuxagent.common.protocol.extensions_goal_state.EmptyExtensionsGoalState` represents the no-configuration case.
- **ExtensionsConfig protocol adapter:** `ExtensionsGoalStateFromExtensionsConfig` owns the XML- and wire-client-backed representation.
- **VM settings protocol adapter:** `ExtensionsGoalStateFromVmSettings` owns the JSON representation keyed by ETag and correlation ID.
