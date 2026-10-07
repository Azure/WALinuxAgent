# WALinuxAgent

WALinuxAgent is the Linux guest agent that coordinates Azure VM guest operations
through stable factories, shared protocol contracts, distribution-specific adapters,
and long-running handlers. It normalizes platform goal state, manages extensions and
host resources, and reports status and telemetry.

## Documentation

MUST read the documentation index before searching code for any non-trivial task:

- [Master docs-index](../copilot-docs/docs-index.md) — Start here. Contains layer
  indexes and reading chains.
- [L0 Primer](../copilot-docs/L0-foundations/codebase-primer.md) — Always-loaded
  architecture foundation.
- [L1 Conceptual Index](../copilot-docs/L1-conceptual/docs-index.md) — Core contracts,
  domain models, handler factories, lifecycle abstractions, and service concepts.
- [L2 Platform Index](../copilot-docs/L2-platform/docs-index.md) — OS adapters, logging,
  telemetry, resource governance, diagnostics, utilities, packaging, and error handling.
- [L3 Flows Index](../copilot-docs/L3-flows/docs-index.md) — Application startup and
  end-to-end provisioning, deprovisioning, RDMA, and SCVMM workflows.

## Ownership Table

| Topic | Code Area | Doc Area |
|-------|-----------|----------|
| Application bootstrap | `(see docs)` | L3 `agent-application-bootstrap.md` |
| Daemon construction | `(see docs)` | L3 `daemon-entrypoint.md` |
| Goal-state domain model | `(see docs)` | L1 `goal-state-domain-models.md` |
| Extension goal-state construction | `(see docs)` | L1 `extension-goal-state-factory.md` |
| Protocol data contracts | `(see docs)` | L1 `protocol-data-contracts.md` |
| Provisioning handler selection | `(see docs)` | L1 `provision-handler-selection.md` |
| Machine deprovisioning | `(see docs)` | L3 `machine-deprovisioning-flow.md` |
| Distribution host operations | `(see docs)` | L2 `distribution-os-adapters.md` |
| Resource-disk handler selection | `(see docs)` | L1 `resource-disk-factory.md` |
| RDMA setup and reconciliation | `(see docs)` | L3 `rdma-configuration-workflows.md` |
| Background handler lifecycle | `(see docs)` | L1 `thread-handler-contract.md` |
| Logging and event reporting | `(see docs)` | L2 `agent-logging-service.md`, L2 `agent-event-reporting.md` |
| Cgroup governance and telemetry | `(see docs)` | L2 `cgroup-resource-governance.md`, L2 `cgroup-telemetry-tracking.md` |
| Diagnostics and log collection | `(see docs)` | L2 `archive-operations.md`, L2 `log-collector-manifests.md` |

<!-- AUTO-GENERATED-MAPPING:BEGIN  (managed by step7_inject_routing_table.py) -->

## Component Mapping (auto-generated)

_This section is generated deterministically from `scripts/dag-enrichment/compose_to_dag_mapping-symbols.json` (by `step7_inject_routing_table.py`). Do not hand-edit - it is rewritten on every DAG regeneration. Anything outside the AUTO-GENERATED-MAPPING markers in this file is preserved._

**How to use this table** — the table answers three kinds of lookups, not just path lookups:

1. **Path lookup**: if the question (or your investigation) mentions a source path, find the row whose pattern matches and follow its reading chain.
2. **Symbol / class lookup**: if the question names a class, interface, method, error code, config key, or feature (e.g. *FsmBlock*, *BackupTaskController*, *PreBackupBlock*), scan the **What it covers** column for that term. Each description names the symbols and concepts the DAG covers because the cluster was built from those very symbols.
3. **Concept lookup**: for broader concepts (e.g. *backup workflow*, *plugin lifecycle*, *cross-platform helpers*), the **What it covers** column groups related areas. Pick the row that best matches; follow the reading chain; use the `(see also: ...)` cross-references to find adjacent DAGs.

In every case the reading chain is the same: open the compact `copilot-docs/` doc first, then its `intermediate-docs/{layer}/{name}.content.md` companion. Only read source code if both tiers are insufficient.

| Source path pattern | Reading chain (tier-1 -> tier-2) | What it covers |
|---------------------|----------------------------------|----------------|
| `azurelinuxagent/common/`<br>`azurelinuxagent/common/protocol/`<br>`azurelinuxagent/ga/` | `copilot-docs/L1-conceptual/agent-feature-capabilities.md` -> `intermediate-docs/L1-conceptual/agent-feature-capabilities.content.md`<br>*(see also: goal-state-domain-models, protocol-data-contracts, agent-event-reporting, platform-error-handling, +12 more)* | Agent capability declarations used by protocol, extension, telemetry, and update components |
| `azurelinuxagent/pa/deprovision/` | `copilot-docs/L1-conceptual/deprovision-handler-dispatch.md` -> `intermediate-docs/L1-conceptual/deprovision-handler-dispatch.content.md` | Selects the platform-specific handler for machine deprovisioning |
| `azurelinuxagent/common/utils/` | `copilot-docs/L1-conceptual/distribution-version-model.md` -> `intermediate-docs/L1-conceptual/distribution-version-model.content.md`<br>*(see also: rdma-configuration-workflows)* | Comparable value model for Linux distribution versions |
| `azurelinuxagent/common/protocol/` | `copilot-docs/L1-conceptual/extension-goal-state-factory.md` -> `intermediate-docs/L1-conceptual/extension-goal-state-factory.content.md` | Factory for constructing extension goal states from supported configuration sources |
| `azurelinuxagent/common/`<br>`azurelinuxagent/common/protocol/` | `copilot-docs/L1-conceptual/goal-state-domain-models.md` -> `intermediate-docs/L1-conceptual/goal-state-domain-models.content.md`<br>*(see also: protocol-data-contracts, agent-event-reporting, platform-error-handling, extension-goal-state-factory, +6 more)* | Shared agent globals, extension goal state, and protocol event models |
| `azurelinuxagent/common/osutil/` | `copilot-docs/L1-conceptual/os-service-management.md` -> `intermediate-docs/L1-conceptual/os-service-management.content.md`<br>*(see also: cgroup-resource-governance, rdma-configuration-workflows)* | Operating system utility selection and systemd service management |
| `azurelinuxagent/ga/` | `copilot-docs/L1-conceptual/periodic-operation-runner.md` -> `intermediate-docs/L1-conceptual/periodic-operation-runner.content.md`<br>*(see also: rdma-configuration-workflows)* | Schedules and runs recurring agent operations at controlled intervals |
| `azurelinuxagent/common/`<br>`azurelinuxagent/common/protocol/` | `copilot-docs/L1-conceptual/protocol-data-contracts.md` -> `intermediate-docs/L1-conceptual/protocol-data-contracts.content.md`<br>*(see also: agent-event-reporting, platform-error-handling, rdma-configuration-workflows)* | REST API and telemetry data contracts exchanged with Azure services |
| `azurelinuxagent/pa/provision/` | `copilot-docs/L1-conceptual/provision-handler-selection.md` -> `intermediate-docs/L1-conceptual/provision-handler-selection.content.md` | Creates the platform-specific handler used to provision virtual machines |
| `azurelinuxagent/pa/rdma/` | `copilot-docs/L1-conceptual/rdma-handler-factory.md` -> `intermediate-docs/L1-conceptual/rdma-handler-factory.content.md`<br>*(see also: rdma-configuration-workflows)* | Creates the distribution-specific handler for RDMA configuration |
| `azurelinuxagent/daemon/resourcedisk/` | `copilot-docs/L1-conceptual/resource-disk-factory.md` -> `intermediate-docs/L1-conceptual/resource-disk-factory.content.md` | Factory contract for selecting platform-specific resource disk handlers |
| `azurelinuxagent/ga/` | `copilot-docs/L1-conceptual/thread-handler-contract.md` -> `intermediate-docs/L1-conceptual/thread-handler-contract.content.md` | Lifecycle contract for starting, monitoring, and keeping worker threads alive |
| `azurelinuxagent/common/`<br>`azurelinuxagent/common/protocol/` | `copilot-docs/L1-conceptual/thread-local-singleton.md` -> `intermediate-docs/L1-conceptual/thread-local-singleton.content.md`<br>*(see also: file-io-utilities, cgroup-resource-governance, rdma-configuration-workflows)* | Thread-scoped singleton pattern and supporting protocol utilities |
| `azurelinuxagent/common/protocol/`<br>`azurelinuxagent/daemon/`<br>`azurelinuxagent/daemon/resourcedisk/`<br>`azurelinuxagent/ga/`<br>`azurelinuxagent/ga/policy/`<br>`azurelinuxagent/pa/provision/` | `copilot-docs/L2-platform/agent-event-reporting.md` -> `intermediate-docs/L2-platform/agent-event-reporting.content.md`<br>*(see also: platform-error-handling, os-service-management, extension-goal-state-factory, thread-local-singleton, +16 more)* | Cross-cutting event reporting for daemon, extension, firewall, cgroup, and update operations |
| `azurelinuxagent/common/`<br>`azurelinuxagent/pa/provision/` | `copilot-docs/L2-platform/agent-logging-service.md` -> `intermediate-docs/L2-platform/agent-logging-service.content.md`<br>*(see also: utc-time-utilities, agent-packaging-factories, rdma-configuration-workflows)* | Agent logging infrastructure with periodic controls and cloud-init detection support |
| `azurelinuxagent/common/osutil/`<br>`azurelinuxagent/daemon/resourcedisk/`<br>`azurelinuxagent/pa/deprovision/`<br>`azurelinuxagent/pa/provision/`<br>`makepkg.py.md/` | `copilot-docs/L2-platform/agent-packaging-factories.md` -> `intermediate-docs/L2-platform/agent-packaging-factories.content.md`<br>*(see also: platform-error-handling, distribution-os-adapters, resource-disk-factory, cgroup-resource-governance, +4 more)* | Build packaging and platform-specific factory selection for agent components |
| `azurelinuxagent/common/utils/` | `copilot-docs/L2-platform/archive-operations.md` -> `intermediate-docs/L2-platform/archive-operations.content.md`<br>*(see also: file-io-utilities, rdma-configuration-workflows)* | Utilities for creating, inspecting, and extracting archives |
| `azurelinuxagent/ga/` | `copilot-docs/L2-platform/cgroup-resource-governance.md` -> `intermediate-docs/L2-platform/cgroup-resource-governance.content.md`<br>*(see also: agent-event-reporting, os-service-management, file-io-utilities, cgroup-telemetry-tracking, +3 more)* | Cgroup configuration, monitoring, and diagnostic log collection services |
| `azurelinuxagent/ga/` | `copilot-docs/L2-platform/cgroup-telemetry-tracking.md` -> `intermediate-docs/L2-platform/cgroup-telemetry-tracking.content.md`<br>*(see also: rdma-configuration-workflows)* | Cgroup controller tracking and resource governance telemetry |
| `azurelinuxagent/common/osutil/` | `copilot-docs/L2-platform/distribution-os-adapters.md` -> `intermediate-docs/L2-platform/distribution-os-adapters.content.md`<br>*(see also: file-io-utilities, network-route-utilities, agent-packaging-factories, cgroup-resource-governance, +1 more)* | Distribution-specific operating system utility implementations |
| `azurelinuxagent/common/utils/` | `copilot-docs/L2-platform/file-io-utilities.md` -> `intermediate-docs/L2-platform/file-io-utilities.content.md`<br>*(see also: rdma-configuration-workflows)* | File reading, writing, copying, and filesystem manipulation utilities |
| `azurelinuxagent/common/`<br>`azurelinuxagent/common/utils/` | `copilot-docs/L2-platform/flexible-version-comparison.md` -> `intermediate-docs/L2-platform/flexible-version-comparison.content.md`<br>*(see also: shell-command-validation, rdma-configuration-workflows)* | Flexible parsing, representation, and comparison of agent and platform versions |
| `azurelinuxagent/ga/` | `copilot-docs/L2-platform/log-collector-manifests.md` -> `intermediate-docs/L2-platform/log-collector-manifests.content.md` | Manifest definitions that select files and data for diagnostic log collection |
| `azurelinuxagent/common/utils/` | `copilot-docs/L2-platform/network-route-utilities.md` -> `intermediate-docs/L2-platform/network-route-utilities.content.md` | Network route parsing and conversion of kernel route values to IP addresses |
| `azurelinuxagent/`<br>`azurelinuxagent/common/`<br>`azurelinuxagent/common/osutil/`<br>`azurelinuxagent/common/protocol/`<br>`azurelinuxagent/common/utils/`<br>`azurelinuxagent/daemon/resourcedisk/`<br>*(+2 more)* | `copilot-docs/L2-platform/platform-error-handling.md` -> `intermediate-docs/L2-platform/platform-error-handling.content.md`<br>*(see also: agent-application-bootstrap, extension-goal-state-factory, thread-local-singleton, file-io-utilities, +9 more)* | Shared exceptions and platform-specific operating system failure handling |
| `azurelinuxagent/common/` | `copilot-docs/L2-platform/runtime-compatibility-helpers.md` -> `intermediate-docs/L2-platform/runtime-compatibility-helpers.content.md`<br>*(see also: shell-command-validation)* | Compatibility helpers for UTC time zone behavior across Python runtimes |
| `azurelinuxagent/common/`<br>`azurelinuxagent/common/protocol/` | `copilot-docs/L2-platform/service-error-state.md` -> `intermediate-docs/L2-platform/service-error-state.content.md`<br>*(see also: goal-state-domain-models, extension-goal-state-factory, shell-command-validation, utc-time-utilities, +2 more)* | Error state tracking and host plugin failure handling |
| `azurelinuxagent/common/utils/`<br>`azurelinuxagent/ga/` | `copilot-docs/L2-platform/shell-command-validation.md` -> `intermediate-docs/L2-platform/shell-command-validation.content.md`<br>*(see also: cgroup-resource-governance, rdma-configuration-workflows)* | Shell command execution and signature validation support |
| `azurelinuxagent/common/utils/` | `copilot-docs/L2-platform/text-xml-utilities.md` -> `intermediate-docs/L2-platform/text-xml-utilities.content.md`<br>*(see also: rdma-configuration-workflows)* | Text conversion, XML parsing, and document traversal utilities |
| `azurelinuxagent/common/utils/` | `copilot-docs/L2-platform/utc-time-utilities.md` -> `intermediate-docs/L2-platform/utc-time-utilities.content.md` | UTC timestamp creation and time conversion utilities |
| `__main__.py.md/` | `copilot-docs/L3-flows/agent-application-bootstrap.md` -> `intermediate-docs/L3-flows/agent-application-bootstrap.content.md` | Agent process entry point and application startup |
| `azurelinuxagent/daemon/` | `copilot-docs/L3-flows/daemon-entrypoint.md` -> `intermediate-docs/L3-flows/daemon-entrypoint.content.md` | Daemon startup entrypoint for initializing and running the agent service |
| `azurelinuxagent/pa/deprovision/` | `copilot-docs/L3-flows/distro-deprovision-workflows.md` -> `intermediate-docs/L3-flows/distro-deprovision-workflows.content.md` | Implements distribution-specific cleanup workflows for machine deprovisioning |
| `azurelinuxagent/pa/deprovision/` | `copilot-docs/L3-flows/machine-deprovisioning-flow.md` -> `intermediate-docs/L3-flows/machine-deprovisioning-flow.content.md`<br>*(see also: os-service-management, cgroup-resource-governance, distro-deprovision-workflows, rdma-configuration-workflows)* | Guest deprovisioning workflow and associated resource isolation cleanup |
| `azurelinuxagent/pa/rdma/` | `copilot-docs/L3-flows/rdma-configuration-workflows.md` -> `intermediate-docs/L3-flows/rdma-configuration-workflows.content.md`<br>*(see also: file-io-utilities)* | Configures RDMA drivers and packages across supported Linux distributions |
| `azurelinuxagent/daemon/` | `copilot-docs/L3-flows/scvmm-agent-integration.md` -> `intermediate-docs/L3-flows/scvmm-agent-integration.content.md`<br>*(see also: cgroup-resource-governance, rdma-configuration-workflows)* | SCVMM environment detection and guest agent startup workflow |

**Coverage gap rule:** if your source path matches no row above, no DAG doc covers that area. Say so explicitly in your answer and cite the source file(s) you used. Do not silently substitute an unrelated doc.

### Defining namespace -> DAG (concept / symbol index)

Use this table when the user prompt names a **class, interface, type, or namespace** without giving you a source path. Scan the namespace and short-name columns for the term. Each entry's reading chain is the same as in the path table above (tier-1 -> tier-2).

| Defining namespace | Short | Tier-1 doc | What it covers |
|--------------------|-------|------------|----------------|
| `%REPO%/azurelinuxagent/agent` | `%REPO%/azurelinuxagent/agent` | `copilot-docs/L3-flows/agent-application-bootstrap.md` | Agent process entry point and application startup |
| `%REPO%/azurelinuxagent/common/AgentGlobals` | `%REPO%/azurelinuxagent/common/AgentGlobals` | `copilot-docs/L1-conceptual/goal-state-domain-models.md` | Shared agent globals, extension goal state, and protocol event models |
| `%REPO%/azurelinuxagent/common/agent_supported_feature` | `%REPO%/azurelinuxagent/common/agent_supported_feature` | `copilot-docs/L1-conceptual/agent-feature-capabilities.md` | Agent capability declarations used by protocol, extension, telemetry, and update components |
| `%REPO%/azurelinuxagent/common/datacontract` | `%REPO%/azurelinuxagent/common/datacontract` | `copilot-docs/L1-conceptual/protocol-data-contracts.md` | REST API and telemetry data contracts exchanged with Azure services |
| `%REPO%/azurelinuxagent/common/errorstate` | `%REPO%/azurelinuxagent/common/errorstate` | `copilot-docs/L2-platform/service-error-state.md` | Error state tracking and host plugin failure handling |
| `%REPO%/azurelinuxagent/common/event` | `%REPO%/azurelinuxagent/common/event` | `copilot-docs/L2-platform/agent-event-reporting.md` | Cross-cutting event reporting for daemon, extension, firewall, cgroup, and update operations |
| `%REPO%/azurelinuxagent/common/exception` | `%REPO%/azurelinuxagent/common/exception` | `copilot-docs/L2-platform/platform-error-handling.md` | Shared exceptions and platform-specific operating system failure handling |
| `%REPO%/azurelinuxagent/common/future` | `%REPO%/azurelinuxagent/common/future` | `copilot-docs/L2-platform/runtime-compatibility-helpers.md` | Compatibility helpers for UTC time zone behavior across Python runtimes |
| `%REPO%/azurelinuxagent/common/logger` | `%REPO%/azurelinuxagent/common/logger` | `copilot-docs/L2-platform/agent-logging-service.md` | Agent logging infrastructure with periodic controls and cloud-init detection support |
| `%REPO%/azurelinuxagent/common/osutil/default` | `%REPO%/azurelinuxagent/common/osutil/default` | `copilot-docs/L2-platform/distribution-os-adapters.md` | Distribution-specific operating system utility implementations |
| `%REPO%/azurelinuxagent/common/osutil/factory` | `%REPO%/azurelinuxagent/common/osutil/factory` | `copilot-docs/L1-conceptual/os-service-management.md` | Operating system utility selection and systemd service management |
| `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state` | `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state` | `copilot-docs/L1-conceptual/extension-goal-state-factory.md` | Factory for constructing extension goal states from supported configuration sources |
| `%REPO%/azurelinuxagent/common/singletonperthread` | `%REPO%/azurelinuxagent/common/singletonperthread` | `copilot-docs/L1-conceptual/thread-local-singleton.md` | Thread-scoped singleton pattern and supporting protocol utilities |
| `%REPO%/azurelinuxagent/common/utils/archive` | `%REPO%/azurelinuxagent/common/utils/archive` | `copilot-docs/L2-platform/archive-operations.md` | Utilities for creating, inspecting, and extracting archives |
| `%REPO%/azurelinuxagent/common/utils/distro_version` | `%REPO%/azurelinuxagent/common/utils/distro_version` | `copilot-docs/L1-conceptual/distribution-version-model.md` | Comparable value model for Linux distribution versions |
| `%REPO%/azurelinuxagent/common/utils/fileutil` | `%REPO%/azurelinuxagent/common/utils/fileutil` | `copilot-docs/L2-platform/file-io-utilities.md` | File reading, writing, copying, and filesystem manipulation utilities |
| `%REPO%/azurelinuxagent/common/utils/flexible_version` | `%REPO%/azurelinuxagent/common/utils/flexible_version` | `copilot-docs/L2-platform/flexible-version-comparison.md` | Flexible parsing, representation, and comparison of agent and platform versions |
| `%REPO%/azurelinuxagent/common/utils/networkutil` | `%REPO%/azurelinuxagent/common/utils/networkutil` | `copilot-docs/L2-platform/network-route-utilities.md` | Network route parsing and conversion of kernel route values to IP addresses |
| `%REPO%/azurelinuxagent/common/utils/shellutil` | `%REPO%/azurelinuxagent/common/utils/shellutil` | `copilot-docs/L2-platform/shell-command-validation.md` | Shell command execution and signature validation support |
| `%REPO%/azurelinuxagent/common/utils/textutil` | `%REPO%/azurelinuxagent/common/utils/textutil` | `copilot-docs/L2-platform/text-xml-utilities.md` | Text conversion, XML parsing, and document traversal utilities |
| `%REPO%/azurelinuxagent/common/utils/timeutil` | `%REPO%/azurelinuxagent/common/utils/timeutil` | `copilot-docs/L2-platform/utc-time-utilities.md` | UTC timestamp creation and time conversion utilities |
| `%REPO%/azurelinuxagent/common/version` | `%REPO%/azurelinuxagent/common/version` | `copilot-docs/L2-platform/agent-packaging-factories.md` | Build packaging and platform-specific factory selection for agent components |
| `%REPO%/azurelinuxagent/daemon/main` | `%REPO%/azurelinuxagent/daemon/main` | `copilot-docs/L3-flows/daemon-entrypoint.md` | Daemon startup entrypoint for initializing and running the agent service |
| `%REPO%/azurelinuxagent/daemon/resourcedisk/factory` | `%REPO%/azurelinuxagent/daemon/resourcedisk/factory` | `copilot-docs/L1-conceptual/resource-disk-factory.md` | Factory contract for selecting platform-specific resource disk handlers |
| `%REPO%/azurelinuxagent/daemon/scvmm` | `%REPO%/azurelinuxagent/daemon/scvmm` | `copilot-docs/L3-flows/scvmm-agent-integration.md` | SCVMM environment detection and guest agent startup workflow |
| `%REPO%/azurelinuxagent/ga/cgroupconfigurator` | `%REPO%/azurelinuxagent/ga/cgroupconfigurator` | `copilot-docs/L3-flows/machine-deprovisioning-flow.md` | Guest deprovisioning workflow and associated resource isolation cleanup |
| `%REPO%/azurelinuxagent/ga/cgroupcontroller` | `%REPO%/azurelinuxagent/ga/cgroupcontroller` | `copilot-docs/L2-platform/cgroup-resource-governance.md` | Cgroup configuration, monitoring, and diagnostic log collection services |
| `%REPO%/azurelinuxagent/ga/cgroupstelemetry` | `%REPO%/azurelinuxagent/ga/cgroupstelemetry` | `copilot-docs/L2-platform/cgroup-telemetry-tracking.md` | Cgroup controller tracking and resource governance telemetry |
| `%REPO%/azurelinuxagent/ga/interfaces` | `%REPO%/azurelinuxagent/ga/interfaces` | `copilot-docs/L1-conceptual/thread-handler-contract.md` | Lifecycle contract for starting, monitoring, and keeping worker threads alive |
| `%REPO%/azurelinuxagent/ga/logcollector_manifests` | `%REPO%/azurelinuxagent/ga/logcollector_manifests` | `copilot-docs/L2-platform/log-collector-manifests.md` | Manifest definitions that select files and data for diagnostic log collection |
| `%REPO%/azurelinuxagent/ga/periodic_operation` | `%REPO%/azurelinuxagent/ga/periodic_operation` | `copilot-docs/L1-conceptual/periodic-operation-runner.md` | Schedules and runs recurring agent operations at controlled intervals |
| `%REPO%/azurelinuxagent/pa/deprovision/__init__` | `%REPO%/azurelinuxagent/pa/deprovision/__init__` | `copilot-docs/L1-conceptual/deprovision-handler-dispatch.md` | Selects the platform-specific handler for machine deprovisioning |
| `%REPO%/azurelinuxagent/pa/deprovision/default` | `%REPO%/azurelinuxagent/pa/deprovision/default` | `copilot-docs/L3-flows/distro-deprovision-workflows.md` | Implements distribution-specific cleanup workflows for machine deprovisioning |
| `%REPO%/azurelinuxagent/pa/provision/factory` | `%REPO%/azurelinuxagent/pa/provision/factory` | `copilot-docs/L1-conceptual/provision-handler-selection.md` | Creates the platform-specific handler used to provision virtual machines |
| `%REPO%/azurelinuxagent/pa/rdma/factory` | `%REPO%/azurelinuxagent/pa/rdma/factory` | `copilot-docs/L1-conceptual/rdma-handler-factory.md` | Creates the distribution-specific handler for RDMA configuration |
| `%REPO%/azurelinuxagent/pa/rdma/rdma` | `%REPO%/azurelinuxagent/pa/rdma/rdma` | `copilot-docs/L3-flows/rdma-configuration-workflows.md` | Configures RDMA drivers and packages across supported Linux distributions |

<!-- AUTO-GENERATED-MAPPING:END -->

## Hard Rules

- MUST read `copilot-docs/docs-index.md` before searching code for architecture,
  flow, or design questions.
- MUST read `copilot-docs/L0-foundations/codebase-primer.md` before answering any
  architecture question.
- Resolve context in this order: compact DAG doc, corresponding detailed content
  file, then source code. If `copilot-docs/` lacks enough detail, MUST read
  `intermediate-docs/{layer}/{name}.content.md` before searching source. For example,
  map `copilot-docs/L1-conceptual/goal-state-domain-models.md` to
  `intermediate-docs/L1-conceptual/goal-state-domain-models.content.md`. Search source
  only when both documentation levels are insufficient.
- Keep platform selection behind the existing provisioning, deprovisioning,
  resource-disk, RDMA, and daemon factory or dispatch boundaries.
- Use the shared protocol contracts and centralized extension goal-state factory
  rather than coupling consumers to WireServer or HostGAPlugin representations.
- Put distribution-specific service, package, network, storage, provisioning,
  deprovisioning, and RDMA behavior in distribution adapters; keep shared workflows
  platform-neutral.
- Reuse centralized shell, file, XML/text, time, version, logging, telemetry, and
  typed-error utilities instead of reimplementing boundary behavior.

## Build & Test

Targets: Python on supported Linux distributions.

```bash
python -m pip install -e .
python setup.py build
python -m pytest
```

## Code Conventions

- Expose stable package-level factory entry points for daemon, provisioning, deprovisioning, resource-disk, and RDMA handler selection.
- Program against source-independent protocol and goal-state contracts rather than concrete platform payloads.
- Extend `DefaultOSUtil` for distribution-specific host behavior.
- Implement background handlers through `ThreadHandlerInterface` and interval-gated polling work through `PeriodicOperation`.
- Use `SingletonPerThread` only where state must be isolated by thread name.
- Use `FlexibleVersion` for configurable agent or extension version ordering and `DistroVersion` for Linux release comparisons.
- Report operational outcomes through the centralized logging, event, and typed-error infrastructure.
