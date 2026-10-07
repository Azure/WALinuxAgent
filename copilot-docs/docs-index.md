# Documentation Index — WALinuxAgent

> Master index for all agent-optimized documentation. Read this FIRST for any non-trivial question.


## Always-Loaded Foundation

- [L0 Primer](L0-foundations/codebase-primer.md) — Architecture, terminology, ownership. Always read before any task.


## Layer Indexes

- [L1 — Conceptual](L1-conceptual/docs-index.md) — "What is X?" — Foundational concepts, architecture, design rationale.
- [L2 — Platform](L2-platform/docs-index.md) — "How does X work?" — Infrastructure services, build, deployment, telemetry, flighting.
- [L3 — Flows](L3-flows/docs-index.md) — "How to implement X?" — End-to-end flows composing L1 concepts and L2 platform services.

## Detailed Content Fallback

Every DAG doc has a corresponding **detailed content file** at `intermediate-docs/` with per-file NL summaries. When a compact DAG doc (~200 lines) lacks sufficient detail:

1. Read the compact DAG doc in `{layer}/{name}.md`
2. If insufficient, read `intermediate-docs/{layer}/{name}.content.md` (detailed, no line limit)
3. Only then search source code directly

Ordered document sequences for common query types. Follow in order.

## Reading Chains

### "Understand how extension goal state is modeled and created"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L1-conceptual/goal-state-domain-models.md](L1-conceptual/goal-state-domain-models.md)
3. [L1-conceptual/protocol-data-contracts.md](L1-conceptual/protocol-data-contracts.md)
4. [L1-conceptual/extension-goal-state-factory.md](L1-conceptual/extension-goal-state-factory.md)

### "Trace agent startup and background operation scheduling"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L3-flows/agent-application-bootstrap.md](L3-flows/agent-application-bootstrap.md)
3. [L3-flows/daemon-entrypoint.md](L3-flows/daemon-entrypoint.md)
4. [L1-conceptual/thread-handler-contract.md](L1-conceptual/thread-handler-contract.md)
5. [L1-conceptual/periodic-operation-runner.md](L1-conceptual/periodic-operation-runner.md)
6. [L1-conceptual/thread-local-singleton.md](L1-conceptual/thread-local-singleton.md)

### "Modify provisioning or machine deprovisioning behavior"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L1-conceptual/provision-handler-selection.md](L1-conceptual/provision-handler-selection.md)
3. [L1-conceptual/deprovision-handler-dispatch.md](L1-conceptual/deprovision-handler-dispatch.md)
4. [L3-flows/machine-deprovisioning-flow.md](L3-flows/machine-deprovisioning-flow.md)
5. [L3-flows/distro-deprovision-workflows.md](L3-flows/distro-deprovision-workflows.md)
6. [L2-platform/distribution-os-adapters.md](L2-platform/distribution-os-adapters.md)

### "Diagnose logging, telemetry, and resource-governance behavior"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L2-platform/agent-logging-service.md](L2-platform/agent-logging-service.md)
3. [L2-platform/agent-event-reporting.md](L2-platform/agent-event-reporting.md)
4. [L2-platform/cgroup-resource-governance.md](L2-platform/cgroup-resource-governance.md)
5. [L2-platform/cgroup-telemetry-tracking.md](L2-platform/cgroup-telemetry-tracking.md)
6. [L2-platform/service-error-state.md](L2-platform/service-error-state.md)

### "Change RDMA configuration for a Linux distribution"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L1-conceptual/rdma-handler-factory.md](L1-conceptual/rdma-handler-factory.md)
3. [L3-flows/rdma-configuration-workflows.md](L3-flows/rdma-configuration-workflows.md)
4. [L2-platform/distribution-os-adapters.md](L2-platform/distribution-os-adapters.md)
5. [L2-platform/shell-command-validation.md](L2-platform/shell-command-validation.md)

### "Work on diagnostics, state archives, or log collection"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L2-platform/archive-operations.md](L2-platform/archive-operations.md)
3. [L2-platform/log-collector-manifests.md](L2-platform/log-collector-manifests.md)
4. [L2-platform/file-io-utilities.md](L2-platform/file-io-utilities.md)
5. [L2-platform/shell-command-validation.md](L2-platform/shell-command-validation.md)
6. [L2-platform/platform-error-handling.md](L2-platform/platform-error-handling.md)
