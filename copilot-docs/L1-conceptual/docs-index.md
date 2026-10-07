# L1 — Conceptual Documentation Index

> "What is X?" — Foundational concepts, architecture, design rationale.


| Document | Description |
|----------|-------------|
| [agent-feature-capabilities.md](agent-feature-capabilities.md) | **TL;DR:** The agent keeps a small, centralized capability registry and publishes different feature sets to Azure CRP and extension processes. Protoco |
| [deprovision-handler-dispatch.md](deprovision-handler-dispatch.md) | **TL;DR:** The deprovision package exposes `get_deprovision_handler` as its public handler-selection entry point. Consumers import this package-level  |
| [distribution-version-model.md](distribution-version-model.md) | **TL;DR:** `DistroVersion` converts arbitrary Linux distribution version strings into loosely ordered, comparable values. Use it for distro release ch |
| [extension-goal-state-factory.md](extension-goal-state-factory.md) | **TL;DR:** `ExtensionsGoalStateFactory` is the centralized construction boundary for extension goal states. It selects an empty, ExtensionsConfig-back |
| [goal-state-domain-models.md](goal-state-domain-models.md) | **TL;DR:** The goal-state model gives extension handling one source-independent contract for empty, WireServer `ExtensionsConfig`, and HostGAPlugin `v |
| [os-service-management.md](os-service-management.md) | **TL;DR:** `azurelinuxagent.common.osutil.systemd` centralizes systemd detection, agent unit discovery, runtime property management, and `systemd-run` |
| [periodic-operation-runner.md](periodic-operation-runner.md) | **TL;DR:** `PeriodicOperation` is a lightweight base class for polling-loop tasks that should run no more often than a configured interval. It isolate |
| [protocol-data-contracts.md](protocol-data-contracts.md) | **TL;DR:** Protocol data contracts are the agent's shared in-memory vocabulary for goal state, extension configuration, status reporting, updates, rem |
| [provision-handler-selection.md](provision-handler-selection.md) | **TL;DR:** `get_provision_handler` is the provisioning subsystem's stable factory entry point. It selects cloud-init when explicitly configured, or wh |
| [rdma-handler-factory.md](rdma-handler-factory.md) | **TL;DR:** `get_rdma_handler` is the construction boundary that selects the Linux-distribution-specific RDMA handler used by the agent. It isolates ca |
| [resource-disk-factory.md](resource-disk-factory.md) | **TL;DR:** `get_resourcedisk_handler` is the stable construction boundary for resource-disk management. It selects a FreeBSD, OpenBSD, or OpenWRT impl |
| [thread-handler-contract.md](thread-handler-contract.md) | **TL;DR:** `ThreadHandlerInterface` defines the lifecycle contract for background thread handlers owned by the Guest Agent. Implementations supply nam |
| [thread-local-singleton.md](thread-local-singleton.md) | **TL;DR:** `SingletonPerThread` gives each derived class one cached instance per thread name. It is used by `ProtocolUtil` to isolate protocol initial |
