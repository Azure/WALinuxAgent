# WALinuxAgent — Primer

> Always-loaded foundation. Max 200 lines. No index.

## Architecture

WALinuxAgent is a Linux guest-agent codebase organized around stable factories, shared protocol contracts, distribution-specific adapters, and long-running handlers. The application bootstrap delegates to the agent entry module, which constructs daemon and operation handlers rather than binding callers to concrete implementations.

The protocol layer normalizes goal state, extension configuration, status, update, remote-access, and related wire data into shared in-memory contracts. Extension goal states are created through a centralized factory so consumers can work against one model regardless of whether data came from an empty state, WireServer ExtensionsConfig, or HostGAPlugin.

Host-facing behavior is split between common services and distribution adapters. Common services provide logging, telemetry, file and XML handling, subprocess execution, route inspection, version comparison, archiving, time formatting, and typed errors. OS adapters translate shared operations into distribution-specific service, package, network, storage, provisioning, deprovisioning, and RDMA behavior.

Long-running work uses explicit lifecycle and scheduling boundaries. ThreadHandlerInterface defines background-handler ownership, PeriodicOperation controls polling cadence, and SingletonPerThread isolates selected state by thread. Resource governance places the agent, extensions, and log collector into cgroups, while telemetry tracks resource usage and operational events.

Provisioning, deprovisioning, resource-disk management, daemon startup, and RDMA setup use factory or dispatch boundaries. These boundaries keep platform selection localized and let the main workflows compose common contracts with OS-specific handlers.

## Request Flow

Application bootstrap → agent entry module → daemon factory → background handlers and periodic operations

Platform goal state → protocol contracts → extension goal-state factory → extension handling → status and telemetry reporting

Administrative operation → stable handler factory → common workflow → distribution adapter → host command or file operation → logging, typed errors, and events

Diagnostic operation → state and command collection → archive or log-collector manifest → packaged diagnostic output

Across these flows, shell execution, file access, XML/text conversion, time formatting, version comparison, and error classification are centralized infrastructure rather than reimplemented in each subsystem.

## Core Terminology

| Term | Definition |
|------|------------|
| Guest Agent | The WALinuxAgent process that coordinates Azure VM guest operations on Linux. |
| Daemon handler | The stable runtime handler created by the daemon entry-point factory. |
| Goal state | The normalized desired-state data that drives extension and agent behavior. |
| ExtensionsConfig | WireServer extension configuration represented through the shared goal-state model. |
| HostGAPlugin | Host-side protocol source that can provide extension goal-state data. |
| ExtensionsGoalStateFactory | Construction boundary that selects and creates the appropriate extension goal-state representation. |
| Protocol data contracts | Shared in-memory models for goal state, status, updates, remote access, and extension configuration. |
| Distribution adapter | A DefaultOSUtil specialization that maps common host operations to a Linux distribution. |
| Handler factory | A stable selection boundary for provisioning, deprovisioning, resource disk, RDMA, or daemon implementations. |
| ThreadHandlerInterface | Lifecycle contract for background handlers owned by the Guest Agent. |
| PeriodicOperation | Interval-gated abstraction for tasks executed by polling loops. |
| SingletonPerThread | Per-thread-name instance cache used to isolate selected runtime state. |
| CGroupConfigurator | Service that assigns agent-related processes to systemd cgroup slices and applies resource controls. |
| CGroupsTelemetry | Thread-safe registry of cgroup controllers monitored for resource metrics. |
| ErrorState | Timer-based model that detects a continuously failing service after a configured duration. |
| WALAEventOperation | Vocabulary for categorizing operational telemetry events. |
| DistroVersion | Loose ordering model for Linux distribution release strings. |
| FlexibleVersion | Configurable comparison model for numeric agent and extension versions. |

## Key Components

| Component | Description |
|-----------|-------------|
| Application and daemon bootstrap | Transfers control from packaging entry points into the agent and constructs the daemon handler. |
| Goal-state domain model | Provides source-independent contracts for extension configuration and related platform state. |
| Extension goal-state factory | Centralizes construction of empty, WireServer-backed, and HostGAPlugin-backed extension states. |
| Provisioning and deprovisioning | Selects handlers and executes ordered setup or destructive cleanup workflows with distribution-specific behavior. |
| Distribution OS adapters | Implement the common host-operation contract for supported Linux variants. |
| Resource disk management | Selects platform-specific handlers behind a stable resource-disk factory. |
| RDMA management | Selects distribution handlers and reconciles drivers with Network Direct firmware requirements. |
| Background operation framework | Defines handler lifecycle, polling cadence, and thread-local state boundaries. |
| Logging and event reporting | Formats and redacts logs, throttles repeated messages, queues telemetry, and reports operational outcomes. |
| Cgroup governance and monitoring | Applies CPU and memory controls and gathers agent, extension, and log-collector resource metrics. |
| Protocol and platform utilities | Centralizes network routes, files, XML/text, shell commands, versions, UTC timestamps, and runtime compatibility. |
| Diagnostics and archiving | Preserves goal-state snapshots and assembles normal or full diagnostic bundles from declarative manifests. |
| Platform error model | Uses typed exceptions and continuous-failure state to preserve boundary-specific failure semantics. |
| Packaging infrastructure | Produces installable and publishable artifacts and connects runtime factories to packaged entry points. |
