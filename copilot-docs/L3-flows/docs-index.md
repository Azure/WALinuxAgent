# L3 — Flows Documentation Index

> "How to implement X?" — End-to-end flows composing L1 concepts and L2 platform services.


| Document | Description |
|----------|-------------|
| [agent-application-bootstrap.md](agent-application-bootstrap.md) | **TL;DR:** `setup.py` is the minimal application bootstrap: it imports the agent entry module and immediately delegates execution to `azurelinuxagent. |
| [daemon-entrypoint.md](daemon-entrypoint.md) | **TL;DR:** The daemon package exposes `get_daemon_handler` from `azurelinuxagent.daemon.main` as its stable construction entry point. Callers use this |
| [distro-deprovision-workflows.md](distro-deprovision-workflows.md) | **TL;DR:** Distribution handlers extend the default deprovision plan with OS-specific cleanup while preserving its warning-and-action contract. Arch a |
| [machine-deprovisioning-flow.md](machine-deprovisioning-flow.md) | **TL;DR:** `DeprovisionHandler` builds an ordered list of destructive cleanup actions, displays their warnings, obtains confirmation unless forced, an |
| [rdma-configuration-workflows.md](rdma-configuration-workflows.md) | **TL;DR:** RDMA setup selects a distribution-specific driver handler, reconciles the driver with the Network Direct firmware version when enabled, the |
| [scvmm-agent-integration.md](scvmm-agent-integration.md) | **TL;DR:** `ScvmmHandler` detects Microsoft System Center Virtual Machine Manager (SCVMM) media, launches its `install` script asynchronously, then de |
