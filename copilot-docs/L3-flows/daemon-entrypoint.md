# Daemon Entrypoint


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L3-flows/daemon-entrypoint.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** The daemon package exposes `get_daemon_handler` from `azurelinuxagent.daemon.main` as its stable construction entry point. Callers use this factory boundary instead of coupling startup code directly to `DaemonHandler`.

## Why

The entry point separates daemon consumers from the concrete daemon implementation. This keeps imports stable while allowing lifecycle behavior and handler construction to evolve inside the daemon module.

## What

The flow has three roles:

1. `azurelinuxagent.daemon` exposes the public daemon factory.
2. `get_daemon_handler` constructs the daemon handler.
3. `DaemonHandler` owns daemon initialization and execution after construction.

The package boundary contains no configuration, branching, or lifecycle policy; it only forwards the factory symbol from the implementation module.

## How

### Entrypoint sequence

1. A caller imports `get_daemon_handler` from `azurelinuxagent.daemon`.
2. The package resolves that symbol from `azurelinuxagent.daemon.main`.
3. The caller invokes `get_daemon_handler`.
4. The factory returns a `DaemonHandler`.
5. The caller starts daemon processing through `DaemonHandler.run`.

### Change guidance

- Preserve `get_daemon_handler` as the public construction boundary for daemon callers.
- Put daemon startup, restart, and lifecycle behavior in `DaemonHandler`, not in the package initializer.
- Update the re-export and implementation together if the factory name or location changes.
- Diagnose failures after handler construction in `DaemonHandler`; the package entry point adds no runtime logic.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Public daemon entry point | `azurelinuxagent/daemon/__init__.py` | `get_daemon_handler` re-export |
| Daemon factory and lifecycle | `azurelinuxagent/daemon/main.py` | `get_daemon_handler`, `DaemonHandler`, `DaemonHandler.run` |

## Related Components

- [Agent Application Bootstrap](agent-application-bootstrap.md) — adjacent top-level application launch and delegation boundary.
- `azurelinuxagent.daemon.main` — concrete daemon construction and lifecycle implementation.
