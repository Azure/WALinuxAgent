# Machine Deprovisioning Flow


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L3-flows/machine-deprovisioning-flow.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `DeprovisionHandler` builds an ordered list of destructive cleanup actions, displays their warnings, obtains confirmation unless forced, and then executes them without allowing interruption. A separate changed-unique-ID path performs narrower, non-interactive cleanup so stale goal state and extension data do not contaminate a reused VM.

## Why

VM images and reused machines must not retain identity, credentials, network state, agent state, or resource-control configuration from a previous instance. The deprovisioning flow centralizes that cleanup while separating planning from execution so users can review warnings before destructive work starts.

The changed-unique-ID flow addresses a related recovery case: when the VM identifier changes without manual deprovisioning, cached incarnation, goal-state, extension, firewall, and cgroup data can make the agent interpret the new VM through stale state.

## What

`DeprovisionHandler` coordinates platform-specific operations through `osutil`, protocol data through `protocol_util`, and filesystem cleanup through `fileutil`. Each operation is wrapped in a `DeprovisionAction`; setup methods collect actions and warnings without immediately changing the machine.

### Cleanup modes

| Mode | Entry Method | Scope | Confirmation |
|---|---|---|---|
| Full deprovisioning | `DeprovisionHandler.run` | Stops the agent; clears network, host, credential, agent, firewall, and cgroup state; optionally deletes the provisioned user | Required unless `force=True` |
| Changed unique ID | `DeprovisionHandler.run_changed_unique_id` | Clears DHCP leases, cached protocol/goal-state files, extension status/settings, persisted firewall artifacts, and agent cgroup configuration | None |

Full deprovisioning is configuration-sensitive: SSH host keys and the root password are removed only when their corresponding configuration flags are enabled. User deletion is controlled by the `deluser` argument and depends on reading the username from the OVF environment; a missing OVF environment produces warnings and skips that action.

## How

### Full deprovisioning sequence

1. `DeprovisionHandler.setup` creates warning and action lists.
2. It schedules the agent service stop, optional SSH host-key deletion, DHCP lease cleanup, and hostname reset.
3. It optionally schedules root-password disabling, then schedules agent directories, logs, shell history, platform random-state files, and `/etc/resolv.conf` for removal.
4. When requested, `DeprovisionHandler.del_user` reads the provisioned username from the OVF environment and schedules account and home-directory deletion.
5. It schedules removal of the persisted firewall service/binary and systemd cgroup drop-ins plus the log-collector slice.
6. `DeprovisionHandler.run` prints all warnings and calls `DeprovisionHandler.do_confirmation`.
7. If confirmed, `DeprovisionHandler.do_actions` invokes each `DeprovisionAction` in insertion order.

### Changed-unique-ID sequence

1. `DeprovisionHandler.setup_changed_unique_id` schedules DHCP lease deletion.
2. It removes known agent library files and matching goal-state/extension XML files.
3. It scans extension handler directories, excluding agent-version directories, and schedules status, settings, handler-status, and sequence files for deletion.
4. It schedules persisted firewall and cgroup configuration cleanup.
5. `DeprovisionHandler.run_changed_unique_id` prints warnings and executes immediately.

### Execution and interruption semantics

- `DeprovisionAction.invoke` calls the stored function with its captured positional and keyword arguments.
- `DeprovisionHandler.do_actions` marks actions as running for the duration of the ordered loop.
- `DeprovisionHandler.handle_interrupt_signal` exits cleanly on `SIGINT` before execution starts, but refuses interruption while cleanup actions are running to avoid a partially deprovisioned machine.
- Actions are not rolled back. Callers and new cleanup steps must tolerate absent files where the delegated utility already provides that behavior.

### Change guidance

- Add cleanup through the appropriate setup method as a `DeprovisionAction`; do not perform destructive work while assembling warnings.
- Preserve ordering dependencies, especially stopping the service before deleting its state.
- Add a warning for user-visible destructive effects and keep confirmation behavior in `run`.
- Keep changed-unique-ID cleanup narrower than full image deprovisioning; it should remove stale agent state without deleting users or credentials.
- Route platform-specific account, service, and hostname behavior through `osutil`; use configuration accessors and shared path constants instead of duplicating paths.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Deprovision orchestration | `azurelinuxagent/pa/deprovision/default.py` | `DeprovisionHandler`, `DeprovisionHandler.setup`, `DeprovisionHandler.run`, `DeprovisionHandler.run_changed_unique_id` |
| Deferred cleanup action | `azurelinuxagent/pa/deprovision/default.py` | `DeprovisionAction`, `DeprovisionAction.invoke` |
| Platform operations | `azurelinuxagent/common/osutil/factory.py` | `get_osutil` |
| Provisioning identity lookup | `azurelinuxagent/common/protocol/util.py` | `get_protocol_util` |
| Persisted firewall cleanup | `azurelinuxagent/ga/persist_firewall_rules.py` | `PersistFirewallRulesHandler` |
| Agent cgroup cleanup | `azurelinuxagent/ga/cgroupconfigurator.py` | Agent drop-in constants, `LOGCOLLECTOR_SLICE` |
| Extension artifact matching | `azurelinuxagent/ga/exthandlers.py` | `HANDLER_COMPLETE_NAME_PATTERN` |

## Related Components

- Agent provisioning and OVF environment handling — supplies the account identity removed by `DeprovisionHandler.del_user`.
- Extension handler lifecycle — defines the extension directories and state files cleared after a VM unique-ID change.
- Persisted firewall rules — installs the service and binary removed during either cleanup mode.
- Agent cgroup configuration — owns the systemd drop-ins and log-collector slice removed during either cleanup mode.
