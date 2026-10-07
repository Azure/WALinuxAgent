# Distribution-Specific Deprovision Workflows


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L3-flows/distro-deprovision-workflows.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** Distribution handlers extend the default deprovision plan with OS-specific cleanup while preserving its warning-and-action contract. Arch and CoreOS remove the machine ID, Ubuntu varies resolver cleanup by configuration and release, and Clear Linux currently adds no cleanup.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L3-flows/distro-deprovision-workflows.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

A generalized image must not retain machine identity or stale network state, but those artifacts differ across Linux distributions and releases. These handlers isolate distro-specific policy from the shared deprovision workflow and express every destructive operation as a warning paired with a deferred `DeprovisionAction`.

## What

All variants build on `DeprovisionHandler` and use `DeprovisionAction` to schedule filesystem cleanup.

| Handler | Specialization |
|---|---|
| `ArchDeprovisionHandler` | Extends the default plan to remove `/etc/machine-id`. |
| `CoreOSDeprovisionHandler` | Extends the default plan to remove `/etc/machine-id`. |
| `ClearLinuxDeprovisionHandler` | Retains its distro object but returns the default warnings and actions unchanged. |
| `UbuntuDeprovisionHandler` | Removes either `/etc/resolv.conf` or resolver state files, depending on the resolved target of `/etc/resolv.conf`. |
| `Ubuntu1804DeprovisionHandler` | Overrides Ubuntu resolver cleanup so `/etc/resolv.conf` is preserved and the behavior change is reported. |

## How

### Shared action-planning flow

1. The selected distro handler enters the default deprovision workflow.
2. The default handler produces the baseline `warnings` and `actions` collections.
3. The distro handler appends warnings before adding corresponding cleanup actions.
4. Cleanup is represented by `DeprovisionAction` instances, usually wrapping `fileutil.rm_files`, rather than performed while the plan is assembled.
5. The completed warning and action collections return to the deprovision orchestrator.

### Arch and CoreOS machine identity

`ArchDeprovisionHandler.setup` and `CoreOSDeprovisionHandler.setup` follow the same sequence: call the base setup, warn that `/etc/machine-id` will be removed, and append a file-removal action for that path. Changes to this behavior should remain aligned unless the distributions intentionally diverge.

### Ubuntu resolver state

`UbuntuDeprovisionHandler.del_resolv` selects cleanup from the canonical path:

| Condition | Warning and planned cleanup |
|---|---|
| `/etc/resolv.conf` does not resolve to `/run/resolvconf/resolv.conf` | Remove `/etc/resolv.conf`. |
| `/etc/resolv.conf` resolves to `/run/resolvconf/resolv.conf` | Remove `/etc/resolvconf/resolv.conf.d/tail` and `/etc/resolvconf/resolv.conf.d/original`. |

`Ubuntu1804DeprovisionHandler.del_resolv` deliberately replaces that policy: it adds a warning that `/etc/resolv.conf` will not be removed and schedules no resolver-file deletion.

### Change guidance

- Add distro cleanup through warnings and deferred actions; do not delete files during plan construction.
- Preserve the base handler's warnings and actions when overriding `setup`.
- Keep warnings accurate and adjacent to the actions they describe.
- Treat Ubuntu 18.04 resolver preservation as an intentional compatibility boundary.
- Update handler dispatch separately when introducing a new distro-specific implementation.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Arch machine-ID cleanup | `azurelinuxagent/pa/deprovision/arch.py` | `ArchDeprovisionHandler`; `setup` |
| Clear Linux default-only plan | `azurelinuxagent/pa/deprovision/clearlinux.py` | `ClearLinuxDeprovisionHandler`; `setup` |
| CoreOS machine-ID cleanup | `azurelinuxagent/pa/deprovision/coreos.py` | `CoreOSDeprovisionHandler`; `setup` |
| Ubuntu resolver cleanup | `azurelinuxagent/pa/deprovision/ubuntu.py` | `UbuntuDeprovisionHandler`; `Ubuntu1804DeprovisionHandler`; `del_resolv` |
| Shared deprovision contract | `azurelinuxagent/pa/deprovision/default.py` | `DeprovisionHandler`; `DeprovisionAction` |

## Related Components

- [Deprovision Handler Dispatch](../L1-conceptual/deprovision-handler-dispatch.md) — package-level factory boundary that selects the applicable handler.
- `azurelinuxagent.pa.deprovision.default` — baseline workflow and deferred-action model extended by these distro handlers.
