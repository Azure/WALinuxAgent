# Provision Handler Selection


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/provision-handler-selection.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `get_provision_handler` is the provisioning subsystem's stable factory entry point. It selects cloud-init when explicitly configured, or when automatic detection confirms cloud-init is enabled; otherwise it returns the native WALinuxAgent provisioning handler.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/provision-handler-selection.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Agent startup needs one provisioning implementation without coupling callers to configuration parsing, cloud-init detection, or concrete handler construction. The factory centralizes that policy behind a package-level function so startup code can request a handler and then use the resulting provisioning contract.

## What

The `azurelinuxagent.pa.provision` package re-exports `get_provision_handler` from its factory module. The factory chooses between:

| Selection result | Condition |
|---|---|
| `CloudInitProvisionHandler` | `Provisioning.Agent` is `cloud-init`. |
| `CloudInitProvisionHandler` | `Provisioning.Agent` is `auto` and `cloud_init_is_enabled` succeeds. |
| `ProvisionHandler` | Any other configuration or an automatic check that does not enable cloud-init. |

The factory accepts distribution name and version arguments for API compatibility, but current selection is driven by provisioning configuration and cloud-init detection rather than distro-specific dispatch.

## How

1. A caller imports `get_provision_handler` from `azurelinuxagent.pa.provision`.
2. `get_provision_handler` reads the configured provisioning agent through `conf.get_provisioning_agent`.
3. Explicit `cloud-init` configuration selects `CloudInitProvisionHandler`.
4. `auto` configuration delegates capability detection to `cloud_init_is_enabled`; a positive result selects `CloudInitProvisionHandler`.
5. All remaining cases select the native `ProvisionHandler`.
6. The factory logs whether cloud-init or waagent will perform provisioning before returning the new handler.

### Change guidance

- Keep callers on the package-level `get_provision_handler` API rather than importing concrete handlers directly.
- Change selection precedence only in `get_provision_handler`; duplicated policy can make daemon and agent startup diverge.
- Preserve the native handler as the fallback unless configuration semantics intentionally change.
- Treat the distro parameters as compatibility surface even though the current implementation does not use them.
- Update configuration, cloud-init detection, and provisioning tests together when adding a handler or changing `auto` behavior.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Public provisioning API | `azurelinuxagent/pa/provision/__init__.py` | `get_provision_handler` |
| Handler selection factory | `azurelinuxagent/pa/provision/factory.py` | `get_provision_handler` |
| Native provisioning implementation | `azurelinuxagent/pa/provision/default.py` | `ProvisionHandler` |
| Cloud-init integration | `azurelinuxagent/pa/provision/cloudinit.py` | `CloudInitProvisionHandler`; `cloud_init_is_enabled` |
| Provisioning configuration | `azurelinuxagent/common/conf.py` | `get_provisioning_agent` |

## Related Components

- [Deprovision Handler Dispatch](deprovision-handler-dispatch.md) describes the analogous package-level factory boundary for deprovisioning.
- `azurelinuxagent.daemon.main.Daemon` obtains the selected provisioning handler during daemon initialization.
- `azurelinuxagent.agent.Agent` uses the same factory for direct provisioning startup.
