# Resource Disk Factory


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/resource-disk-factory.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `get_resourcedisk_handler` is the stable construction boundary for resource-disk management. It selects a FreeBSD, OpenBSD, or OpenWRT implementation when needed and otherwise returns the default `ResourceDiskHandler`.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/resource-disk-factory.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Resource-disk discovery, formatting, mounting, and swap setup depend on the host operating system. Callers need one stable entry point rather than direct knowledge of every platform-specific handler.

The factory centralizes platform dispatch, keeps startup and packaging code decoupled from concrete implementations, and provides a safe default for mainstream Linux distributions.

## What

`get_resourcedisk_handler` accepts distribution name, version, and full-name metadata. Selection currently depends only on the normalized distribution name.

| Distribution name | Returned handler |
|---|---|
| `freebsd` | `FreeBSDResourceDiskHandler` |
| `openbsd` | `OpenBSDResourceDiskHandler` |
| `openwrt` | `OpenWRTResourceDiskHandler` |
| Any other value | `ResourceDiskHandler` |

The distribution version and full name remain part of the factory signature for a consistent handler-factory API and future selection rules, although they do not currently affect dispatch.

## How

1. The caller invokes `get_resourcedisk_handler`, normally using distribution metadata detected by `azurelinuxagent.common.version`.
2. The factory compares the distribution name against the supported specialized platforms.
3. A matching platform creates and returns its dedicated handler.
4. Any unmatched platform receives the default `ResourceDiskHandler`.
5. Callers use the returned handler through the common resource-disk behavior instead of branching on the operating system themselves.

### Integration contract

- Obtain handlers through `get_resourcedisk_handler`; do not duplicate platform selection in callers.
- Pass an explicit distribution name in tests when deterministic selection is required.
- Add new platform mappings in the factory while preserving `ResourceDiskHandler` as the generic fallback.
- Keep platform-specific disk behavior in its handler module rather than embedding it in dispatch logic.
- Preserve the factory import in `setup.py`, which makes the selection boundary available to packaging and installation workflows.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Handler selection boundary | `azurelinuxagent/daemon/resourcedisk/factory.py` | `get_resourcedisk_handler` |
| Default resource-disk behavior | `azurelinuxagent/daemon/resourcedisk/default.py` | `ResourceDiskHandler` |
| FreeBSD specialization | `azurelinuxagent/daemon/resourcedisk/freebsd.py` | `FreeBSDResourceDiskHandler` |
| OpenBSD specialization | `azurelinuxagent/daemon/resourcedisk/openbsd.py` | `OpenBSDResourceDiskHandler` |
| OpenWRT specialization | `azurelinuxagent/daemon/resourcedisk/openwrt.py` | `OpenWRTResourceDiskHandler` |
| Packaging integration | `setup.py` | `get_resourcedisk_handler` |

## Related Components

- **Distribution metadata:** `azurelinuxagent.common.version` supplies the default distribution name, version, and full name.
- **Resource-disk handlers:** the default and platform-specific handler modules own disk operations after factory selection.
- [Provision Handler Selection](provision-handler-selection.md) documents a similar factory boundary for provisioning implementations.
- [RDMA Handler Factory](rdma-handler-factory.md) documents distribution-based selection for RDMA management.
