# RDMA Handler Factory


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/rdma-handler-factory.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `get_rdma_handler` is the construction boundary that selects the Linux-distribution-specific RDMA handler used by the agent. It isolates callers, including packaging setup, from concrete SUSE, CentOS-family, and Ubuntu implementations and safely falls back to the base `RDMAHandler`.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/rdma-handler-factory.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

RDMA driver installation and configuration differ across Linux distributions. Callers need one stable entry point instead of importing platform handlers directly or duplicating distribution and version checks.

The factory centralizes that decision and keeps packaging code dependent on the factory contract rather than a concrete handler.

## What

`get_rdma_handler` accepts a distribution name and version, defaulting to the agent's detected `DISTRO_FULL_NAME` and `DISTRO_VERSION`.

| Platform match | Returned handler |
|---|---|
| SUSE Linux Enterprise Server, SLES, or SLE_HPC newer than version 11 | `SUSERDMAHandler` |
| CentOS, Red Hat Enterprise Linux, AlmaLinux, CloudLinux, or Rocky Linux | `CentOSRDMAHandler` |
| Ubuntu | `UbuntuRDMAHandler` |
| Any unsupported distribution or version | Base `RDMAHandler` |

The base-handler fallback is intentional: unsupported platforms remain operable without distribution-specific RDMA behavior. The factory logs the unmatched distribution and version before returning it.

## How

### Selection flow

1. Resolve the distribution identity from explicit arguments or agent version metadata.
2. For SUSE-family systems, compare versions through `DistroVersion`; only releases newer than 11 select the SUSE handler.
3. Match CentOS and related enterprise distributions as a shared handler family, forwarding the distribution version to `CentOSRDMAHandler`.
4. Select `UbuntuRDMAHandler` for Ubuntu.
5. Log unmatched platform metadata and return `RDMAHandler`.

### Integration contract

- Call `get_rdma_handler` instead of constructing a platform handler directly.
- Pass explicit distribution values in tests or when selection must not depend on host detection.
- Keep aliases and version gates in the factory so every caller receives consistent behavior.
- Preserve the generic fallback when adding platforms; unsupported hosts must not fail merely because no specialized handler exists.
- The import in `setup.py` makes this factory available to packaging and installation workflows.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| RDMA handler selection boundary | `azurelinuxagent/pa/rdma/factory.py` | `get_rdma_handler`; `DistroVersion` |
| Generic fallback behavior | `azurelinuxagent/pa/rdma/rdma.py` | `RDMAHandler` |
| SUSE implementation | `azurelinuxagent/pa/rdma/suse.py` | `SUSERDMAHandler` |
| CentOS-family implementation | `azurelinuxagent/pa/rdma/centos.py` | `CentOSRDMAHandler` |
| Ubuntu implementation | `azurelinuxagent/pa/rdma/ubuntu.py` | `UbuntuRDMAHandler` |
| Packaging integration | `setup.py` | `get_rdma_handler` |

## Related Components

- **Distribution metadata:** `azurelinuxagent.common.version` supplies the default distribution name and version.
- **Distribution version comparison:** `azurelinuxagent.common.utils.distro_version.DistroVersion` provides ordered SUSE version checks.
- **Platform RDMA handlers:** `SUSERDMAHandler`, `CentOSRDMAHandler`, and `UbuntuRDMAHandler` own distribution-specific driver operations behind the common `RDMAHandler` contract.
