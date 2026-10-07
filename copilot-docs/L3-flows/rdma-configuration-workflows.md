# RDMA Configuration Workflows


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L3-flows/rdma-configuration-workflows.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** RDMA setup selects a distribution-specific driver handler, reconciles the driver with the Network Direct firmware version when enabled, then configures either a legacy Network Direct device or an SR-IOV InfiniBand interface from host-provided metadata. Firmware presence is the main branch: an ND version selects Network Direct, while its absence selects SR-IOV.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L3-flows/rdma-configuration-workflows.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Azure RDMA provisioning spans host metadata, kernel modules, distribution package managers, and network interfaces. The workflow centralizes common discovery and device configuration while isolating package and reboot policy behind distribution-specific handlers.

## What

The component has three cooperating layers:

| Layer | Responsibility |
|---|---|
| Handler selection | `get_rdma_handler` maps the current distribution and version to a specialized handler, or returns the base `RDMAHandler` for unsupported systems. |
| Driver reconciliation | `RDMAHandler` discovers `NdDriverVersion`, applies feature gates, and provides module and reboot primitives; distro subclasses implement package-specific installation. |
| Device provisioning | `setup_rdma_device` extracts RDMA addressing from SharedConfig and delegates Network Direct or SR-IOV configuration to `RDMADeviceHandler`. |

The supported handler families are Ubuntu, SUSE newer than SLES 11, and CentOS/RHEL-compatible distributions including AlmaLinux, CloudLinux, and Rocky Linux.

## How

### End-to-end flow

1. `get_rdma_handler` selects the distro implementation from the normalized distribution name and version.
2. `RDMAHandler.get_rdma_version` reads `NdDriverVersion` from `/var/lib/hyperv/.kvp_pool_0` and caches it.
3. `RDMAHandler.install_driver_if_needed` runs distro installation only when an ND version exists and `enable_check_rdma_driver` is enabled.
4. `setup_rdma_device` parses SharedConfig, finds `Instance`, reads `rdmaIPv4Address` and `rdmaMacAddress`, and normalizes the MAC with colon separators.
5. `RDMADeviceHandler.start` dispatches by firmware presence:
   - ND version present: run Network Direct provisioning.
   - ND version absent: run SR-IOV InfiniBand provisioning.
6. Device-level exceptions are logged by `RDMADeviceHandler.process`; malformed SharedConfig or a missing `Instance` ends setup before device processing.

### Distribution-specific driver reconciliation

| Handler | Decision and action |
|---|---|
| `CentOSRDMAHandler` | Ensures a Hyper-V KVP daemon is running, matches RPMs to the firmware version, refreshes Yum repositories, installs wrapper plus kernel/user-mode packages from `/opt/microsoft/rdma/rhel<major><minor>`, and reboots when the module cannot be loaded. |
| `SUSERDMAHandler` | Skips special drivers on SLE 15+, otherwise selects the default- or Azure-kernel KMP, installs a firmware-matched package from Zypper or local RPMs, locks it, and reboots when an active driver must be replaced. |
| `UbuntuRDMAHandler` | Resolves the current module alias, points `vmbus-rdma.conf` at an already-installed firmware-specific module, or—when `enable_rdma_update` permits—updates an Azure kernel and reboots. |
| `RDMAHandler` | Provides discovery and module operations but logs that driver installation is not implemented; this is the fallback for unsupported distributions. |

`RDMAHandler.reboot_system` exists because the active RDMA kernel module cannot reliably be unloaded during replacement. Treat reboot calls as intentional workflow outcomes, not ordinary cleanup.

### Network Direct path

`RDMADeviceHandler.provision_network_direct_rdma`:

1. Updates the first existing DAPL configuration in `dapl_config_paths` with the RDMA IPv4 address.
2. If driver checking is disabled, skips module inspection and configures the interface directly.
3. Otherwise resolves and loads `hv_network_direct`, then inspects its version.
4. For driver 4.1 or later, skips writing the legacy `/dev/hvnd_rdma` device; older or unversioned drivers wait for that device and receive the formatted MAC/IP payload.
5. Locates the Ethernet interface by MAC, brings it up, and assigns the IPv4 address with a `/16` prefix.

### SR-IOV path

`RDMADeviceHandler.provision_sriov_rdma` first looks for `IPoIB_Data` in KVP pool 0:

- For multiple entries, it validates the declared pair count, matches each host MAC/IP pair to an InfiniBand interface, and retries address assignment.
- For a single SharedConfig IPv4 address, it waits for an InfiniBand device, brings the discovered `ib*` interface up, and assigns the address with a `/16` prefix.
- Without either source of addressing, it logs that the IP address is missing and performs no interface update.

### Change guidance

- Keep distribution detection in `factory.py`; add package-manager behavior only in the corresponding handler.
- Preserve both feature gates: `enable_check_rdma_driver` controls reconciliation and Network Direct checks, while `enable_rdma_update` controls Ubuntu kernel upgrades.
- Do not collapse firmware absence into an error: it deliberately selects SR-IOV provisioning.
- Maintain the Network Direct compatibility boundary that writes `/dev/hvnd_rdma` only for drivers older than 4.1.
- Keep KVP parsing, timeout/retry behavior, and reboot decisions explicit because they coordinate asynchronous host and kernel state.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Handler selection | `azurelinuxagent/pa/rdma/factory.py` | `get_rdma_handler` |
| Shared setup and device configuration | `azurelinuxagent/pa/rdma/rdma.py` | `RDMAHandler`; `RDMADeviceHandler`; `setup_rdma_device` |
| CentOS/RHEL-family packages | `azurelinuxagent/pa/rdma/centos.py` | `CentOSRDMAHandler`; `install_driver`; `check_or_install_kvp_daemon` |
| SUSE packages | `azurelinuxagent/pa/rdma/suse.py` | `SUSERDMAHandler`; `install_driver` |
| Ubuntu module and kernel updates | `azurelinuxagent/pa/rdma/ubuntu.py` | `UbuntuRDMAHandler`; `install_driver`; `update_modprobed_conf` |

## Related Components

- [RDMA Handler Factory](../L1-conceptual/rdma-handler-factory.md) — conceptual ownership and distribution dispatch contract.
- [Distribution Version Model](../L1-conceptual/distribution-version-model.md) — version comparison used to gate SUSE handler selection and SLE behavior.
- [Distribution OS Adapters](../L2-platform/distribution-os-adapters.md) — broader platform-specific adaptation patterns.
