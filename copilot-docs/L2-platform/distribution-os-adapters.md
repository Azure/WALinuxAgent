# Distribution OS Adapters


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/distribution-os-adapters.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** Distribution adapters extend `DefaultOSUtil` to translate the agent's common host-operation contract into each Linux variant's service manager, network stack, filesystem layout, and supported capabilities. Most adapters are intentionally thin; platform-specific behavior should remain isolated here and selected through `get_osutil`.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/distribution-os-adapters.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The Guest Agent performs the same logical operations on many distributions—restart networking, control DHCP and agent services, configure SSH, locate binaries and units, and discover DHCP lease endpoints—but the commands and supported operations differ substantially. A shared implementation alone would either contain pervasive distribution checks or execute unsafe commands on unsupported platforms.

These adapters provide:

- One `DefaultOSUtil` contract for higher-level agent code.
- Small overrides for init systems, network managers, and filesystem conventions.
- Explicit no-op behavior where the platform owns an operation or does not support it.
- Distribution-local command, retry, and error-handling semantics.
- Stable integration with the OS utility factory rather than branching at call sites.

## What

### Systemd and systemd-networkd adapters

`ArchUtil`, `ClearLinuxUtil`, `CoreOSUtil`, `MarinerOSUtil`, and `PhotonOSUtil` primarily map network, DHCP, agent, and SSH operations to `systemctl`. Their distinctions are important:

- `ArchUtil`, `ClearLinuxUtil`, `MarinerOSUtil`, and `PhotonOSUtil` install units under `/usr/lib/systemd/system` and generally place agent binaries under `/usr/bin`.
- `CoreOSUtil` uses OEM paths, extends `PATH` and `PYTHONPATH`, and treats the `core` account as a non-system user.
- `ClearLinuxUtil` reads configuration from `/usr/share/defaults/waagent/waagent.conf`.
- `MarinerOSUtil` routes service commands through `DefaultOSUtil._run_command_without_raising`.
- `PhotonOSUtil` uses direct shell commands and leaves SSH configuration to the platform.
- `ChainguardOSUtil` also uses systemd-networkd, derives its service name, and retries network restarts while logging command failures.

These similarities do not make the classes interchangeable: preserve each adapter's binary paths, configuration paths, failure behavior, and deliberate no-ops.

### Debian-family and versioned Ubuntu adapters

`DebianOSBaseUtil` supplies Debian-family service behavior and DHCP lease discovery. It reloads or restarts `ssh`, controls the agent through `service azurelinuxagent`, and looks for endpoints in dhclient lease files. Rules-file hooks and generic network startup are intentionally unimplemented.

`DevuanOSUtil` is independent of the Debian systemd behavior: it uses `/usr/sbin/service`, controls `walinuxagent`, and logs service actions explicitly.

`Ubuntu14OSUtil` establishes the `walinuxagent` service name, uses legacy `service` commands, converts `CommandError` into return codes, and uses dhclient lease discovery. Version subclasses specialize only the behavior that changed: for example, `Ubuntu12OSUtil.get_dhcp_pid` targets `dhclient3`; later Ubuntu variants build on the same family contract.

### Direct network-control adapters

`AlpineOSUtil` assumes DHCP is enabled through `dhcpcd`. It discovers the daemon with `get_dhcp_pid` and treats interface restart as a `SIGHUP` to that process. SSH keepalive and SSH configuration are platform-owned no-ops.

`FedoraOSUtil` cycles an interface with `ip link`, applying caller-provided retry and wait values. It controls `sshd` and `waagent` with systemd but leaves broad network and DHCP service lifecycle operations unimplemented.

### Specialized and appliance platforms

`OpenWRTOSUtil` adapts constrained OpenWRT behavior: it uses `udhcpc`, `/bin/ash`, ensures `/home` exists during user creation, parses interface output with `_ip_command_output`, and reports DVD ejection as unsupported. It also uses `NetworkInterfaceCard` for platform-specific network representation.

`IosxeOSUtil` reflects an appliance environment where only the daemon runs and provisioning and DHCP-based services are unavailable. Hostname changes prefer `hostnamectl` and fall back to `DefaultOSUtil.set_hostname`; service registration and host identity behavior are specialized for IOS XE.

## How

### Runtime interaction

1. Distribution detection supplies name, version, code name, and full name.
2. `get_osutil` selects the matching adapter.
3. The adapter initializes platform paths, service names, DHCP client identity, and capability flags.
4. Agent subsystems invoke the common `DefaultOSUtil` methods without further distribution checks.
5. The adapter executes the platform command, delegates to a default helper, or intentionally performs no action.
6. Return codes, `CommandError`, `OSUtilError`, retries, and logging retain the semantics expected by that platform.

### Behavioral boundaries

| Concern | Adapter behavior |
|---|---|
| Agent layout | Override configuration, binary, Python, and systemd-unit paths only where the distribution differs. |
| Network restart | Restart the network manager, cycle a link, or signal the DHCP client according to the platform. |
| DHCP lifecycle | Control the actual DHCP/network daemon; do not assume `dhclient` or systemd-networkd universally. |
| Service lifecycle | Use the distribution's service name and init mechanism, preserving expected return-code behavior. |
| SSH management | Restart the correct unit or leave configuration untouched when socket activation or platform ownership applies. |
| Unsupported operations | Keep deliberate no-ops or warnings explicit; do not substitute a generic command that may be unsafe. |

### Change guidance

- Add a distribution override only when `DefaultOSUtil` is incorrect for that platform; inherit shared behavior otherwise.
- Update `get_osutil` alongside a new adapter so the implementation is reachable.
- Preserve command failure semantics: some methods return codes, some suppress command errors, and others raise `OSUtilError`.
- Do not collapse platform-owned no-ops into generic SSH, DHCP, provisioning, or network mutations.
- Keep retries bounded and retain logging around recoverable network failures.
- Use argument-list command execution where the surrounding adapter already uses `run_command`; avoid introducing shell interpolation without need.
- Verify configuration, binary, service-unit, and lease-file paths against the target distribution.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Alpine/dhcpcd integration | `azurelinuxagent/common/osutil/alpine.py` | `AlpineOSUtil`; `get_dhcp_pid`; `restart_if`; `conf_sshd` |
| Arch systemd integration | `azurelinuxagent/common/osutil/arch.py` | `ArchUtil`; `start_network`; `restart_if`; `get_dhcp_pid` |
| Chainguard systemd integration | `azurelinuxagent/common/osutil/chainguard.py` | `ChainguardOSUtil`; `restart_if`; `is_dhcp_available`; `is_dhcp_enabled` |
| Clear Linux integration | `azurelinuxagent/common/osutil/clearlinux.py` | `ClearLinuxUtil`; `start_network`; `restart_if`; `get_agent_bin_path` |
| CoreOS OEM integration | `azurelinuxagent/common/osutil/coreos.py` | `CoreOSUtil`; `is_sys_user`; `start_network`; `restart_if` |
| Debian-family base | `azurelinuxagent/common/osutil/debian.py` | `DebianOSBaseUtil`; `restart_ssh_service`; `get_dhcp_lease_endpoint` |
| Devuan service integration | `azurelinuxagent/common/osutil/devuan.py` | `DevuanOSUtil`; `restart_ssh_service`; `start_agent_service`; `stop_agent_service` |
| Fedora link management | `azurelinuxagent/common/osutil/fedora.py` | `FedoraOSUtil`; `restart_if`; `restart_ssh_service` |
| IOS XE appliance integration | `azurelinuxagent/common/osutil/iosxe.py` | `IosxeOSUtil`; `set_hostname`; `publish_hostname`; `register_agent_service` |
| Azure Linux/Mariner integration | `azurelinuxagent/common/osutil/mariner.py` | `MarinerOSUtil`; `restart_if`; `register_agent_service` |
| OpenWRT integration | `azurelinuxagent/common/osutil/openwrt.py` | `OpenWRTOSUtil`; `useradd`; `get_dhcp_pid`; `eject_dvd` |
| Photon OS integration | `azurelinuxagent/common/osutil/photonos.py` | `PhotonOSUtil`; `restart_if`; `get_dhcp_pid`; `conf_sshd` |
| Ubuntu version family | `azurelinuxagent/common/osutil/ubuntu.py` | `Ubuntu14OSUtil`; `Ubuntu12OSUtil`; `Ubuntu16OSUtil`; `get_dhcp_pid` |

## Related Components

- [Agent Packaging and Platform Factories](agent-packaging-factories.md) — selects these adapters through `get_osutil` and uses their layout decisions during packaging.
- [OS Service Management](../L1-conceptual/os-service-management.md) — defines the shared service lifecycle abstractions implemented by distribution adapters.
- [Distribution Version Model](../L1-conceptual/distribution-version-model.md) — supports version-aware platform selection without lexical version comparisons.
