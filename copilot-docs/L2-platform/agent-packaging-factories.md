# Agent Packaging and Platform Factories


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/agent-packaging-factories.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** Packaging scripts assemble installable and publishable agent artifacts, while small runtime factories select OS-, provisioning-, deprovisioning-, and resource-disk-specific implementations. Both layers centralize platform variation so callers use stable entry points instead of duplicating distribution checks.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/agent-packaging-factories.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The Linux Agent must be installed on distributions with different filesystem layouts and service managers, then run with behavior appropriate to the detected platform. Scattering these differences across packaging and operational code would make support rules inconsistent and difficult to test.

This component concentrates variation at two boundaries:

- Build-time helpers map agent files into distribution-appropriate packages and publication artifacts.
- Runtime factories map detected distribution and configuration data to specialized handlers, with safe default implementations for broadly supported behavior.

## What

### Packaging surfaces

The repository-level `setup.py` builds the Python package and composes platform-specific `data_files`. Its helper functions add binaries, configuration, logrotate configuration, and service definitions for SysV, OpenRC, systemd, and BSD-style layouts. Agent metadata comes from the shared version module, while `get_osutil` informs platform-specific installation choices.

`makepkg.py` creates the versioned Guest Agent payload under an output `eggs` directory. It also produces:

- The Guest Agent handler manifest used to launch extension handling.
- Signing metadata derived from shared agent version constants.
- The XML publication manifest consumed when publishing the agent image.

`do` wraps subprocess execution and raises a diagnostic exception containing the command and captured output. `run` owns package assembly for an agent family and output directory.

### Runtime factory surfaces

| Factory | Selection inputs | Result |
|---|---|---|
| `get_osutil` | Distribution name, code name, version, and full name | Distribution-specific OS utility, with version-aware variants where required |
| `get_provision_handler` | `Provisioning.Agent` configuration and cloud-init detection | `CloudInitProvisionHandler` or the default `ProvisionHandler` |
| `get_deprovision_handler` | Distribution name, version, and full name | Arch, Ubuntu, CoreOS/Flatcar, Clear Linux, or default deprovision handler |
| `get_resourcedisk_handler` | Distribution name | FreeBSD, OpenBSD, OpenWRT, or default resource-disk handler |

The factories default their detection inputs from `azurelinuxagent.common.version`, but expose parameters so tests and callers can exercise explicit platform identities.

### Selection invariants

- Provisioning selection is configuration-led: explicit `cloud-init` selects cloud-init; `auto` selects it only when detection succeeds; otherwise waagent provisioning is used.
- Ubuntu deprovisioning changes at version `18.04`, using `DistroVersion` rather than lexical string comparison.
- Both `coreos` and `flatcar` use `CoreOSDeprovisionHandler`.
- Clear Linux is recognized through the distribution full name.
- Resource-disk specialization is intentionally narrow; unsupported distributions receive `ResourceDiskHandler`.
- OS utility selection is the broadest dispatch surface and is the shared source of distribution-specific system operations.

## How

### Installation and publication flow

1. `setup.py` reads shared agent and distribution metadata.
2. Packaging logic obtains the active OS utility and chooses destination layouts.
3. `set_*_files` helpers append binaries, configuration, log rotation, and the appropriate service definitions to package data.
4. Setuptools packages Python modules and platform data into an installable distribution.
5. `makepkg.run` stages the versioned Guest Agent payload and writes handler/signing metadata.
6. The publication manifest describes the image version, type, provider, supported OS, and metadata expected by the publishing system.

Keep package identity synchronized through `azurelinuxagent.common.version`; do not independently hard-code agent names or versions in packaging paths or manifests.

### Runtime dispatch flow

1. Shared version detection supplies distribution identity unless explicit values are passed.
2. The relevant factory evaluates only the rules needed by its subsystem.
3. Version-sensitive checks use `DistroVersion`.
4. The factory instantiates and returns one concrete handler or utility.
5. The caller proceeds through the common handler contract without further distribution branching.

For provisioning, cloud-init detection is performed only when configuration requests `auto`; the selected implementation is logged. Other factories use deterministic distribution mappings and fall back to their default implementation.

### Change guidance

- Add platform branches in the narrowest applicable factory; do not couple provisioning, deprovisioning, resource-disk, and OS utility dispatch.
- Preserve default fallbacks unless a platform must be rejected explicitly.
- Use `DistroVersion` for version boundaries and shared distribution constants for defaults.
- Update packaging service-file mappings when adding a new init-system layout.
- Keep handler manifests compatible with the Guest Agent's expected manifest filename and extension-handler command.
- Let subprocess failures from `makepkg.do` remain explicit and diagnostic.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Python package and platform file layout | `setup.py` | `set_files`; `set_bin_files`; `set_conf_files`; `set_logrotate_files`; `set_sysv_files`; `set_openrc_files`; `set_systemd_files` |
| Guest Agent payload and publication manifests | `makepkg.py` | `run`; `do`; `MANIFEST`; `PUBLISH_MANIFEST` |
| OS utility dispatch | `azurelinuxagent/common/osutil/factory.py` | `get_osutil`; distribution-specific `*OSUtil` classes |
| Provisioning dispatch | `azurelinuxagent/pa/provision/factory.py` | `get_provision_handler`; `ProvisionHandler`; `CloudInitProvisionHandler` |
| Deprovisioning dispatch | `azurelinuxagent/pa/deprovision/factory.py` | `get_deprovision_handler`; `DeprovisionHandler`; platform-specific deprovision handlers |
| Resource-disk dispatch | `azurelinuxagent/daemon/resourcedisk/factory.py` | `get_resourcedisk_handler`; `ResourceDiskHandler`; BSD/OpenWRT resource-disk handlers |
| Shared version and distribution identity | `azurelinuxagent/common/version.py` | `AGENT_NAME`; `AGENT_VERSION`; `AGENT_LONG_VERSION`; `DISTRO_NAME`; `DISTRO_VERSION`; `DISTRO_FULL_NAME` |
| Version-aware comparisons | `azurelinuxagent/common/utils/distro_version.py` | `DistroVersion` |

## Related Components

- [Distribution Version Model](../L1-conceptual/distribution-version-model.md) — defines ordering for version-dependent factory rules.
- [Provision Handler Selection](../L1-conceptual/provision-handler-selection.md) — details waagent versus cloud-init provisioning dispatch.
- [Deprovision Handler Dispatch](../L1-conceptual/deprovision-handler-dispatch.md) — details distribution-specific deprovisioning behavior.
- [Resource Disk Factory](../L1-conceptual/resource-disk-factory.md) — details specialized resource-disk handler selection.
- [OS Service Management](../L1-conceptual/os-service-management.md) — covers service-manager operations represented in package layouts.
