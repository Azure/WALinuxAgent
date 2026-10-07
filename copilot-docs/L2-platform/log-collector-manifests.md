# Log Collector Manifests


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/log-collector-manifests.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `logcollector_manifests.py` defines the declarative command lists used to build normal and full Azure Linux Agent diagnostic bundles. The manifests tell the collector which directories to list and which host, agent, extension, boot, and network artifacts to copy.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/log-collector-manifests.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Support investigations need a predictable diagnostic snapshot without hard-coding every path in the collection engine. These manifests separate collection policy from execution: they define useful Linux and agent artifacts in a compact command format while allowing the collector to resolve runtime-specific directories.

Two scopes balance diagnostic coverage against bundle size and sensitivity:

- Normal collection focuses on core agent, operating-system, extension, and configuration evidence.
- Full collection adds broader provisioning, boot, SSH, device, resolver, firewall, and distribution-specific network state.

## What

### Manifest command model

Both manifests are multiline command streams. Each nonblank line consists of an operation and, when needed, a comma-separated operand.

| Operation | Purpose | Examples of targets |
|---|---|---|
| `echo` | Add section headings or spacing to collector output. | Probing, configuration, log, and extension sections |
| `ll` | Record a directory listing without copying the directory wholesale. | `/var/log`, `$LIB_DIR`, `/etc/udev/rules.d` |
| `copy` | Add matching files to the diagnostic bundle. | Configuration, logs, extension state, and goal-state history |

Paths may contain shell-style wildcards and collector variables. `$AGENT_LOG`, `$LOG_DIR`, and `$LIB_DIR` keep the policy independent of configured agent locations; the execution layer must expand them before or while processing commands.

### Normal scope

`MANIFEST_NORMAL` gathers the baseline evidence needed for common agent and extension failures:

- Directory inventories for `/var/log` and the agent library directory.
- Distribution and hostname files plus `/etc/waagent.conf`.
- Agent logs, kernel messages, syslog, authentication logs, nested agent log directories, and the custom-script handler log.
- Provisioning and extension state including `ovf-env.xml`, `waagent_status.json`, extension status and settings, handler state/status, `error.json`, and archived history ZIP files.

The extension patterns span versioned extension directories, making collection independent of a specific extension name or installed version.

### Full scope

`MANIFEST_FULL` begins with the same category-oriented structure but broadens host inspection. The supplied manifest includes:

- Provisioning markers and filesystem configuration.
- SSH server and GRUB boot-loader configuration.
- Distribution identity and hostname data.
- Debian/Ubuntu interfaces and netplan configuration.
- Name-service and resolver configuration, including systemd-resolved and resolvconf paths.
- Firewall configuration for iptables, SuSEfirewall2, and UFW.
- Red Hat/SUSE-style network, interface, and route files.
- Udev rules directory inspection.

These paths intentionally cover several Linux networking and init ecosystems. Missing files or unmatched globs are expected on distributions that use a different layout and should be handled by the manifest executor as collection outcomes, not manifest-definition errors.

### Data considerations

The manifests collect operational configuration and extension state that can contain deployment-specific or sensitive values. Changes should preserve the collector's existing filtering, redaction, permissions, and archive-handling boundaries rather than treating these constants as safe-to-publish file lists.

## How

### Collection flow

1. The caller selects `MANIFEST_NORMAL` or `MANIFEST_FULL` according to the requested diagnostic scope.
2. The collector parses the manifest line by line.
3. `echo` commands organize output, while `ll` probes directories and `copy` resolves files and globs.
4. Runtime variables map abstract agent locations to the configured log and library directories.
5. Available artifacts are added to the diagnostic package; platform-specific absent paths are skipped or reported by the execution layer.

The module defines collection policy only. Parsing, variable substitution, filesystem access, error reporting, redaction, and package creation belong to the log collector that consumes these constants.

### Change guidance

- Put broadly useful, low-volume evidence in `MANIFEST_NORMAL`; reserve expansive or specialized host state for `MANIFEST_FULL`.
- Keep entries grouped under descriptive `echo` headings so bundle contents remain navigable.
- Use `$AGENT_LOG`, `$LOG_DIR`, and `$LIB_DIR` instead of duplicating default installation paths.
- Preserve cross-distribution alternatives; do not replace one distribution's path with another's.
- Prefer narrow globs and explicit files over recursive collection to control bundle size and accidental disclosure.
- When adding extension artifacts, account for versioned extension directories and multiple status/config instances.
- Coordinate new operations or syntax with the manifest parser; these constants cannot introduce commands the execution layer does not understand.
- Review new targets for secrets, credentials, customer payloads, and unbounded file growth.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Standard diagnostic collection policy | `azurelinuxagent/ga/logcollector_manifests.py` | `MANIFEST_NORMAL` |
| Expanded host diagnostic collection policy | `azurelinuxagent/ga/logcollector_manifests.py` | `MANIFEST_FULL` |

## Related Components

- [Archive Operations](archive-operations.md) — the normal manifest collects ZIP snapshots from the agent history directory.
- [Agent Logging Service](agent-logging-service.md) — agent logs selected through `$AGENT_LOG` are core diagnostic-bundle inputs.
- [Distribution OS Adapters](distribution-os-adapters.md) — full collection spans distribution-specific network, firewall, resolver, and service layouts.
