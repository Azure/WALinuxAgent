# OS Service Management


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/os-service-management.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `azurelinuxagent.common.osutil.systemd` centralizes systemd detection, agent unit discovery, runtime property management, and `systemd-run` failure classification. It delegates distro-specific service names and install paths to the OS utility selected by `get_osutil()`.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/os-service-management.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The agent runs across distributions that differ in service names, systemd unit locations, and OS integration details. Callers also need consistent handling for transient resource settings and must distinguish a failure to create a systemd scope from a command that ran inside the scope and failed.

This component keeps those concerns behind one boundary:

- Distribution selection remains in the OS utility factory.
- Unit naming and installation paths come from the selected OS utility.
- `systemctl` invocation, output parsing, and error normalization stay centralized.
- Resource-governance callers receive a clear signal when `systemd-run` itself failed and fallback behavior is appropriate.

## What

### Service-manager facade

The module exposes stateless helpers plus a lazily cached OS utility:

| Concern | Behavior |
|---|---|
| Manager detection | `is_systemd()` checks `/run/systemd/system/`, matching the conventional systemd boot test. |
| Version reporting | `get_version()` returns the first line from `systemctl --version`, or `"unknown"` when probing fails. |
| Agent unit discovery | Unit names and paths are composed from `OSUtil.get_service_name()` and `OSUtil.get_systemd_unit_file_install_path()`. |
| Property inspection | `get_unit_property()` runs `systemctl show` and extracts the value after `=`; malformed output raises `ValueError`. |
| Runtime configuration | Single or multiple properties are passed to `systemctl set-property --runtime`; settings last only until reboot. |
| Unit availability | `is_unit_loaded()` checks whether `LoadState` is `loaded`, treating command failure as not loaded. |
| Failure classification | `is_systemd_run_failure()` identifies infrastructure failures separately from errors produced by the launched command. |

### OS utility selection

`factory.get_osutil()` selects a distro- and version-specific `OSUtil` implementation, falling back to `DefaultOSUtil` for unknown distributions. The systemd facade caches that result through `_get_os_util()` and uses only the service-related OS utility contract; it does not encode per-distribution paths or service names itself.

### Error contracts

- Property queries reject output that does not contain a non-empty `name=value` result.
- Property updates translate `shellutil.CommandError` into contextual `ValueError`.
- Batch updates require equal property-name and value counts.
- A `systemd-run` error is classified as infrastructure failure when stderr says the unit was not found or never mentions the requested unit.
- If stderr mentions the unit without the not-found message, the command reached the unit and its failure belongs to the command, not systemd infrastructure.

## How

### Unit resolution

1. `_get_os_util()` initializes and caches `get_osutil()`.
2. `get_agent_unit_name()` appends `.service` to the distro-specific service name.
3. `get_agent_unit_file()` joins the install path and unit name.
4. `get_agent_drop_in_path()` derives the sibling `<unit>.d` directory for overrides.

### Runtime property flow

1. `get_unit_property()` invokes `systemctl show <unit> --property <name>`.
2. The returned `name=value` line is parsed and only the value is returned.
3. `set_unit_run_time_property()` formats one assignment; `set_unit_run_time_properties()` validates and formats a batch.
4. Both setters invoke `systemctl set-property <unit> ... --runtime`, preserving transient semantics.
5. Callers use `is_unit_loaded()` before depending on a target unit.

### `systemd-run` failure decision

1. `is_systemd_run_failure()` accepts either a Unicode string or a seekable stderr stream.
2. Streams are read only up to `TELEMETRY_MESSAGE_MAX_LEN` and decoded with replacement-safe error handling.
3. `"Unit <name> not found."` means scope creation or lookup failed.
4. Absence of the unit name means systemd failed before launching the command.
5. Any other stderr containing the unit name is attributed to the launched command and should propagate through normal command error handling.

### Change rules

- Add distro-specific service names and paths to the appropriate `OSUtil`; keep `systemd.py` distro-neutral.
- Preserve `--runtime` unless a caller explicitly requires persistent unit configuration.
- Keep batch property updates atomic at the `systemctl` invocation boundary.
- Do not broadly suppress property-management failures; callers rely on `ValueError` context.
- Maintain the infrastructure-versus-command distinction when extending `systemd-run` diagnostics, because it controls fallback behavior.
- Reset `_get_os_util.value` in tests that replace or reconfigure the OS utility.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Systemd detection and version probe | `azurelinuxagent/common/osutil/systemd.py` | `is_systemd()`; `get_version()` |
| Agent unit and drop-in discovery | `azurelinuxagent/common/osutil/systemd.py` | `_get_os_util()`; `get_unit_file_install_path()`; `get_agent_unit_name()`; `get_agent_unit_file()`; `get_agent_drop_in_path()` |
| Runtime unit properties | `azurelinuxagent/common/osutil/systemd.py` | `get_unit_property()`; `set_unit_run_time_property()`; `set_unit_run_time_properties()`; `is_unit_loaded()` |
| `systemd-run` failure classification | `azurelinuxagent/common/osutil/systemd.py` | `is_systemd_run_failure()` |
| Distribution-specific OS utility selection | `azurelinuxagent/common/osutil/factory.py` | `get_osutil()`; `_get_osutil()`; `DefaultOSUtil` and distro-specific `OSUtil` subclasses |
| Command execution boundary | `azurelinuxagent/common/utils/shellutil.py` | `run_command()`; `CommandError` |

## Related Components

- [Distribution Version Model](distribution-version-model.md) — supplies the loose version comparisons used by the OS utility factory to select distro-version-specific implementations.
- **Extension process and resource governance** (`azurelinuxagent/ga/extensionprocessutil.py`) — supplies the telemetry-safe stderr limit and consumes systemd failure classification when deciding whether fallback execution is appropriate.
- **Distribution OS utilities** (`azurelinuxagent/common/osutil/`) — own service names, systemd unit installation paths, and platform-specific behavior used by this facade.
