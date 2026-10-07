# SCVMM Agent Integration


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L3-flows/scvmm-agent-integration.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `ScvmmHandler` detects Microsoft System Center Virtual Machine Manager (SCVMM) media, launches its `install` script asynchronously, then delays and exits the Linux Agent process. If no SCVMM configuration media is found, control returns without changing the process lifecycle.

## Why

SCVMM supplies guest initialization through attached virtual media rather than the normal Azure provisioning path. This integration discovers that media, hands initialization to the SCVMM-provided script, and prevents the Linux Agent from continuing once SCVMM takes ownership.

The flow relies on the distribution-specific OS utility abstraction for device mounting, so detection remains independent of a concrete Linux distribution.

## What

`ScvmmHandler` coordinates three responsibilities:

1. Discover candidate optical devices under `/dev`.
2. Identify SCVMM media by the presence of `linuxosconfiguration.xml`.
3. Start the media's `install` script and terminate the current agent process after a five-minute handoff delay.

`get_scvmm_handler` is the construction boundary. It creates a handler whose OS operations come from `get_osutil`.

### Detection contract

Candidate device names match `sr[0-9]`, `hd[c-z]`, `cdrom[0-9]?`, or `cd[0-9]+`. Each candidate is mounted at the configured DVD mount point with one retry and non-fatal mount error handling.

- Media containing `linuxosconfiguration.xml` is treated as SCVMM media.
- Non-matching media is unmounted before the scan continues.
- Detection stops at the first match and returns `True`.
- Exhausting all candidates returns `False`.
- Loading the `ata_piix` support module is best effort and does not block scanning.

## How

### End-to-end sequence

1. A daemon caller obtains a handler through `get_scvmm_handler`.
2. `ScvmmHandler.__init__` resolves the distribution OS utility through `get_osutil`.
3. `ScvmmHandler.run` calls `ScvmmHandler.detect_scvmm_env`.
4. Detection attempts to load ATAPI support and reads the DVD mount point from configuration.
5. For each candidate device, the handler mounts it and checks for `linuxosconfiguration.xml`.
6. On a match, `ScvmmHandler.start_scvmm_agent` launches `/bin/bash <mount>/install "-p <mount>"`.
7. Standard output and standard error from the child process are redirected to the null device; the launch is asynchronous.
8. Detection returns success to `run`, which logs exit intent, sleeps for 300 seconds, and exits with status `0`.
9. If detection returns false, `run` returns normally and does not exit the process.

### Operational boundaries

- The matching SCVMM DVD remains mounted for the startup script; only rejected media is unmounted.
- `start_scvmm_agent` uses the configured DVD mount point when no mount point is supplied.
- Script launch failures from `subprocess.Popen` are not suppressed by this flow.
- Child-process output is intentionally unavailable for diagnosis; use the surrounding agent logs and SCVMM media/script behavior.
- The five-minute delay is part of the ownership handoff, not process supervision: the handler does not wait on or inspect the child process.

### Change guidance

- Keep device matching aligned with Linux optical-device naming conventions supported by `mount_dvd`.
- Preserve unmounting of rejected media and retention of matched media until the SCVMM script can consume it.
- Treat `linuxosconfiguration.xml` and `install` as the media contract; coordinate changes with the SCVMM media producer.
- Preserve the distinction between “not detected” and launch failure: absence returns `False`, while startup errors should remain visible.
- Route platform-specific mount behavior through the OS utility abstraction rather than adding distribution branches here.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| SCVMM factory and orchestration | `azurelinuxagent/daemon/scvmm.py` | `get_scvmm_handler`, `ScvmmHandler` |
| Media detection | `azurelinuxagent/daemon/scvmm.py` | `ScvmmHandler.detect_scvmm_env`, `VMM_CONF_FILE_NAME` |
| Startup and process handoff | `azurelinuxagent/daemon/scvmm.py` | `ScvmmHandler.start_scvmm_agent`, `ScvmmHandler.run`, `VMM_STARTUP_SCRIPT_NAME` |
| OS utility selection | `azurelinuxagent/common/osutil/factory.py` | `get_osutil` |
| DVD mount-point configuration | `azurelinuxagent/common/conf.py` | `get_dvd_mount_point` |
| Flow logging | `azurelinuxagent/common/logger.py` | `info` |

## Related Components

- [Daemon Entrypoint](daemon-entrypoint.md) — daemon construction and lifecycle boundary surrounding specialized handlers.
- [Distribution OS Adapters](../L2-platform/distribution-os-adapters.md) — platform-specific OS utility selected by `get_osutil`.
- [Agent Logging Service](../L2-platform/agent-logging-service.md) — logging used for detection, startup, and exit notices.
