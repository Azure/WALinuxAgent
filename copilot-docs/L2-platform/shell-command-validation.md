# Shell Command Validation


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/shell-command-validation.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** WALinuxAgent centralizes subprocess execution in `shellutil` and builds package-signature validation on that explicit command/error contract. Compatibility shims keep command output and timeout behavior stable on legacy Python, while signature checks enforce OpenSSL prerequisites and run resource-intensive validation under cgroup controls.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/shell-command-validation.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The agent invokes host tools whose availability, exit codes, output encoding, and runtime APIs vary across distributions and Python versions. Package signature validation adds a security-sensitive OpenSSL workflow that must distinguish unsupported capability, command failure, and invalid package state without treating any of them as success.

These boundaries provide:

- One subprocess contract for command discovery, execution, output capture, logging, and expected-error handling.
- Typed command and package-validation failures that retain command, return-code, output, and inner-error context.
- Legacy Python compatibility for `check_output`, `CalledProcessError`, and timeout behavior.
- Explicit OpenSSL version and signing-certificate prerequisites.
- Resource governance and operation telemetry around package validation.

## What

### Command execution contract

`shellutil` is the shared host-command boundary. `has_command` checks whether a required executable is available. `run` executes commands when only completion status matters, while `run_get_output` captures output and exposes controls for command logging and known expected errors. `_popen` owns process creation, `_on_command_completed` applies completion policy, and `__encode_command_output` normalizes output for logging and exceptions.

Callers choose whether nonzero status is fatal through `chk_err` and may identify `expected_errors` that should follow the documented non-fatal path. Unexpected failures remain explicit as `CommandError`; they must not be converted to empty output or a successful status.

### Runtime compatibility

The setup compatibility layer backports `subprocess.check_output` where the runtime does not provide it. It captures standard output, raises `CalledProcessError` on nonzero exit, and supplies a fallback `TimeoutExpired` type on Python 2. These shims preserve the subprocess-shaped interface expected by command helpers without spreading version branches through callers.

### Package signature validation

`signature_validation_util` consumes the shell-command contract to validate agent packages with OpenSSL. Validation depends on:

- The Microsoft signing certificate path from `get_microsoft_signing_certificate_path`.
- OpenSSL `1.1.0` or later, represented by `_MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION`, because CMS verification requires `no_check_time`.
- Persistent validation state in `_PACKAGE_VALIDATION_STATE_FILE`.
- `PackageValidationError` for validation-specific failure context and codes.
- Agent identity/version metadata for telemetry.

The validation operation is isolated through `CGroupConfigurator` using the package-validation CPU quota, slice, and systemd unit constants. Systemd launch failures are classified with `is_systemd_run_failure`; cgroup disablement remains a distinct platform-governance outcome rather than proof that a package is valid.

### Observability and state

Validation emits operation and elapsed-time data through `add_event`, `WALAEventOperation`, and `elapsed_milliseconds`. Timestamp sentinels such as `datetime_min_utc` support state initialization, and `FlexibleVersion` provides reliable OpenSSL capability comparison. Command and validation errors retain their original context for searchable logs and telemetry.

## How

### Validation flow

1. Resolve the signing certificate and load the package-validation state.
2. Check command availability and determine the installed OpenSSL version.
3. Reject or bypass validation only according to the explicit capability policy; never infer success from a missing tool or unsupported version.
4. Build the OpenSSL CMS verification command.
5. Execute it through `run_command`/`shellutil`, under the package-validation cgroup when supported.
6. Translate command, systemd, or validation failures into `PackageValidationError` with the original cause and code.
7. Persist the resulting validation state and emit duration and outcome telemetry.

### Change guidance

- Route new host commands through `shellutil`; do not add ad hoc `subprocess` handling that bypasses logging, output normalization, or typed errors.
- Keep `chk_err` and `expected_errors` semantics explicit at each call site. Expected failures may be suppressed only when the caller has a documented recovery path.
- Preserve command text, return code, and output when translating `CommandError` into a domain error.
- Compare tool versions with `FlexibleVersion`, not lexical string ordering.
- Keep OpenSSL feature requirements synchronized with the exact flags used by signature verification.
- Treat cgroup/systemd launch failure separately from cryptographic verification failure.
- Update validation state only after the outcome is known, and emit one operation-level event with elapsed time.
- Preserve fallback subprocess behavior while legacy Python remains supported.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Shell command execution | `azurelinuxagent/common/utils/shellutil.py` | `has_command`; `run`; `run_get_output`; `run_command`; `CommandError` |
| Process creation and completion | `azurelinuxagent/common/utils/shellutil.py` | `_popen`; `_on_command_completed`; `__encode_command_output` |
| Package signature validation | `azurelinuxagent/ga/signature_validation_util.py` | `PackageValidationError`; `_PACKAGE_VALIDATION_STATE_FILE`; `_MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION` |
| Signing certificate lookup | `azurelinuxagent/ga/signing_certificate_util.py` | `get_microsoft_signing_certificate_path` |
| Validation resource isolation | `azurelinuxagent/ga/cgroupconfigurator.py` | `CGroupConfigurator`; `PKG_SIGNATURE_VALIDATION_CPU_QUOTA`; `PKG_SIGNATURE_VALIDATION_SLICE_NAME`; `PKG_SIGNATURE_VALIDATION_CGROUPS_UNIT_NAME`; `DisableCgroups` |
| Version comparison | `azurelinuxagent/common/utils/flexible_version.py` | `FlexibleVersion` |
| Legacy subprocess compatibility | `setup.py` | `TimeoutExpired`; `check_output`; `CalledProcessError` |
| Validation telemetry | `azurelinuxagent/common/event.py` | `add_event`; `WALAEventOperation`; `elapsed_milliseconds` |

## Related Components

- [Platform Error Handling](platform-error-handling.md) — defines typed command, agent, crypto, and resource-governance failure semantics.
- [Runtime Compatibility Helpers](runtime-compatibility-helpers.md) — normalizes text, datetime, and subprocess behavior across supported Python runtimes.
- [Cgroup Resource Governance](cgroup-resource-governance.md) — provides the systemd/cgroup controls used to isolate package validation.
- [Flexible Version Comparison](flexible-version-comparison.md) — compares OpenSSL capability versions safely.
- [Agent Event Reporting](agent-event-reporting.md) — records validation outcome and duration.
