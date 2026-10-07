# Distribution Version Model


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/distribution-version-model.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `DistroVersion` converts arbitrary Linux distribution version strings into loosely ordered, comparable values. Use it for distro release checks where semantic-version parsers cannot safely handle vendor-specific formats.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/distribution-version-model.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Linux distributions expose releases as numeric versions, release candidates, rolling-build timestamps, vendor suffixes, code names, and free-form identifiers. Raw string comparison misorders numeric fragments, while semantic-version parsers reject many valid distro values.

`DistroVersion` provides one permissive comparison boundary for values such as `azurelinuxagent.common.version.DISTRO_VERSION`. It preserves the supplied text for display but derives a mechanical ordering suitable for distro-specific feature and handler decisions.

## What

`DistroVersion` is a value object modeled on the deprecated `distutils.LooseVersion` strategy:

- The original version string remains unchanged for `str()` and `repr()`.
- A case-insensitive regular expression splits the string into numeric, alphabetic, dot, and unmatched fragments.
- Dots are separators and are removed from the comparison representation.
- Numeric fragments become integers; all other fragments remain strings.
- Equality and all relative-order operators share the same three-way comparison.
- String operands are accepted and converted to `DistroVersion` before comparison.

The model establishes a consistent loose order, not vendor-defined release semantics. It does not require a fixed field count or standardized prerelease syntax.

## How

### Comparison lifecycle

1. `DistroVersion.__init__` stores the input in `_version`.
2. `DistroVersion._fragment_re` splits the input; empty fragments and dots are discarded.
3. `DistroVersion._number_re` identifies fragments to convert to integers, producing `_fragments`.
4. `DistroVersion._compare` wraps a string operand, compares fragment lists, and returns `-1`, `0`, or `1`.
5. `DistroVersion.__eq__`, `__lt__`, `__le__`, `__gt__`, and `__ge__` project that result into Python comparison operators.

### Usage constraints

- Wrap distro releases in `DistroVersion` before threshold or range checks; do not compare raw distro strings.
- Keep parsing and ordering changes centralized in `DistroVersion.__init__` and `DistroVersion._compare`.
- Do not replace this model with semantic-version parsing without auditing every supported distro format.
- Treat surprising results as loose fragment ordering first; the class does not encode each vendor's prerelease policy.
- Use the agent's separate flexible-version model for simpler agent or extension version schemes.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Distro version tokenization and ordering | `azurelinuxagent/common/utils/distro_version.py` | `DistroVersion`; `DistroVersion.__init__`; `DistroVersion._compare`; `DistroVersion.__eq__`; `DistroVersion.__lt__`; `DistroVersion.__le__`; `DistroVersion.__gt__`; `DistroVersion.__ge__` |
| Detected distro version value | `azurelinuxagent/common/version.py` | `DISTRO_VERSION` |

## Related Components

- [Deprovision Handler Dispatch](deprovision-handler-dispatch.md) — uses `DistroVersion` to select the Ubuntu handler by release threshold.
- `azurelinuxagent.common.version` — supplies the host distribution version consumed by this model.
