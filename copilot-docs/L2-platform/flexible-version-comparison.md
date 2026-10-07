# Flexible Version Comparison


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/flexible-version-comparison.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `FlexibleVersion` parses and compares agent- and extension-style numeric versions with configurable separators and ordered prerelease tags. Use `DistroVersion`, not this utility, for arbitrary Linux distribution release strings.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/flexible-version-comparison.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Agent and extension versions need numeric ordering, but they do not always fit `distutils.version.StrictVersion`: they may contain any number of numeric fields, use a non-dot separator, or express prereleases as `1.2.3alpha1`, `1.2.3-alpha1`, or `1.2.3.alpha1`.

`FlexibleVersion` provides one comparison model for those controlled formats. It prevents lexical misordering, normalizes equivalent trailing zero fields, and lets callers define prerelease precedence without applying distro-specific assumptions.

## What

### Version structure

Each instance carries three structural settings:

| Setting | Meaning |
|---|---|
| `sep` | Separator between numeric components; defaults to `.` and may be customized. |
| `prerel_tags` | Ordered prerelease tags; defaults to `alpha`, `beta`, `rc`. |
| `prerel_sep` | Separator observed before the prerelease tag: empty, `.`, or `-`. |

`FlexibleVersion._compile_pattern` builds a regular expression from those settings. `FlexibleVersion._parse` rejects invalid input with `ValueError`, converts numeric fields to integers, and stores a prerelease as `(tag, number)` when present. `major`, `minor`, and `patch` return the first three numeric fields, defaulting missing fields to zero.

### Ordering and equality

Comparisons require both operands to use the same numeric separator and prerelease-tag sequence. `FlexibleVersion._ensure_compatible` raises `ValueError` for incompatible structures and pads the shorter numeric tuple with zeros, making versions such as `1.2` and `1.2.0.0` equivalent.

For equal numeric components:

- A prerelease sorts before the final release.
- Tags sort by their position in `prerel_tags`.
- Equal tags sort by their numeric prerelease value.
- Equality requires both normalized numeric components and prerelease data to match.

The rich comparison methods (`__eq__`, `__lt__`, `__le__`, `__gt__`, and `__ge__`) share these rules.

### Prefix matching and arithmetic

`FlexibleVersion.matches` implements directional prefix matching: the receiver cannot have more numeric fields than the candidate, each receiver field must match, and a configured prerelease-tag sequence must agree. This is not the same operation as equality.

`FlexibleVersion.__add__` and `FlexibleVersion.__sub__` return new instances after changing the final numeric component. Subtraction rejects attempts to decrement a non-positive final component; formatting and prerelease metadata are preserved through `FlexibleVersion._assemble`.

### Daemon-version integration

`azurelinuxagent.common.version` uses `FlexibleVersion` to serialize the daemon version into `_AZURE_GUEST_AGENT_DAEMON_VERSION_` and parse it when read. `get_daemon_version` returns `0.0.0.0` when the environment variable is absent, giving callers a comparable sentinel. Agent package discovery also returns parsed agent versions for numeric ordering.

## How

### Comparison lifecycle

1. Construct both values with the same `sep` and `prerel_tags`.
2. `FlexibleVersion._compile_pattern` creates the accepted grammar.
3. `FlexibleVersion._parse` validates the text and separates numeric and prerelease data.
4. `FlexibleVersion._ensure_compatible` checks structural compatibility and pads trailing zeros.
5. Numeric components are compared first; prerelease presence, tag order, and number break ties.

### Change guidance

- Use `FlexibleVersion` for agent, extension, and similarly controlled numeric versions; use `DistroVersion` for vendor release strings.
- Preserve the structural compatibility check. Silently comparing instances with different separators or tag order changes their meaning.
- Keep trailing-zero normalization when modifying comparison behavior.
- Treat `matches` as directional prefix matching; do not replace it with equality or make it symmetric without auditing callers.
- Preserve the original prerelease separator during string conversion and arithmetic.
- Add prerelease tags in intended precedence order, from earliest to latest.
- Keep invalid version input explicit through `ValueError`; do not fall back to lexical comparison.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Parsing, formatting, matching, arithmetic, and ordering | `azurelinuxagent/common/utils/flexible_version.py` | `FlexibleVersion`; `FlexibleVersion.__init__`; `FlexibleVersion._compile_pattern`; `FlexibleVersion._parse`; `FlexibleVersion._ensure_compatible`; `FlexibleVersion.matches`; `FlexibleVersion.__add__`; `FlexibleVersion.__sub__` |
| Version fields and comparison operators | `azurelinuxagent/common/utils/flexible_version.py` | `FlexibleVersion.major`; `FlexibleVersion.minor`; `FlexibleVersion.patch`; `FlexibleVersion.__eq__`; `FlexibleVersion.__lt__`; `FlexibleVersion.__le__`; `FlexibleVersion.__gt__`; `FlexibleVersion.__ge__` |
| Daemon and agent version integration | `azurelinuxagent/common/version.py` | `set_daemon_version`; `get_daemon_version`; `set_current_agent`; `AGENT_VERSION`; `AGENT_LONG_VERSION` |

## Related Components

- [Distribution Version Model](../L1-conceptual/distribution-version-model.md) — handles arbitrary distro release formats that are intentionally outside `FlexibleVersion`'s grammar.
- [Agent Packaging and Platform Factories](agent-packaging-factories.md) — consumes agent version metadata during package discovery and platform selection.
