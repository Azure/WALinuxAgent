# Deprovision Handler Dispatch


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/deprovision-handler-dispatch.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** The deprovision package exposes `get_deprovision_handler` as its public handler-selection entry point. Consumers import this package-level API while the factory module owns the dispatch implementation.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/deprovision-handler-dispatch.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Deprovisioning callers need a stable way to obtain a handler without coupling themselves to the factory module's internal organization. The package boundary keeps that dependency narrow: callers use one exported function, while handler-selection logic can remain behind the public API.

## What

`azurelinuxagent.pa.deprovision` re-exports `get_deprovision_handler` from the factory module. Its `__all__` declaration identifies that function as the package's intended public symbol.

This creates two responsibilities:

| Boundary | Responsibility |
|---|---|
| Deprovision package | Publishes the supported import surface through `__all__`. |
| Factory module | Implements `get_deprovision_handler`, the handler-dispatch entry point. |

## How

1. A consumer imports `get_deprovision_handler` from `azurelinuxagent.pa.deprovision`.
2. The package resolves that symbol from `azurelinuxagent.pa.deprovision.factory`.
3. Calling `get_deprovision_handler` delegates handler selection to the factory implementation.

### Change guidance

- Keep callers dependent on the package-level entry point rather than factory internals.
- Preserve `get_deprovision_handler` in `__all__` while it remains the supported public API.
- Make dispatch-policy changes in `get_deprovision_handler`; do not duplicate selection logic in consumers.
- Treat changes to the exported name or package import path as public API changes.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Public deprovision API | `azurelinuxagent/pa/deprovision/__init__.py` | `__all__`; `get_deprovision_handler` |
| Handler dispatch factory | `azurelinuxagent/pa/deprovision/factory.py` | `get_deprovision_handler` |

## Related Components

- **Deprovision factory:** `azurelinuxagent.pa.deprovision.factory.get_deprovision_handler` contains the selection behavior hidden behind the package API.
