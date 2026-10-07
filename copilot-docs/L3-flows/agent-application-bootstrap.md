# Agent Application Bootstrap


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L3-flows/agent-application-bootstrap.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `setup.py` is the minimal application bootstrap: it imports the agent entry module and immediately delegates execution to `azurelinuxagent.agent.main`. All startup behavior belongs behind that entry point rather than in the launcher.

## Why

The bootstrap provides a stable, low-complexity boundary between invoking the application and running the agent. Keeping this boundary thin:

- gives packaging or process launchers one canonical entry point;
- prevents startup policy from being duplicated in `setup.py`;
- centralizes initialization, argument handling, and lifecycle ownership in the agent module.

## What

The flow has two participants:

1. `setup.py` acts as the executable launcher.
2. `azurelinuxagent.agent.main` is the application entry method and owns all behavior after delegation.

The launcher has no branching, configuration parsing, error translation, or lifecycle management of its own.

## How

### Bootstrap sequence

1. The runtime executes `setup.py`.
2. `setup.py` imports the `azurelinuxagent.agent` module.
3. The launcher invokes `azurelinuxagent.agent.main`.
4. Control remains with the agent entry point for the rest of application startup and execution.

### Change guidance

- Put new startup behavior in or behind `azurelinuxagent.agent.main`, not in `setup.py`.
- Keep the launcher free of side effects beyond importing the entry module and invoking `main`.
- When changing the entry-point contract, update both the launcher call site and the agent module together.
- Diagnose failures after delegation from the agent entry flow; `setup.py` contributes no intermediate logic.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Application launcher | `setup.py` | Module-level invocation of `azurelinuxagent.agent.main` |
| Agent entry point | `azurelinuxagent/agent.py` | `main` |

## Related Components

- `azurelinuxagent.agent` — canonical application entry module reached by this bootstrap.
