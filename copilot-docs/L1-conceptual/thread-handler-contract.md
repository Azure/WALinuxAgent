# Thread Handler Contract


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/thread-handler-contract.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `ThreadHandlerInterface` defines the lifecycle contract for background thread handlers owned by the Guest Agent. Implementations supply naming, execution, liveness, startup, and shutdown behavior, while opting out explicitly if a dead handler should not be restarted.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/thread-handler-contract.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The Guest Agent maintains multiple background workers and needs a uniform way to identify, start, monitor, restart, and stop them. Depending directly on each worker's threading details would couple lifecycle orchestration to concrete implementations.

`ThreadHandlerInterface` establishes the shared boundary: the owner can manage handlers consistently, and each handler remains responsible for its own execution and thread state.

## What

The interface defines six operations:

| Operation | Contract |
|---|---|
| `ThreadHandlerInterface.get_thread_name` | Returns the handler's thread name without requiring an instance. |
| `ThreadHandlerInterface.run` | Performs the handler's main execution work. |
| `ThreadHandlerInterface.keep_alive` | Indicates whether the owner should restart the handler after its thread dies. |
| `ThreadHandlerInterface.is_alive` | Reports whether the handler's thread is currently alive. |
| `ThreadHandlerInterface.start` | Starts the handler. |
| `ThreadHandlerInterface.stop` | Stops the handler. |

All operations except `keep_alive` are abstract by convention and raise `NotImplementedError` in the base interface. `keep_alive` defaults to `True`, making restart-on-death the standard policy; implementations must override it to leave a terminated handler stopped.

## How

### Lifecycle model

1. The Guest Agent identifies a handler through `get_thread_name`.
2. It invokes `start` to begin the handler's execution lifecycle.
3. The concrete handler arranges for `run` to perform its background work.
4. The owner uses `is_alive` to monitor the underlying thread.
5. If the thread dies, the owner consults `keep_alive` to decide whether it should be restarted.
6. During shutdown, the owner invokes `stop`.

The interface does not prescribe how threads are created, joined, synchronized, or cancelled. Concrete handlers must implement those mechanics while preserving the observable lifecycle contract.

### Implementation guidance

- Subclass `ThreadHandlerInterface` for every thread handler managed by the Guest Agent.
- Implement all methods that raise `NotImplementedError`; inheriting one of them fails only when the lifecycle operation is invoked.
- Keep `get_thread_name` static and stable so orchestration and diagnostics can identify the handler without constructing it.
- Ensure `is_alive` reflects the same execution resource controlled by `start` and `stop`.
- Override `keep_alive` only when terminal failure or one-shot execution is intentional.
- Make `stop` compatible with the handler's blocking behavior so agent shutdown can complete predictably.
- Keep restart policy separate from execution logic: `run` performs work, while `keep_alive` communicates the desired response to thread death.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Thread-handler lifecycle contract | `azurelinuxagent/ga/interfaces.py` | `ThreadHandlerInterface`; `ThreadHandlerInterface.get_thread_name`; `ThreadHandlerInterface.run`; `ThreadHandlerInterface.keep_alive`; `ThreadHandlerInterface.is_alive`; `ThreadHandlerInterface.start`; `ThreadHandlerInterface.stop` |

## Related Components

- **Guest Agent:** Owns and maintains implementations of `ThreadHandlerInterface`, using the contract for lifecycle orchestration and restart decisions.
- **Concrete thread handlers:** Supply the execution and threading mechanics hidden behind this interface.
