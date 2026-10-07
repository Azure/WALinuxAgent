# Thread-Local Singleton


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/thread-local-singleton.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `SingletonPerThread` gives each derived class one cached instance per thread name. It is used by `ProtocolUtil` to isolate protocol initialization state between agent threads while preserving stable state within each thread.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L1-conceptual/thread-local-singleton.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Agent threads can perform protocol work independently but repeatedly request the same coordinating object. A process-wide singleton would mix thread-specific state, while constructing a new object for every request would discard useful state and repeat initialization.

`SingletonPerThread` supplies a reusable inheritance-based contract: callers construct a derived class normally, and the metaclass returns the instance already associated with that class and thread.

## What

The abstraction consists of:

| Element | Responsibility |
|---|---|
| `_SingletonPerThreadMetaClass` | Intercepts construction and owns the shared instance cache. |
| `_instances` | Maps a derived class name plus current thread name to an object. |
| `_lock` | Serializes cache lookup and first construction across all derived classes and threads. |
| `SingletonPerThread` | Hides metaclass wiring behind a base class that consumers inherit. |
| `ProtocolUtil` | Uses the contract so `get_protocol_util()` resolves to the current thread's protocol utility instance. |

The identity boundary is the string `<class name>__<thread name>`, not a thread object or thread identifier. Instances therefore remain cached for the process lifetime unless cache-management behavior is added elsewhere.

## How

### Instance resolution

1. A caller constructs a class derived from `SingletonPerThread`, directly or through a factory such as `get_protocol_util()`.
2. `_SingletonPerThreadMetaClass.__call__` acquires the metaclass-wide lock.
3. It combines the derived class name with `current_thread().name`.
4. If the key is absent, normal class construction runs once and the result is cached.
5. The cached object is returned for that key on every later construction request.

This provides per-thread-name identity while also making first construction atomic. The lock covers object construction, so a slow constructor temporarily blocks singleton creation for every participating class.

### Identity and lifecycle constraints

- Two calls for the same derived class on threads with the same name resolve to the same object, even if the original thread has exited.
- Different thread names receive different objects for the same derived class.
- Different derived classes are separated by class name, but classes with the same `__name__` share the same key space even if they come from different modules.
- Constructor arguments are used only when a key is first created; later arguments do not reconfigure the cached object.
- The cache holds strong references and has no eviction in the shown implementation.
- The base-class comment mentions `DerivedClassName.clear()`, but no `clear` method appears in this implementation; do not rely on that API without verifying or adding it.

### Protocol usage

`ProtocolUtil` inherits `SingletonPerThread`, and `get_protocol_util()` constructs `ProtocolUtil` rather than managing caching itself. Each named thread consequently retains its own protocol initialization utility, including the dependencies involved in OS detection, DHCP, OVF environment handling, WireServer communication, and metadata-server migration.

### Change guidance

- Preserve normal constructor syntax for consumers; cache behavior belongs in the metaclass/base abstraction.
- Use stable, unique thread names when object identity must not cross thread lifetimes.
- Avoid passing different constructor arguments after an instance may already exist; they will be ignored for an existing key.
- Prefer a key based on the class object and actual thread identity if removing class-name collisions or thread-name reuse is required.
- If adding cleanup, synchronize it with `_lock` and define whether cleanup affects only the current class/thread key or the entire cache.
- Keep constructors lightweight because they run while holding the shared lock.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Per-thread singleton contract and cache | `azurelinuxagent/common/singletonperthread.py` | `_SingletonPerThreadMetaClass`; `_SingletonPerThreadMetaClass.__call__`; `SingletonPerThread` |
| Protocol utility consumer and factory | `azurelinuxagent/common/protocol/util.py` | `ProtocolUtil`; `get_protocol_util` |
| Wire protocol implementation used by protocol initialization | `azurelinuxagent/common/protocol/wire.py` | `WireProtocol` |
| OVF environment input | `azurelinuxagent/common/protocol/ovfenv.py` | `OvfEnv` |
| Platform and DHCP dependencies | `azurelinuxagent/common/osutil/factory.py`; `azurelinuxagent/common/dhcp.py` | `get_osutil`; `get_dhcp_handler` |

## Related Components

- [Goal State Domain Models](goal-state-domain-models.md): describes the goal-state data acquired through `WireProtocol`, downstream of protocol selection and initialization.
- [Protocol Data Contracts](protocol-data-contracts.md): `ProtocolUtil` coordinates discovery and setup for the protocol implementations that populate agent protocol state.
- [Thread Handler Contract](thread-handler-contract.md): thread naming and lifecycle directly determine whether a cached singleton is isolated, newly created, or reused.
