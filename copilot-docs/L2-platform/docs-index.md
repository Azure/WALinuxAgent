# L2 — Platform Documentation Index

> "How does X work?" — Infrastructure services, build, deployment, telemetry, flighting.


| Document | Description |
|----------|-------------|
| [agent-event-reporting.md](agent-event-reporting.md) | **TL;DR:** Agent subsystems report operational outcomes through `add_event` and `WALAEventOperation`, while `SendTelemetryEventsHandler` batches queue |
| [agent-logging-service.md](agent-logging-service.md) | **TL;DR:** The agent logging service centralizes formatted output, message throttling, prefixing, and sensitive SAS-token redaction. Platform code con |
| [agent-packaging-factories.md](agent-packaging-factories.md) | **TL;DR:** Packaging scripts assemble installable and publishable agent artifacts, while small runtime factories select OS-, provisioning-, deprovisio |
| [archive-operations.md](archive-operations.md) | **TL;DR:** `archive.py` preserves diagnostic snapshots of Guest Agent goal state under the state directory's `history` folder. It moves selected state |
| [cgroup-resource-governance.md](cgroup-resource-governance.md) | **TL;DR:** `CGroupConfigurator` places the agent, extensions, and log collector under systemd cgroup slices with CPU and memory controls. `MonitorHand |
| [cgroup-telemetry-tracking.md](cgroup-telemetry-tracking.md) | **TL;DR:** `CGroupsTelemetry` is the thread-safe registry for cgroup controllers whose resource metrics the agent polls. It gives each controller a ve |
| [distribution-os-adapters.md](distribution-os-adapters.md) | **TL;DR:** Distribution adapters extend `DefaultOSUtil` to translate the agent's common host-operation contract into each Linux variant's service mana |
| [file-io-utilities.md](file-io-utilities.md) | **TL;DR:** `fileutil.py` centralizes byte-safe file reads and writes, optional text decoding and BOM removal, append behavior, and small path/content  |
| [flexible-version-comparison.md](flexible-version-comparison.md) | **TL;DR:** `FlexibleVersion` parses and compares agent- and extension-style numeric versions with configurable separators and ordered prerelease tags. |
| [log-collector-manifests.md](log-collector-manifests.md) | **TL;DR:** `logcollector_manifests.py` defines the declarative command lists used to build normal and full Azure Linux Agent diagnostic bundles. The m |
| [network-route-utilities.md](network-route-utilities.md) | **TL;DR:** `RouteEntry` models one Linux IPv4 route using the hexadecimal network-byte-order values exposed by the route table. It converts those valu |
| [platform-error-handling.md](platform-error-handling.md) | **TL;DR:** WALinuxAgent uses typed exceptions to preserve the failing platform boundary—configuration, protocol, network, OS, storage, cgroups, crypto |
| [runtime-compatibility-helpers.md](runtime-compatibility-helpers.md) | **TL;DR:** `azurelinuxagent.common.future` provides a stable import and behavior surface across supported Python runtimes and Linux distributions. It  |
| [service-error-state.md](service-error-state.md) | **TL;DR:** `ErrorState` tracks when a continuous failure period began and becomes triggered after a configured duration. The Host Plugin uses this sta |
| [shell-command-validation.md](shell-command-validation.md) | **TL;DR:** WALinuxAgent centralizes subprocess execution in `shellutil` and builds package-signature validation on that explicit command/error contrac |
| [text-xml-utilities.md](text-xml-utilities.md) | **TL;DR:** `textutil.py` centralizes XML DOM access, byte/text compatibility, binary formatting, configuration-line mutation, encoding, redaction, and |
| [utc-time-utilities.md](utc-time-utilities.md) | **TL;DR:** `create_utc_timestamp` converts a timezone-aware UTC `datetime` into the agent's canonical ISO-8601 timestamp with a `Z` suffix. It rejects |
