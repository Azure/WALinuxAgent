# Vendored OpenTelemetry dependencies

This directory contains the minimized Python 3.10+ runtime dependency closure
for W3C trace-context propagation, span creation, batching, and OTLP/HTTP trace
export to HostGAPlugin. WALA owns the small OTLP JSON encoder and uses its
existing HTTP transport; the upstream OpenTelemetry exporters, protobuf,
Requests, urllib3, and their transitive dependencies are not included. Baggage
propagation is intentionally not included. The dependencies
are committed to the WALinuxAgent source tree so that the agent does not need
to install external Python packages at runtime.

The package sources and their original distribution metadata are stored under
`site-packages/`. The directory is intentionally isolated from the normal
Python import path; agent integration code must explicitly prepend it before
importing OpenTelemetry.

For POC testing, tracing is enabled by default on Python 3.10+ in the source
defaults and all configuration templates, including when an existing
configuration omits the switch. Set `OpenTelemetry.Enabled=n` in `waagent.conf`
to disable it explicitly. The root sampling ratio remains `1.0`; upstream
sampling decisions are preserved. This POC default is not a production rollout
recommendation.

Operation and goal-state spans do not automatically record exception messages,
stack traces, or exception-derived status descriptions, since extension command
output can contain SAS URLs or other secrets. Failures set only the span's error
status code; the original exception continues through normal agent handling.

SDK-dependent tests are skipped on Python below 3.10 without importing the
vendored runtime. Tracing test modules remain parseable on Python 2.6 so older
CI jobs can still discover the supported tests.

`manifest.json` records the exact versions, source artifacts, SHA-256 hashes,
project URLs, and license files. `THIRD-PARTY-NOTICES.txt` summarizes the
components, while `licenses/` contains normalized copies of the required
license and notice files. Each `.dist-info` directory retains `METADATA` and
any entry points needed by OpenTelemetry's runtime provider discovery.

The vendor tree intentionally excludes logs, profiles, experimental samplers,
upstream OTLP exporters, protobuf messages/runtime, third-party HTTP clients,
gRPC exporters/stubs, command-line utilities, tests, type stubs, redundant
wheel installation metadata, bytecode caches, and platform-specific compiled
artifacts. Do not edit files under
`site-packages/` manually.
Dependency updates must replace the complete pinned closure, run
`ci/prune_opentelemetry_vendor.py`, and regenerate the manifest, license copies,
and notices together.
