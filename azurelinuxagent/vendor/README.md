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
