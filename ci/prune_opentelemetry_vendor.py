#!/usr/bin/env python3

import json
import os


REPOSITORY_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR_ROOT = os.path.join(REPOSITORY_ROOT, "azurelinuxagent", "vendor")
SITE_PACKAGES_ROOT = os.path.join(VENDOR_ROOT, "site-packages")

REMOVED_PACKAGES = {
    "certifi",
    "charset-normalizer",
    "googleapis-common-protos",
    "idna",
    "opentelemetry-exporter-otlp-proto-common",
    "opentelemetry-exporter-otlp-proto-http",
    "opentelemetry-proto",
    "protobuf",
    "requests",
    "urllib3",
}

RETAINED_DISTRIBUTIONS = {
    "opentelemetry_api-1.44.0.dist-info",
    "opentelemetry_sdk-1.44.0.dist-info",
    "opentelemetry_semantic_conventions-0.65b0.dist-info",
    "typing_extensions-4.16.0.dist-info",
}

OPENTELEMETRY_PACKAGE_TREES = (
    "opentelemetry/attributes/",
    "opentelemetry/context/",
    "opentelemetry/environment_variables/",
    "opentelemetry/metrics/",
    "opentelemetry/trace/",
    "opentelemetry/sdk/_shared_internal/",
    "opentelemetry/sdk/environment_variables/",
    "opentelemetry/sdk/resources/",
    "opentelemetry/sdk/util/",
    "opentelemetry/sdk/version/",
)

OPENTELEMETRY_FILES = {
    "opentelemetry/propagators/textmap.py",
    "opentelemetry/sdk/trace/__init__.py",
    "opentelemetry/sdk/trace/_tracer_metrics.py",
    "opentelemetry/sdk/trace/export/__init__.py",
    "opentelemetry/sdk/trace/id_generator.py",
    "opentelemetry/sdk/trace/sampling.py",
    "opentelemetry/semconv/__init__.py",
    "opentelemetry/semconv/_incubating/attributes/otel_attributes.py",
    "opentelemetry/semconv/_incubating/metrics/otel_metrics.py",
    "opentelemetry/semconv/attributes/__init__.py",
    "opentelemetry/semconv/attributes/error_attributes.py",
    "opentelemetry/semconv/attributes/exception_attributes.py",
    "opentelemetry/semconv/resource/__init__.py",
    "opentelemetry/util/_decorator.py",
    "opentelemetry/util/_importlib_metadata.py",
    "opentelemetry/util/_once.py",
    "opentelemetry/util/_providers.py",
    "opentelemetry/util/types.py",
}

RETAINED_DISTRIBUTION_METADATA = {
    "METADATA",
}

RETAINED_ENTRY_POINTS = {
    "opentelemetry_api-1.44.0.dist-info",
    "opentelemetry_sdk-1.44.0.dist-info",
}

ENTRY_POINTS = {
    "opentelemetry_api-1.44.0.dist-info": """\
[opentelemetry_context]
contextvars_context = opentelemetry.context.contextvars_context:ContextVarsRuntimeContext

[opentelemetry_environment_variables]
api = opentelemetry.environment_variables

[opentelemetry_meter_provider]
default_meter_provider = opentelemetry.metrics:NoOpMeterProvider

[opentelemetry_propagator]
tracecontext = opentelemetry.trace.propagation.tracecontext:TraceContextTextMapPropagator

[opentelemetry_tracer_provider]
default_tracer_provider = opentelemetry.trace:NoOpTracerProvider
""",
    "opentelemetry_sdk-1.44.0.dist-info": """\
[opentelemetry_environment_variables]
sdk = opentelemetry.sdk.environment_variables

[opentelemetry_id_generator]
random = opentelemetry.sdk.trace.id_generator:RandomIdGenerator

[opentelemetry_resource_detector]
host = opentelemetry.sdk.resources:_HostResourceDetector
os = opentelemetry.sdk.resources:OsResourceDetector
otel = opentelemetry.sdk.resources:OTELResourceDetector
process = opentelemetry.sdk.resources:ProcessResourceDetector
service_instance = opentelemetry.sdk.resources:ServiceInstanceIdResourceDetector

[opentelemetry_tracer_provider]
sdk_tracer_provider = opentelemetry.sdk.trace:TracerProvider

[opentelemetry_traces_exporter]
console = opentelemetry.sdk.trace.export:ConsoleSpanExporter

[opentelemetry_traces_sampler]
always_off = opentelemetry.sdk.trace.sampling:_AlwaysOff
always_on = opentelemetry.sdk.trace.sampling:_AlwaysOn
parentbased_always_off = opentelemetry.sdk.trace.sampling:_ParentBasedAlwaysOff
parentbased_always_on = opentelemetry.sdk.trace.sampling:_ParentBasedAlwaysOn
parentbased_traceidratio = opentelemetry.sdk.trace.sampling:ParentBasedTraceIdRatio
traceidratio = opentelemetry.sdk.trace.sampling:TraceIdRatioBased
""",
}


def normalize(path):
    return path.replace(os.sep, "/")


def should_retain(relative_path):
    relative_path = normalize(relative_path)
    components = relative_path.split("/")

    if "__pycache__" in components or relative_path.endswith((".pyc", ".pyo")):
        return False

    if components[0] in RETAINED_DISTRIBUTIONS:
        if len(components) != 2:
            return False
        if components[1] in RETAINED_DISTRIBUTION_METADATA:
            return True
        return components[1] == "entry_points.txt" and components[0] in RETAINED_ENTRY_POINTS

    if relative_path == "typing_extensions.py":
        return True

    if relative_path in OPENTELEMETRY_FILES:
        return True

    return relative_path.startswith(OPENTELEMETRY_PACKAGE_TREES) and relative_path.endswith(".py")


def prune_site_packages():
    for directory, _, filenames in os.walk(SITE_PACKAGES_ROOT, topdown=False):
        for filename in filenames:
            path = os.path.join(directory, filename)
            relative_path = os.path.relpath(path, SITE_PACKAGES_ROOT)
            if not should_retain(relative_path):
                os.remove(path)

        if directory != SITE_PACKAGES_ROOT and not os.listdir(directory):
            os.rmdir(directory)


def update_entry_points():
    for distribution, contents in ENTRY_POINTS.items():
        entry_points_path = os.path.join(SITE_PACKAGES_ROOT, distribution, "entry_points.txt")
        with open(entry_points_path, mode="w", encoding="utf-8", newline="\n") as entry_points_file:
            entry_points_file.write(contents)


def update_manifest():
    manifest_path = os.path.join(VENDOR_ROOT, "manifest.json")
    with open(manifest_path, encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)

    manifest["packages"] = [
        package for package in manifest["packages"]
        if package["name"] not in REMOVED_PACKAGES
    ]
    manifest["notes"] = [
        "Only the pure-Python runtime files needed for context propagation, span creation, "
        "batching, and WALA's HostGAPlugin OTLP/HTTP JSON exporter are retained.",
        "Metrics export, logs, profiles, baggage propagation, gRPC exporters/stubs, test "
        "files, protobuf support, third-party HTTP clients, type stubs, compiled artifacts, "
        "and bytecode caches are intentionally excluded.",
        "METADATA and required entry points are retained for shipped distributions; normalized "
        "license and notice files are retained under azurelinuxagent/vendor/licenses.",
    ]

    with open(manifest_path, mode="w", encoding="utf-8", newline="\n") as manifest_file:
        json.dump(manifest, manifest_file, indent=2, sort_keys=True)
        manifest_file.write("\n")


def update_third_party_notices():
    notices_path = os.path.join(VENDOR_ROOT, "THIRD-PARTY-NOTICES.txt")
    with open(notices_path, encoding="utf-8") as notices_file:
        lines = notices_file.readlines()

    retained_lines = [
        line for line in lines
        if not any(line.startswith("- {0} ".format(package)) for package in REMOVED_PACKAGES)
    ]

    with open(notices_path, mode="w", encoding="utf-8", newline="\n") as notices_file:
        notices_file.writelines(retained_lines)


def remove_unused_licenses():
    licenses_root = os.path.join(VENDOR_ROOT, "licenses")
    for filename in os.listdir(licenses_root):
        if any(filename.startswith("{0}-".format(package)) for package in REMOVED_PACKAGES):
            os.remove(os.path.join(licenses_root, filename))


def main():
    prune_site_packages()
    update_entry_points()
    update_manifest()
    update_third_party_notices()
    remove_unused_licenses()


if __name__ == "__main__":
    main()
