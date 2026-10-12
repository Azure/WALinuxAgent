# Copyright 2026 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and Openssl 1.0+
#

import os
import sys
import threading
from contextlib import contextmanager
from functools import wraps

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.exception import AgentConfigError
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION


_MINIMUM_SUPPORTED_PYTHON_VERSION = (3, 10)
_VENDOR_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, "vendor", "site-packages")
)
_DEFAULT_EXPORT_TIMEOUT_SECONDS = 10
_DEFAULT_EXPORT_INTERVAL_MILLISECONDS = 5000
_DEFAULT_MAX_QUEUE_SIZE = 2048
_DEFAULT_MAX_EXPORT_BATCH_SIZE = 64
_DEFAULT_ROOT_SAMPLING_RATIO = 1.0
_EXTENSIONS_TRACER_NAME = "azurelinuxagent.ga.exthandlers"
_PROCESS_EXTENSIONS_GOAL_STATE_SPAN_NAME = "ProcessExtensionsGoalState"

_initialization_lock = threading.Lock()
_tracer_provider = None
_is_shutdown = False


def is_supported():
    """
    Returns whether this interpreter can load the vendored OpenTelemetry packages.
    """
    return sys.version_info >= _MINIMUM_SUPPORTED_PYTHON_VERSION


def is_active():
    """
    Returns whether the WALinuxAgent tracer provider is active.
    """
    return is_supported() and _tracer_provider is not None and not _is_shutdown


def enable_vendored_packages():
    """
    Prepends the vendored package directory to sys.path on supported interpreters.

    Returns True when the path is enabled and False when OpenTelemetry is not
    supported by the current Python interpreter.
    """
    if not is_supported():
        return False

    while _VENDOR_PATH in sys.path:
        sys.path.remove(_VENDOR_PATH)
    sys.path.insert(0, _VENDOR_PATH)
    return True


def _create_sampler(root_sampling_ratio):
    from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased

    return ParentBased(root=TraceIdRatioBased(root_sampling_ratio))


def _create_tracer_provider(host_endpoint, timeout, schedule_delay_millis, max_queue_size, max_export_batch_size,
                            root_sampling_ratio):
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from azurelinuxagent.common.opentelemetry_exporter import HostPluginSpanExporter

    resource = Resource.create({
        "service.name": AGENT_NAME,
        "service.version": str(CURRENT_VERSION)
    })
    exporter = HostPluginSpanExporter(host_endpoint=host_endpoint, timeout=timeout)
    provider = TracerProvider(
        resource=resource,
        sampler=_create_sampler(root_sampling_ratio)
    )
    provider.add_span_processor(BatchSpanProcessor(
        exporter,
        max_queue_size=max_queue_size,
        schedule_delay_millis=schedule_delay_millis,
        max_export_batch_size=max_export_batch_size
    ))
    return provider


def _set_global_tracer_provider(provider):
    from opentelemetry import trace

    trace.set_tracer_provider(provider)
    return trace.get_tracer_provider() is provider


def extract_goal_state_context(extensions_goal_state):
    """
    Extracts the upstream W3C trace context carried by an ExtensionsGoalState.

    Invalid or missing context is returned as an empty OpenTelemetry Context.
    Returns None when OpenTelemetry is unsupported or extraction fails.
    """
    if not is_supported():
        return None

    try:
        enable_vendored_packages()
        from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

        carrier = {}
        if extensions_goal_state.trace_parent:
            carrier["traceparent"] = extensions_goal_state.trace_parent
        if extensions_goal_state.trace_state:
            carrier["tracestate"] = extensions_goal_state.trace_state

        return TraceContextTextMapPropagator().extract(carrier)
    except Exception as error:
        logger.error(
            "OpenTelemetry trace context extraction failed: {0}",
            error.__class__.__name__
        )
        return None


def start_goal_state_span(extensions_goal_state):
    """
    Creates the consumer span for processing an ExtensionsGoalState.

    Returns the span context manager, or None when tracing is not initialized
    or the span cannot be created.
    """
    if not is_active():
        return None

    try:
        enable_vendored_packages()
        from opentelemetry import trace
        from opentelemetry.context import Context
        from opentelemetry.trace import SpanKind

        parent_context = extract_goal_state_context(extensions_goal_state)
        if parent_context is None:
            parent_context = Context()

        tracer = trace.get_tracer(_EXTENSIONS_TRACER_NAME)
        return tracer.start_as_current_span(
            _PROCESS_EXTENSIONS_GOAL_STATE_SPAN_NAME,
            context=parent_context,
            kind=SpanKind.CONSUMER,
            attributes={
                "walinuxagent.goal_state.id": extensions_goal_state.id,
                "walinuxagent.goal_state.channel": extensions_goal_state.channel,
                "walinuxagent.goal_state.source": extensions_goal_state.source
            }
        )
    except Exception as error:
        logger.error(
            "OpenTelemetry goal state span creation failed: {0}",
            error.__class__.__name__
        )
        return None


def start_operation_span(span_name, context=None):
    """
    Creates an internal child operation span.

    Returns the span context manager, or None when tracing is not active or the
    span cannot be created.
    """
    if not is_active():
        return None

    try:
        enable_vendored_packages()
        from opentelemetry import trace
        from opentelemetry.trace import SpanKind

        tracer = trace.get_tracer(_EXTENSIONS_TRACER_NAME)
        return tracer.start_as_current_span(
            span_name,
            context=context,
            kind=SpanKind.INTERNAL
        )
    except Exception as error:
        logger.error(
            "OpenTelemetry operation span creation failed: {0}",
            error.__class__.__name__
        )
        return None


@contextmanager
def operation_span(span_name, context=None):
    """
    Runs an operation within a child span when tracing is active.
    """
    span_scope = start_operation_span(span_name, context=context)
    if span_scope is None:
        yield None
    else:
        with span_scope as span:
            yield span


def trace_operation(span_name):
    """
    Instruments an operation using a static span name.
    """
    def decorator(operation):
        @wraps(operation)
        def wrapper(*args, **kwargs):
            with operation_span(span_name):
                return operation(*args, **kwargs)

        wrapper._opentelemetry_span_name = span_name
        return wrapper

    return decorator


def inject_current_context(headers=None):
    """
    Returns request headers containing the current W3C trace context.

    The input mapping is not modified. Existing trace context headers are
    replaced case-insensitively.
    """
    if not is_active():
        return headers

    try:
        enable_vendored_packages()
        from opentelemetry import trace
        from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

        if not trace.get_current_span().get_span_context().is_valid:
            return headers

        carrier = {} if headers is None else dict(headers)
        for name in list(carrier.keys()):
            if name.lower() in ("traceparent", "tracestate"):
                del carrier[name]

        TraceContextTextMapPropagator().inject(carrier)
        return carrier
    except Exception as error:
        logger.error(
            "OpenTelemetry context injection failed: {0}",
            error.__class__.__name__
        )
        return headers


def initialize_from_config(configuration=conf.__conf__):
    """
    Initializes tracing when it is enabled and validly configured.
    """
    if not is_supported():
        return None

    try:
        if not conf.get_opentelemetry_enabled(configuration):
            return None
        settings = conf.get_opentelemetry_configuration(configuration)
        return initialize(**settings)
    except AgentConfigError as error:
        logger.error("OpenTelemetry configuration is invalid: {0}", error)
        return None


def initialize(host_endpoint=None,
               timeout=_DEFAULT_EXPORT_TIMEOUT_SECONDS,
               schedule_delay_millis=_DEFAULT_EXPORT_INTERVAL_MILLISECONDS,
               max_queue_size=_DEFAULT_MAX_QUEUE_SIZE,
               max_export_batch_size=_DEFAULT_MAX_EXPORT_BATCH_SIZE,
               root_sampling_ratio=_DEFAULT_ROOT_SAMPLING_RATIO):
    """
    Initializes the vendored OpenTelemetry SDK and HostGAPlugin exporter once.

    Returns the TracerProvider, or None when the current Python version is not
    supported or initialization fails.
    """
    global _tracer_provider  # pylint: disable=global-statement

    if not is_supported():
        return None

    with _initialization_lock:
        if _tracer_provider is not None:
            return _tracer_provider

        provider = None
        try:
            enable_vendored_packages()
            provider = _create_tracer_provider(
                host_endpoint,
                timeout,
                schedule_delay_millis,
                max_queue_size,
                max_export_batch_size,
                root_sampling_ratio
            )
            if not _set_global_tracer_provider(provider):
                provider.shutdown()
                logger.error("OpenTelemetry initialization failed: the global tracer provider is already configured")
                return None

            _tracer_provider = provider
            return _tracer_provider
        except Exception as error:
            if provider is not None:
                provider.shutdown()
            logger.error("OpenTelemetry initialization failed: {0}", error)
            return None


def shutdown():
    """
    Flushes pending spans and shuts down the initialized TracerProvider once.
    """
    global _is_shutdown  # pylint: disable=global-statement

    with _initialization_lock:
        if _tracer_provider is None or _is_shutdown:
            return False

        try:
            _tracer_provider.shutdown()
        except Exception as error:
            logger.error("OpenTelemetry shutdown failed: {0}", error)
        finally:
            _is_shutdown = True

        return True
