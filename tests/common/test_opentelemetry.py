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

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

import azurelinuxagent.common.opentelemetry as opentelemetry
from tests.lib.tools import AgentTestCase, MagicMock, Mock, patch


class TestOpenTelemetry(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.original_tracer_provider = opentelemetry._tracer_provider
        self.original_is_shutdown = opentelemetry._is_shutdown
        opentelemetry._tracer_provider = None
        opentelemetry._is_shutdown = False

    def tearDown(self):
        opentelemetry._tracer_provider = self.original_tracer_provider
        opentelemetry._is_shutdown = self.original_is_shutdown
        AgentTestCase.tearDown(self)

    def test_is_supported_returns_true_for_python_3_10_and_newer(self):
        with patch.object(opentelemetry.sys, "version_info", (3, 10)):
            self.assertTrue(opentelemetry.is_supported())

        with patch.object(opentelemetry.sys, "version_info", (3, 11)):
            self.assertTrue(opentelemetry.is_supported())

    def test_is_supported_returns_false_for_older_python_versions(self):
        with patch.object(opentelemetry.sys, "version_info", (2, 7)):
            self.assertFalse(opentelemetry.is_supported())

        with patch.object(opentelemetry.sys, "version_info", (3, 9)):
            self.assertFalse(opentelemetry.is_supported())

    def test_vendored_entry_points_reference_retained_modules(self):
        opentelemetry.enable_vendored_packages()

        for distribution in [
            "opentelemetry_api-1.44.0.dist-info",
            "opentelemetry_sdk-1.44.0.dist-info"
        ]:
            entry_points = configparser.ConfigParser()
            entry_points.optionxform = str
            entry_points.read(os.path.join(
                opentelemetry._VENDOR_PATH,
                distribution,
                "entry_points.txt"
            ))

            for section in entry_points.sections():
                for _, target in entry_points.items(section):
                    module_name, separator, attribute_name = target.partition(":")
                    module = __import__(module_name, fromlist=[attribute_name or "*"])
                    if separator:
                        self.assertTrue(
                            hasattr(module, attribute_name),
                            "Entry point [{0}] references missing target [{1}]".format(section, target)
                        )

    def test_is_active_requires_a_running_provider(self):
        with patch.object(opentelemetry, "is_supported", return_value=True):
            self.assertFalse(opentelemetry.is_active())

            opentelemetry._tracer_provider = Mock()
            self.assertTrue(opentelemetry.is_active())

            opentelemetry._is_shutdown = True
            self.assertFalse(opentelemetry.is_active())

    def test_enable_vendored_packages_prepends_the_vendor_path(self):
        original_path = list(sys.path)
        try:
            sys.path[:] = ["existing-path", opentelemetry._VENDOR_PATH]
            with patch.object(opentelemetry.sys, "version_info", (3, 10)):
                self.assertTrue(opentelemetry.enable_vendored_packages())

            self.assertEqual(opentelemetry._VENDOR_PATH, sys.path[0])
            self.assertEqual(1, sys.path.count(opentelemetry._VENDOR_PATH))
        finally:
            sys.path[:] = original_path

    def test_enable_vendored_packages_is_idempotent(self):
        original_path = list(sys.path)
        try:
            sys.path[:] = ["existing-path"]
            with patch.object(opentelemetry.sys, "version_info", (3, 10)):
                opentelemetry.enable_vendored_packages()
                opentelemetry.enable_vendored_packages()

            self.assertEqual(opentelemetry._VENDOR_PATH, sys.path[0])
            self.assertEqual(1, sys.path.count(opentelemetry._VENDOR_PATH))
        finally:
            sys.path[:] = original_path

    def test_enable_vendored_packages_does_not_change_path_when_unsupported(self):
        original_path = list(sys.path)
        try:
            sys.path[:] = ["existing-path"]
            with patch.object(opentelemetry.sys, "version_info", (3, 9)):
                self.assertFalse(opentelemetry.enable_vendored_packages())

            self.assertEqual(["existing-path"], sys.path)
        finally:
            sys.path[:] = original_path

    def test_initialize_returns_none_when_python_is_not_supported(self):
        with patch.object(opentelemetry, "is_supported", return_value=False):
            with patch.object(opentelemetry, "_create_tracer_provider") as create_provider:
                self.assertIsNone(opentelemetry.initialize(host_endpoint="168.63.129.16"))

        create_provider.assert_not_called()

    def test_extract_goal_state_context_returns_none_when_python_is_not_supported(self):
        extensions_goal_state = Mock()

        with patch.object(opentelemetry, "is_supported", return_value=False):
            with patch.object(opentelemetry, "enable_vendored_packages") as enable_vendored_packages:
                self.assertIsNone(opentelemetry.extract_goal_state_context(extensions_goal_state))

        enable_vendored_packages.assert_not_called()

    def test_extract_goal_state_context_extracts_remote_parent_and_trace_state(self):
        extensions_goal_state = Mock()
        extensions_goal_state.trace_parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        extensions_goal_state.trace_state = "vendor=opaque-value"

        context = opentelemetry.extract_goal_state_context(extensions_goal_state)

        from opentelemetry import trace
        span_context = trace.get_current_span(context).get_span_context()
        self.assertTrue(span_context.is_valid)
        self.assertTrue(span_context.is_remote)
        self.assertEqual(0x4bf92f3577b34da6a3ce929d0e0e4736, span_context.trace_id)
        self.assertEqual(0x00f067aa0ba902b7, span_context.span_id)
        self.assertEqual("opaque-value", span_context.trace_state.get("vendor"))

    def test_extract_goal_state_context_treats_missing_context_as_absent(self):
        extensions_goal_state = Mock()
        extensions_goal_state.trace_parent = None
        extensions_goal_state.trace_state = None

        context = opentelemetry.extract_goal_state_context(extensions_goal_state)

        from opentelemetry import trace
        self.assertFalse(trace.get_current_span(context).get_span_context().is_valid)

    def test_extract_goal_state_context_treats_invalid_context_as_absent(self):
        extensions_goal_state = Mock()
        extensions_goal_state.trace_parent = "invalid"
        extensions_goal_state.trace_state = "vendor=opaque-value"

        context = opentelemetry.extract_goal_state_context(extensions_goal_state)

        from opentelemetry import trace
        self.assertFalse(trace.get_current_span(context).get_span_context().is_valid)

    def test_extract_goal_state_context_does_not_log_trace_context_on_failure(self):
        extensions_goal_state = Mock()
        extensions_goal_state.trace_parent = "sensitive-trace-parent"
        extensions_goal_state.trace_state = "sensitive-trace-state"

        with patch.object(opentelemetry, "enable_vendored_packages", side_effect=ValueError("sensitive-trace-state")):
            with patch.object(opentelemetry.logger, "error") as log_error:
                self.assertIsNone(opentelemetry.extract_goal_state_context(extensions_goal_state))

        log_error.assert_called_once_with(
            "OpenTelemetry trace context extraction failed: {0}",
            "ValueError"
        )

    def test_start_goal_state_span_returns_none_when_tracing_is_not_initialized(self):
        extensions_goal_state = Mock()

        with patch.object(opentelemetry, "extract_goal_state_context") as extract_context:
            self.assertIsNone(opentelemetry.start_goal_state_span(extensions_goal_state))

        extract_context.assert_not_called()

    def test_start_goal_state_span_returns_none_after_shutdown(self):
        opentelemetry._tracer_provider = Mock()
        opentelemetry._is_shutdown = True
        extensions_goal_state = Mock()

        with patch.object(opentelemetry, "extract_goal_state_context") as extract_context:
            self.assertIsNone(opentelemetry.start_goal_state_span(extensions_goal_state))

        extract_context.assert_not_called()

    def test_start_goal_state_span_creates_consumer_span_with_remote_parent(self):
        opentelemetry._tracer_provider = Mock()
        opentelemetry.enable_vendored_packages()

        from opentelemetry import trace
        from opentelemetry.context import Context
        from opentelemetry.trace import SpanKind

        extensions_goal_state = Mock()
        extensions_goal_state.id = "incarnation_2"
        extensions_goal_state.channel = "WireServer"
        extensions_goal_state.source = "Fabric"
        parent_context = Context()
        tracer = Mock()
        span_scope = Mock()
        tracer.start_as_current_span.return_value = span_scope

        with patch.object(opentelemetry, "extract_goal_state_context", return_value=parent_context):
            with patch.object(trace, "get_tracer", return_value=tracer) as get_tracer:
                self.assertIs(span_scope, opentelemetry.start_goal_state_span(extensions_goal_state))

        get_tracer.assert_called_once_with("azurelinuxagent.ga.exthandlers")
        tracer.start_as_current_span.assert_called_once_with(
            "ProcessExtensionsGoalState",
            context=parent_context,
            kind=SpanKind.CONSUMER,
            attributes={
                "walinuxagent.goal_state.id": "incarnation_2",
                "walinuxagent.goal_state.channel": "WireServer",
                "walinuxagent.goal_state.source": "Fabric"
            }
        )

    def test_start_goal_state_span_uses_root_context_when_parent_extraction_fails(self):
        opentelemetry._tracer_provider = Mock()
        opentelemetry.enable_vendored_packages()

        from opentelemetry import trace
        from opentelemetry.context import Context

        extensions_goal_state = Mock()
        extensions_goal_state.id = "etag_1"
        extensions_goal_state.channel = "HostGAPlugin"
        extensions_goal_state.source = "FastTrack"
        tracer = Mock()

        with patch.object(opentelemetry, "extract_goal_state_context", return_value=None):
            with patch.object(trace, "get_tracer", return_value=tracer):
                opentelemetry.start_goal_state_span(extensions_goal_state)

        span_context = tracer.start_as_current_span.call_args[1]["context"]
        self.assertIsInstance(span_context, Context)
        self.assertEqual(0, len(span_context))

    def test_operation_span_creates_internal_child_span(self):
        opentelemetry._tracer_provider = Mock()
        opentelemetry.enable_vendored_packages()

        from opentelemetry import trace
        from opentelemetry.trace import SpanKind

        tracer = Mock()
        span_scope = MagicMock()
        tracer.start_as_current_span.return_value = span_scope

        with patch.object(trace, "get_tracer", return_value=tracer):
            with opentelemetry.operation_span("InstallExtension") as span:
                self.assertIs(span_scope.__enter__.return_value, span)

        tracer.start_as_current_span.assert_called_once_with(
            "InstallExtension",
            context=None,
            kind=SpanKind.INTERNAL
        )
        span_scope.__exit__.assert_called_once_with(None, None, None)

    def test_trace_operation_preserves_behavior_when_tracing_is_inactive(self):
        @opentelemetry.trace_operation("TestOperation")
        def operation(value):
            return value + 1

        self.assertEqual(2, operation(1))
        self.assertEqual("TestOperation", operation._opentelemetry_span_name)

    def test_trace_operation_passes_exceptions_to_the_span(self):
        error = ValueError("operation failed")
        span_scope = MagicMock()

        @opentelemetry.trace_operation("TestOperation")
        def operation():
            raise error

        with patch.object(opentelemetry, "start_operation_span", return_value=span_scope):
            with self.assertRaises(ValueError):
                operation()

        exit_arguments = span_scope.__exit__.call_args[0]
        self.assertIs(ValueError, exit_arguments[0])
        self.assertIs(error, exit_arguments[1])
        self.assertIsNotNone(exit_arguments[2])

    def test_inject_current_context_preserves_headers_and_replaces_existing_context(self):
        opentelemetry._tracer_provider = Mock()
        opentelemetry.enable_vendored_packages()

        from opentelemetry import trace
        from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags, TraceState

        span_context = SpanContext(
            trace_id=0x4bf92f3577b34da6a3ce929d0e0e4736,
            span_id=0x00f067aa0ba902b7,
            is_remote=False,
            trace_flags=TraceFlags(TraceFlags.SAMPLED),
            trace_state=TraceState([("vendor", "opaque-value")])
        )
        headers = {
            "Existing": "value",
            "TraceParent": "stale",
            "TRACESTATE": "stale"
        }

        with trace.use_span(NonRecordingSpan(span_context)):
            injected = opentelemetry.inject_current_context(headers)

        self.assertEqual("value", injected["Existing"])
        self.assertEqual(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            injected["traceparent"]
        )
        self.assertEqual("vendor=opaque-value", injected["tracestate"])
        self.assertNotIn("TraceParent", injected)
        self.assertNotIn("TRACESTATE", injected)
        self.assertEqual("stale", headers["TraceParent"])
        self.assertEqual("stale", headers["TRACESTATE"])

    def test_inject_current_context_returns_original_headers_without_a_current_span(self):
        opentelemetry._tracer_provider = Mock()
        headers = {"Existing": "value"}

        self.assertIs(headers, opentelemetry.inject_current_context(headers))

    def test_initialize_from_config_returns_none_when_tracing_is_disabled(self):
        configuration = opentelemetry.conf.ConfigurationProvider()
        configuration.load("OpenTelemetry.Enabled=n")

        with patch.object(opentelemetry, "initialize") as initialize:
            self.assertIsNone(opentelemetry.initialize_from_config(configuration))

        initialize.assert_not_called()

    def test_initialize_from_config_passes_validated_settings_to_initialize(self):
        configuration = opentelemetry.conf.ConfigurationProvider()
        configuration.load("""
OpenTelemetry.Enabled=y
OpenTelemetry.ExportTimeoutSeconds=7
OpenTelemetry.ExportIntervalMilliseconds=1000
OpenTelemetry.MaxQueueSize=100
OpenTelemetry.MaxExportBatchSize=50
OpenTelemetry.RootSamplingRatio=0.25
""")
        provider = Mock()

        with patch.object(opentelemetry, "is_supported", return_value=True):
            with patch.object(opentelemetry, "initialize", return_value=provider) as initialize:
                self.assertIs(provider, opentelemetry.initialize_from_config(configuration))

        initialize.assert_called_once_with(
            timeout=7,
            schedule_delay_millis=1000,
            max_queue_size=100,
            max_export_batch_size=50,
            root_sampling_ratio=0.25
        )

    def test_initialize_from_config_logs_invalid_numeric_configuration(self):
        configuration = opentelemetry.conf.ConfigurationProvider()
        configuration.load("""
OpenTelemetry.Enabled=y
OpenTelemetry.MaxQueueSize=0
""")

        with patch.object(opentelemetry, "is_supported", return_value=True):
            with patch.object(opentelemetry, "initialize") as initialize:
                with patch.object(opentelemetry.logger, "error") as log_error:
                    self.assertIsNone(opentelemetry.initialize_from_config(configuration))

        initialize.assert_not_called()
        log_error.assert_called_once()

    def test_initialize_from_config_logs_invalid_enabled_value(self):
        configuration = opentelemetry.conf.ConfigurationProvider()
        configuration.load("OpenTelemetry.Enabled=invalid")

        with patch.object(opentelemetry, "is_supported", return_value=True):
            with patch.object(opentelemetry, "initialize") as initialize:
                with patch.object(opentelemetry.logger, "error") as log_error:
                    self.assertIsNone(opentelemetry.initialize_from_config(configuration))

        initialize.assert_not_called()
        log_error.assert_called_once()

    def test_initialize_configures_the_provider_once(self):
        provider = Mock()
        with patch.object(opentelemetry, "is_supported", return_value=True):
            with patch.object(opentelemetry, "enable_vendored_packages", return_value=True):
                with patch.object(opentelemetry, "_create_tracer_provider", return_value=provider) as create_provider:
                    with patch.object(opentelemetry, "_set_global_tracer_provider", return_value=True) as set_provider:
                        initialized = opentelemetry.initialize(
                            host_endpoint="168.63.129.16",
                            timeout=7,
                            schedule_delay_millis=1000,
                            max_queue_size=100,
                            max_export_batch_size=50,
                            root_sampling_ratio=0.25
                        )
                        initialized_again = opentelemetry.initialize(host_endpoint="ignored")

        self.assertIs(provider, initialized)
        self.assertIs(provider, initialized_again)
        create_provider.assert_called_once_with(
            "168.63.129.16",
            7,
            1000,
            100,
            50,
            0.25
        )
        set_provider.assert_called_once_with(provider)

    def test_sampler_preserves_remote_parent_sampling_decisions(self):
        opentelemetry.enable_vendored_packages()

        from opentelemetry import trace
        from opentelemetry.sdk.trace.sampling import Decision
        from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

        never_sample_roots = opentelemetry._create_sampler(0.0)
        always_sample_roots = opentelemetry._create_sampler(1.0)

        sampled_parent = trace.set_span_in_context(NonRecordingSpan(SpanContext(
            trace_id=1,
            span_id=1,
            is_remote=True,
            trace_flags=TraceFlags(TraceFlags.SAMPLED)
        )))
        unsampled_parent = trace.set_span_in_context(NonRecordingSpan(SpanContext(
            trace_id=1,
            span_id=1,
            is_remote=True,
            trace_flags=TraceFlags(0)
        )))

        self.assertEqual(
            Decision.RECORD_AND_SAMPLE,
            never_sample_roots.should_sample(sampled_parent, 2, "sampled-child").decision
        )
        self.assertEqual(
            Decision.DROP,
            always_sample_roots.should_sample(unsampled_parent, 2, "unsampled-child").decision
        )
        self.assertEqual(
            Decision.DROP,
            never_sample_roots.should_sample(None, 2, "dropped-local-root").decision
        )
        self.assertEqual(
            Decision.RECORD_AND_SAMPLE,
            always_sample_roots.should_sample(None, 2, "sampled-local-root").decision
        )

    def test_initialize_shuts_down_provider_when_global_provider_is_already_configured(self):
        provider = Mock()
        with patch.object(opentelemetry, "is_supported", return_value=True):
            with patch.object(opentelemetry, "enable_vendored_packages", return_value=True):
                with patch.object(opentelemetry, "_create_tracer_provider", return_value=provider):
                    with patch.object(opentelemetry, "_set_global_tracer_provider", return_value=False):
                        with patch.object(opentelemetry.logger, "error") as log_error:
                            self.assertIsNone(opentelemetry.initialize())

        provider.shutdown.assert_called_once_with()
        log_error.assert_called_once()

    def test_initialize_logs_and_returns_none_on_failure(self):
        with patch.object(opentelemetry, "is_supported", return_value=True):
            with patch.object(opentelemetry, "enable_vendored_packages", return_value=True):
                with patch.object(opentelemetry, "_create_tracer_provider", side_effect=ValueError("invalid")):
                    with patch.object(opentelemetry.logger, "error") as log_error:
                        self.assertIsNone(opentelemetry.initialize())

        log_error.assert_called_once()

    def test_shutdown_shuts_down_the_provider_once(self):
        provider = Mock()
        opentelemetry._tracer_provider = provider

        self.assertTrue(opentelemetry.shutdown())
        self.assertFalse(opentelemetry.shutdown())

        provider.shutdown.assert_called_once_with()

    def test_shutdown_logs_failures_and_remains_idempotent(self):
        provider = Mock()
        provider.shutdown.side_effect = ValueError("failed")
        opentelemetry._tracer_provider = provider

        with patch.object(opentelemetry.logger, "error") as log_error:
            self.assertTrue(opentelemetry.shutdown())
            self.assertFalse(opentelemetry.shutdown())

        provider.shutdown.assert_called_once_with()
        log_error.assert_called_once()
