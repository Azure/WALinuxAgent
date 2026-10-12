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

from azurelinuxagent.ga.exthandlers import ExtHandlerInstance, ExtHandlersHandler
from azurelinuxagent.ga.signature_validation_util import validate_handler_manifest_signing_info, validate_signature
from tests.lib.tools import AgentTestCase, MagicMock, Mock, patch


class TestExtHandlersTracing(AgentTestCase):
    @staticmethod
    def _create_handler():
        extensions_goal_state = Mock()
        extensions_goal_state.activity_id = "activity"
        extensions_goal_state.extensions = []
        extensions_goal_state.id = "incarnation_2"
        extensions_goal_state.svd_sequence_number = 2
        extensions_goal_state.channel = "WireServer"
        extensions_goal_state.source = "Fabric"
        extensions_goal_state.correlation_id = "correlation"
        extensions_goal_state.created_on_timestamp = "timestamp"

        goal_state = Mock()
        goal_state.extensions_goal_state = extensions_goal_state
        protocol = Mock()
        protocol.get_goal_state.return_value = goal_state
        return ExtHandlersHandler(protocol), extensions_goal_state

    def test_run_processes_extensions_within_goal_state_span(self):
        handler, extensions_goal_state = self._create_handler()
        span_scope = MagicMock()

        with patch.object(handler, "_extensions_on_hold", return_value=False):
            with patch.object(handler, "_ExtHandlersHandler__process_and_handle_extensions") as process_extensions:
                with patch.object(handler, "_cleanup_outdated_handlers") as cleanup:
                    with patch(
                            "azurelinuxagent.ga.exthandlers.agent_opentelemetry.start_goal_state_span",
                            return_value=span_scope) as start_span:
                        handler.run()

        start_span.assert_called_once_with(extensions_goal_state)
        span_scope.__enter__.assert_called_once_with()
        span_scope.__exit__.assert_called_once_with(None, None, None)
        process_extensions.assert_called_once_with(2, "incarnation_2")
        cleanup.assert_called_once_with()

    def test_run_passes_processing_errors_to_goal_state_span(self):
        handler, _ = self._create_handler()
        span_scope = MagicMock()
        error = ValueError("extension processing failed")

        with patch.object(handler, "_extensions_on_hold", return_value=False):
            with patch.object(
                    handler,
                    "_ExtHandlersHandler__process_and_handle_extensions",
                    side_effect=error):
                with patch.object(handler, "_cleanup_outdated_handlers") as cleanup:
                    with patch(
                            "azurelinuxagent.ga.exthandlers.agent_opentelemetry.start_goal_state_span",
                            return_value=span_scope):
                        handler.run()

        exit_arguments = span_scope.__exit__.call_args[0]
        self.assertIs(ValueError, exit_arguments[0])
        self.assertIs(error, exit_arguments[1])
        self.assertIsNotNone(exit_arguments[2])
        cleanup.assert_not_called()

    def test_extension_operation_boundaries_are_instrumented(self):
        instrumented_operations = [
            (ExtHandlerInstance._fetch_extension_manifest, "DownloadExtensionManifest"),
            (ExtHandlerInstance.download, "DownloadExtensionPackage"),
            (validate_signature, "ValidateExtensionPackage"),
            (validate_handler_manifest_signing_info, "ValidateHandlerManifest"),
            (ExtHandlerInstance.install, "InstallExtension"),
            (ExtHandlerInstance.enable, "EnableExtension"),
            (ExtHandlerInstance.disable, "DisableExtension"),
            (ExtHandlerInstance.uninstall, "UninstallExtension")
        ]

        for operation, expected_span_name in instrumented_operations:
            self.assertEqual(expected_span_name, operation._opentelemetry_span_name)

    def test_status_reporting_uses_the_upstream_goal_state_context(self):
        handler, extensions_goal_state = self._create_handler()
        parent_context = Mock()
        status = Mock()
        span_scope = MagicMock()

        with patch(
                "azurelinuxagent.ga.exthandlers.agent_opentelemetry.is_active",
                return_value=True):
            with patch(
                    "azurelinuxagent.ga.exthandlers.agent_opentelemetry.extract_goal_state_context",
                    return_value=parent_context) as extract_context:
                with patch(
                        "azurelinuxagent.ga.exthandlers.agent_opentelemetry.operation_span",
                        return_value=span_scope) as operation_span:
                    with patch.object(
                            handler,
                            "_report_ext_handlers_status",
                            return_value=status) as report_status:
                        result = handler.report_ext_handlers_status(
                            goal_state_changed=True,
                            vm_agent_update_status="update-status",
                            vm_agent_supports_fast_track=True
                        )

        self.assertIs(status, result)
        extract_context.assert_called_once_with(extensions_goal_state)
        operation_span.assert_called_once_with("ReportExtensionStatus", context=parent_context)
        report_status.assert_called_once_with(True, "update-status", True)
