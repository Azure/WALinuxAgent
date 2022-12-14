# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

import json

from azurelinuxagent.ga.agent_update import get_agent_update_handler
from azurelinuxagent.ga.exthandlers import ExtHandlersHandler
from azurelinuxagent.ga.update import get_update_handler
from tests.ga.mocks import mock_update_handler
from tests.protocol.mocks import mock_wire_protocol, MockHttpResponse
from tests.tools import AgentTestCase, patch
from tests.protocol import mockwiredata
from tests.protocol.HttpRequestPredicates import HttpRequestPredicates


class ReportStatusTestCase(AgentTestCase):
    """
    Tests for UpdateHandler._report_status()
    """

    def test_update_handler_should_report_status_when_fetch_goal_state_fails(self):
        # The test executes the main loop of UpdateHandler.run() twice, failing requests for the goal state
        # on the second iteration. We expect the 2 iterations to report status, despite the goal state failure.
        fail_goal_state_request = [False]

        def http_get_handler(url, *_, **__):
            if HttpRequestPredicates.is_goal_state_request(url) and fail_goal_state_request[0]:
                return MockHttpResponse(status=410)
            return None

        def on_new_iteration(iteration):
            fail_goal_state_request[0] = iteration == 2

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_get_handler=http_get_handler) as protocol:
            exthandlers_handler = ExtHandlersHandler(protocol)
            with patch.object(exthandlers_handler, "run", wraps=exthandlers_handler.run) as exthandlers_handler_run:
                with mock_update_handler(protocol, iterations=2, on_new_iteration=on_new_iteration, exthandlers_handler=exthandlers_handler) as update_handler:
                    update_handler.run(debug=True)

                    self.assertEqual(1, exthandlers_handler_run.call_count,  "Extensions should have been executed only once.")
                    self.assertEqual(2, len(protocol.mock_wire_data.status_blobs),  "Status should have been reported for the 2 iterations.")

                    #
                    # Verify that we reported status for the extension in the test data
                    #
                    first_status = json.loads(protocol.mock_wire_data.status_blobs[0])

                    handler_aggregate_status = first_status.get('aggregateStatus', {}).get("handlerAggregateStatus")
                    self.assertIsNotNone(handler_aggregate_status, "Could not find the handlerAggregateStatus")
                    self.assertEqual(1, len(handler_aggregate_status), "Expected 1 extension status. Got:  {0}".format(handler_aggregate_status))
                    extension_status = handler_aggregate_status[0]
                    self.assertEqual("OSTCExtensions.ExampleHandlerLinux", extension_status["handlerName"], "The status does not correspond to the test data")

                    #
                    # Verify that we reported the same status (minus timestamps) in the 2 iterations
                    #
                    second_status = json.loads(protocol.mock_wire_data.status_blobs[1])

                    def remove_timestamps(x):
                        if isinstance(x, list):
                            for v in x:
                                remove_timestamps(v)
                        elif isinstance(x, dict):
                            for k, v in x.items():
                                if k == "timestampUTC":
                                    x[k] = ''
                                else:
                                    remove_timestamps(v)

                    remove_timestamps(first_status)
                    remove_timestamps(second_status)

                    self.assertEqual(first_status, second_status)

    def test_report_status_should_log_errors_only_once_per_goal_state(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=False):  # skip agent update
                with patch("azurelinuxagent.ga.update.logger.warn") as logger_warn:
                    update_handler = get_update_handler()
                    update_handler._goal_state = protocol.get_goal_state()  # these tests skip the initialization of the goal state. so do that here
                    exthandlers_handler = ExtHandlersHandler(protocol)
                    agent_update_handler = get_agent_update_handler(protocol)
                    agent_update_status = agent_update_handler.get_vmagent_update_status()
                    update_handler._report_status(exthandlers_handler, agent_update_status)
                    self.assertEqual(0, logger_warn.call_count, "UpdateHandler._report_status() should not report WARNINGS when there are no errors")

                    with patch("azurelinuxagent.ga.update.ExtensionsSummary.__init__", side_effect=Exception("TEST EXCEPTION")):  # simulate an error during _report_status()
                        get_warnings = lambda: [args[0] for args, _ in logger_warn.call_args_list if "TEST EXCEPTION" in args[0]]

                        update_handler._report_status(exthandlers_handler, agent_update_status)
                        update_handler._report_status(exthandlers_handler, agent_update_status)
                        update_handler._report_status(exthandlers_handler, agent_update_status)

                        self.assertEqual(1, len(get_warnings()), "UpdateHandler._report_status() should report only 1 WARNING when there are multiple errors within the same goal state")

                        exthandlers_handler.protocol.mock_wire_data.set_incarnation(999)
                        update_handler._try_update_goal_state(exthandlers_handler.protocol)
                        update_handler._report_status(exthandlers_handler, agent_update_status)
                        self.assertEqual(2, len(get_warnings()), "UpdateHandler._report_status() should continue reporting errors after a new goal state")

    def test_update_handler_should_add_fast_track_to_supported_features_when_it_is_supported(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            self._test_supported_features_includes_fast_track(protocol, True)

    def test_update_handler_should_not_add_fast_track_to_supported_features_when_it_is_not_supported(self):
        def http_get_handler(url, *_, **__):
            if HttpRequestPredicates.is_host_plugin_vm_settings_request(url):
                return MockHttpResponse(status=404)
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS, http_get_handler=http_get_handler) as protocol:
            self._test_supported_features_includes_fast_track(protocol, False)

    def _test_supported_features_includes_fast_track(self, protocol, expected):
        with mock_update_handler(protocol) as update_handler:
            update_handler.run(debug=True)

            status = json.loads(protocol.mock_wire_data.status_blobs[0])
            supported_features = status['supportedFeatures']
            includes_fast_track = any(f['Key'] == 'FastTrack' for f in supported_features)
            self.assertEqual(expected, includes_fast_track, "supportedFeatures should {0}include FastTrack. Got: {1}".format("" if expected else "not ", supported_features))

