# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import os.path

from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.future import httpclient
from azurelinuxagent.common.protocol import hostplugin
from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState
from azurelinuxagent.common.utils import restutil, fileutil
from tests.protocol.mocks import mock_wire_protocol
from tests.protocol import mockwiredata
from tests.protocol.mocks import HttpRequestPredicates, MockHttpResponse
from tests.tools import AgentTestCase, data_dir, patch

_original_http_request = restutil.http_request


class ExtensionsGoalStateTestCase(HttpRequestPredicates, AgentTestCase):
    def test_fetch_vm_settings_should_should_retry_on_resource_gone_error(self):
        """
        Requests to the hostgaplugin incude the Container ID and the RoleConfigName as headers; when the hostgaplugin returns GONE (HTTP status 410) the agent
        needs to get a new goal state and retry the request with updated values for the Container ID and RoleConfigName headers.
        """
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            # The mock_wire_protocol mocks azurelinuxagent.common.utils.restutil.http_request, but the GONE status is handled at a lower level, in the internal _http_request.
            # To mock this, we bypass the mock http_request by calling the original http_request (function http_get_handler) and then mocking the internal _http_request (function
            # http_get_vm_settings).
            def http_get_handler(url, *_, **kwargs):
                if self.is_host_plugin_vm_settings_request(url):
                    return _original_http_request("GET", url, None, **kwargs)
                return None
            protocol.set_http_handlers(http_get_handler=http_get_handler)

            request_headers = []  # we expect a retry with new headers and use this array to persist the headers of each request
            def http_get_vm_settings(_method, _host, _relative_url, **kwargs):
                request_headers.append(kwargs["headers"])
                if len(request_headers) == 1:
                    # Fail the first request with status GONE and update the mock data to return the new Container ID and RoleConfigName that should be
                    # used in the headers of the retry request.
                    protocol.mock_wire_data.set_container_id("GET_VM_SETTINGS_TEST_CONTAINER_ID")
                    protocol.mock_wire_data.set_role_config_name("GET_VM_SETTINGS_TEST_ROLE_CONFIG_NAME")
                    return MockHttpResponse(status=httpclient.GONE)
                # For this test we are interested only on the retry logic, so the second request (the retry) is not important; we use NOT_MODIFIED (304) for simplicity.
                return MockHttpResponse(status=httpclient.NOT_MODIFIED)

            with patch("azurelinuxagent.common.utils.restutil._http_request", side_effect=http_get_vm_settings):
                protocol.client._fetch_vm_settings(123)

            self.assertEqual(2, len(request_headers), "We expected 2 requests for vmSettings: the original request and the retry request")
            self.assertEqual("GET_VM_SETTINGS_TEST_CONTAINER_ID", request_headers[1][hostplugin._HEADER_CONTAINER_ID], "The retry request did not include the expected header for the ContainerId")
            self.assertEqual("GET_VM_SETTINGS_TEST_ROLE_CONFIG_NAME", request_headers[1][hostplugin._HEADER_HOST_CONFIG_NAME], "The retry request did not include the expected header for the RoleConfigName")

    def test_compare_should_report_mismatches_between_extensions_config_and_vm_settings(self):
        from_vm_settings = ExtensionsGoalState.create_from_vm_settings("123", fileutil.read_file(os.path.join(data_dir, "hostgaplugin/vm_settings.json")))
        from_extensions_config = ExtensionsGoalState.create_from_extensions_config("123", fileutil.read_file(os.path.join(data_dir, "hostgaplugin/ext_conf.xml")))

        with patch("azurelinuxagent.common.protocol.extensions_goal_state.add_event") as add_event_patcher:
            ExtensionsGoalState.compare(from_extensions_config, from_vm_settings)

            mismatch_events = [kw["message"] for _, kw in add_event_patcher.call_args_list if kw['op'] == WALAEventOperation.GoalStateMismatch]
            self.assertTrue(len(mismatch_events) == 0, "Did not expect any GoalStateMismatch messages, got: {0}".format(mismatch_events))

        with patch("azurelinuxagent.common.protocol.extensions_goal_state.add_event") as add_event_patcher:
            from_vm_settings.required_features = ['FORCE_A_MISMATCH_FEATURE']

            ExtensionsGoalState.compare(from_extensions_config, from_vm_settings)

            mismatch_events = [kw["message"] for _, kw in add_event_patcher.call_args_list if kw['op'] == WALAEventOperation.GoalStateMismatch]
            self.assertTrue(len(mismatch_events) == 1 and 'required_features' in mismatch_events[0],
                "Expected 1 difference in RequiredFeatures, got: {0}".format(mismatch_events))
