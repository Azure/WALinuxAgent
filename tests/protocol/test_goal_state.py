# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

import json
import os

from azurelinuxagent.common.future import httpclient
from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import IncompleteGoalStateError
from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState
from azurelinuxagent.common.protocol.goal_state import GoalState, _NUM_GS_FETCH_RETRIES
from azurelinuxagent.common.protocol import hostplugin
from azurelinuxagent.common.utils import restutil
from tests.protocol.mocks import mock_wire_protocol
from tests.protocol import mockwiredata
from tests.protocol.mocks import HttpRequestPredicates, MockHttpResponse
from tests.tools import AgentTestCase, patch

_original_http_request = restutil.http_request

@patch("azurelinuxagent.common.protocol.wire.conf.get_enable_fast_track", return_value=True)
class GoalStateTestCase(HttpRequestPredicates, AgentTestCase):
    def test_fetch_goal_state_should_raise_on_incomplete_goal_state(self, _):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.mock_wire_data.data_files = mockwiredata.DATA_FILE_NOOP_GS
            protocol.mock_wire_data.reload()
            protocol.mock_wire_data.set_incarnation(2)

            with patch('time.sleep') as mock_sleep:
                with self.assertRaises(IncompleteGoalStateError):
                    GoalState(protocol.client)
                self.assertEqual(_NUM_GS_FETCH_RETRIES, mock_sleep.call_count, "Unexpected number of retries")

    def test_update_goal_state_should_save_goal_state(self, _):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS_PROTECTED_SETTINGS) as protocol:
            protocol.mock_wire_data.set_incarnation(999)
            protocol.mock_wire_data.set_etag(888)
            protocol.update_goal_state()

        extensions_config_file = os.path.join(conf.get_lib_dir(), "ExtensionsConfig.999.xml")
        vm_settings_file = os.path.join(conf.get_lib_dir(), "VmSettings.888.json")
        expected_files = [
            os.path.join(conf.get_lib_dir(), "GoalState.999.xml"),
            os.path.join(conf.get_lib_dir(), "SharedConfig.xml"),
            os.path.join(conf.get_lib_dir(), "Certificates.xml"),
            os.path.join(conf.get_lib_dir(), "HostingEnvironmentConfig.xml"),
            extensions_config_file,
            vm_settings_file
        ]

        for f in expected_files:
            self.assertTrue(os.path.exists(f), "{0} was not saved".format(f))

        with open(extensions_config_file, "r") as file_:
            extensions_goal_state = ExtensionsGoalState.from_extensions_config(file_.read())
        self.assertEqual(4, len(extensions_goal_state.ext_handlers.extHandlers), "Expected 4 extensions in the test ExtensionsConfig")
        for e in extensions_goal_state.ext_handlers.extHandlers:
            self.assertEqual(e.properties.extensions[0].protectedSettings, "*** REDACTED ***", "The protected settings for {0} were not redacted".format(e.name))

        # TODO: Use azurelinuxagent.common.protocol.ExtensionsGoalState once it implements parsing
        with open(vm_settings_file, "r") as file_:
            vm_settings = json.load(file_)
        extensions = vm_settings["extensionGoalStates"]
        self.assertEqual(4, len(extensions), "Expected 4 extensions in the test vmSettings")
        for e in extensions:
            self.assertEqual(e["settings"][0]["protectedSettings"], "*** REDACTED ***", "The protected settings for {0} were not redacted".format(e["name"]))

    def test_update_vm_settings_should_should_retry_on_resource_gone_error(self, _):
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
                protocol.client._update_vm_settings(force_update=False)

            self.assertEqual(2, len(request_headers), "We expected 2 requests for vmSettings: the original request and the retry request")
            self.assertEqual("GET_VM_SETTINGS_TEST_CONTAINER_ID", request_headers[1][hostplugin._HEADER_CONTAINER_ID], "The retry request did not include the expected header for the ContainerId")
            self.assertEqual("GET_VM_SETTINGS_TEST_ROLE_CONFIG_NAME", request_headers[1][hostplugin._HEADER_HOST_CONFIG_NAME], "The retry request did not include the expected header for the RoleConfigName")

