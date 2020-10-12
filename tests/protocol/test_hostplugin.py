# Copyright 2018 Microsoft Corporation
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

import base64
import contextlib
import datetime
import json
import sys
import unittest

import azurelinuxagent.common.protocol.hostplugin as hostplugin
import azurelinuxagent.common.protocol.restapi as restapi
import azurelinuxagent.common.protocol.wire as wire
from azurelinuxagent.common.errorstate import ErrorState
from azurelinuxagent.common.exception import HttpError, ResourceGoneError
from azurelinuxagent.common.future import ustr, httpclient
from azurelinuxagent.common.osutil.default import UUID_PATTERN
from azurelinuxagent.common.protocol.hostplugin import API_VERSION
from azurelinuxagent.common.utils import restutil
from azurelinuxagent.common.version import AGENT_VERSION, AGENT_NAME
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates
from tests.protocol.mockwiredata import DATA_FILE, DATA_FILE_NO_EXT
from tests.protocol.test_wire import MockResponse as TestWireMockResponse
from tests.tools import AgentTestCase, PY_VERSION_MAJOR, Mock, patch


hostplugin_status_url = "http://168.63.129.16:32526/status" # pylint: disable=invalid-name
hostplugin_versions_url = "http://168.63.129.16:32526/versions" # pylint: disable=invalid-name
health_service_url = 'http://168.63.129.16:80/HealthService' # pylint: disable=invalid-name
hostplugin_logs_url = "http://168.63.129.16:32526/vmAgentLog" # pylint: disable=invalid-name
sas_url = "http://sas_url" # pylint: disable=invalid-name
wireserver_url = "168.63.129.16" # pylint: disable=invalid-name

block_blob_type = 'BlockBlob' # pylint: disable=invalid-name
page_blob_type = 'PageBlob' # pylint: disable=invalid-name

api_versions = '["2015-09-01"]' # pylint: disable=invalid-name
storage_version = "2014-02-14" # pylint: disable=invalid-name

faux_status = "{ 'dummy' : 'data' }" # pylint: disable=invalid-name
faux_status_b64 = base64.b64encode(bytes(bytearray(faux_status, encoding='utf-8'))) # pylint: disable=invalid-name
if PY_VERSION_MAJOR > 2:
    faux_status_b64 = faux_status_b64.decode('utf-8') # pylint: disable=invalid-name


class TestHostPlugin(HttpRequestPredicates, AgentTestCase): # pylint: disable=too-many-public-methods

    def _init_host(self):
        with mock_wire_protocol(DATA_FILE) as protocol:
            test_goal_state = protocol.client.get_goal_state()
            host_plugin = wire.HostPluginProtocol(wireserver_url,
                                                  test_goal_state.container_id,
                                                  test_goal_state.role_config_name)
            self.assertTrue(host_plugin.health_service is not None)
            return host_plugin

    def _init_status_blob(self):
        wire_protocol_client = wire.WireProtocol(wireserver_url).client
        status_blob = wire_protocol_client.status_blob
        status_blob.data = faux_status
        status_blob.vm_status = restapi.VMStatus(message="Ready", status="Ready")
        return status_blob

    def _relax_timestamp(self, headers):
        new_headers = []

        for header in headers:
            header_value = header['headerValue']
            if header['headerName'] == 'x-ms-date':
                timestamp = header['headerValue']
                header_value = timestamp[:timestamp.rfind(":")]

            new_header = {header['headerName']: header_value}
            new_headers.append(new_header)

        return new_headers

    def _compare_data(self, actual, expected):
        # Remove seconds from the timestamps for testing purposes, that level or granularity introduces test flakiness
        actual['headers'] = self._relax_timestamp(actual['headers'])
        expected['headers'] = self._relax_timestamp(expected['headers'])

        for k in iter(expected.keys()):
            if k == 'content' or k == 'requestUri': # pylint: disable=consider-using-in
                if actual[k] != expected[k]:
                    print("Mismatch: Actual '{0}'='{1}', "
                          "Expected '{0}'='{2}'".format(k, actual[k], expected[k]))
                    return False
            elif k == 'headers':
                for h in expected['headers']: # pylint: disable=invalid-name
                    if not (h in actual['headers']):
                        print("Missing Header: '{0}'".format(h))
                        return False
            else:
                print("Unexpected Key: '{0}'".format(k))
                return False
        return True

    def _hostplugin_data(self, blob_headers, content=None):
        headers = []
        for name in iter(blob_headers.keys()):
            headers.append({
                'headerName': name,
                'headerValue': blob_headers[name]
            })

        data = {
            'requestUri': sas_url,
            'headers': headers
        }
        if not content is None:
            s = base64.b64encode(bytes(content)) # pylint: disable=invalid-name
            if PY_VERSION_MAJOR > 2:
                s = s.decode('utf-8') # pylint: disable=invalid-name
            data['content'] = s
        return data

    def _hostplugin_headers(self, goal_state):
        return {
            'x-ms-version': '2015-09-01',
            'Content-type': 'application/json',
            'x-ms-containerid': goal_state.container_id,
            'x-ms-host-config-name': goal_state.role_config_name
        }

    def _validate_hostplugin_args(self, args, goal_state, exp_method, exp_url, exp_data): # pylint: disable=too-many-arguments
        args, kwargs = args
        self.assertEqual(exp_method, args[0])
        self.assertEqual(exp_url, args[1])
        self.assertTrue(self._compare_data(json.loads(args[2]), exp_data))

        headers = kwargs['headers']
        self.assertEqual(headers['x-ms-containerid'], goal_state.container_id)
        self.assertEqual(headers['x-ms-host-config-name'], goal_state.role_config_name)

    @staticmethod
    @contextlib.contextmanager
    def create_mock_protocol():
        with mock_wire_protocol(DATA_FILE_NO_EXT) as protocol:
            # These tests use mock wire data that don't have any extensions (extension config will be empty).
            # Populate the upload blob and set an initial empty status before returning the protocol.
            ext_conf = protocol.client._goal_state.ext_conf # pylint: disable=protected-access
            ext_conf.status_upload_blob = sas_url
            ext_conf.status_upload_blob_type = page_blob_type

            status = restapi.VMStatus(status="Ready", message="Guest Agent is running")
            protocol.client.status_blob.set_vm_status(status)

            # Also, they mock WireClient.update_goal_state() to verify how it is called
            protocol.client.update_goal_state = Mock()

            yield protocol

    @patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_versions")
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    @patch("azurelinuxagent.common.protocol.hostplugin.add_event")
    def assert_ensure_initialized(self, patch_event, patch_http_get, patch_report_health, # pylint: disable=too-many-arguments
                                  response_body,
                                  response_status_code,
                                  should_initialize,
                                  should_report_healthy):

        host = hostplugin.HostPluginProtocol(endpoint='ws', container_id='cid', role_config_name='rcf')

        host.is_initialized = False
        patch_http_get.return_value = MockResponse(body=response_body,
                                                   reason='reason',
                                                   status_code=response_status_code)
        return_value = host.ensure_initialized()

        self.assertEqual(return_value, host.is_available)
        self.assertEqual(should_initialize, host.is_initialized)

        self.assertEqual(1, patch_event.call_count)
        self.assertEqual('InitializeHostPlugin', patch_event.call_args[0][0])

        self.assertEqual(should_initialize, patch_event.call_args[1]['is_success'])
        self.assertEqual(1, patch_report_health.call_count)

        self.assertEqual(should_report_healthy, patch_report_health.call_args[1]['is_healthy'])

        actual_response = patch_report_health.call_args[1]['response']
        if should_initialize:
            self.assertEqual('', actual_response)
        else:
            self.assertTrue('HTTP Failed' in actual_response)
            self.assertTrue(response_body in actual_response)
            self.assertTrue(ustr(response_status_code) in actual_response)

    def test_ensure_initialized(self):
        """
        Test calls to ensure_initialized
        """
        self.assert_ensure_initialized(response_body=api_versions, # pylint: disable=no-value-for-parameter
                                       response_status_code=200,
                                       should_initialize=True,
                                       should_report_healthy=True)

        self.assert_ensure_initialized(response_body='invalid ip', # pylint: disable=no-value-for-parameter
                                       response_status_code=400,
                                       should_initialize=False,
                                       should_report_healthy=True)

        self.assert_ensure_initialized(response_body='generic bad request', # pylint: disable=no-value-for-parameter
                                       response_status_code=400,
                                       should_initialize=False,
                                       should_report_healthy=True)

        self.assert_ensure_initialized(response_body='resource gone', # pylint: disable=no-value-for-parameter
                                       response_status_code=410,
                                       should_initialize=False,
                                       should_report_healthy=True)

        self.assert_ensure_initialized(response_body='generic error', # pylint: disable=no-value-for-parameter
                                       response_status_code=500,
                                       should_initialize=False,
                                       should_report_healthy=False)

        self.assert_ensure_initialized(response_body='upstream error', # pylint: disable=no-value-for-parameter
                                       response_status_code=502,
                                       should_initialize=False,
                                       should_report_healthy=True)

    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.ensure_initialized", return_value=True)
    @patch("azurelinuxagent.common.protocol.wire.StatusBlob.upload", return_value=False)
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol._put_page_blob_status")
    def test_default_channel(self, patch_put, patch_upload, _):
        """
        Status now defaults to HostPlugin. Validate that any errors on the public
        channel are ignored.  Validate that the default channel is never changed
        as part of status upload.
        """
        with self.create_mock_protocol() as wire_protocol:
            wire_protocol.update_goal_state()

            # act
            wire_protocol.client.upload_status_blob()

            # assert direct route is not called
            self.assertEqual(0, patch_upload.call_count, "Direct channel was used")

            # assert host plugin route is called
            self.assertEqual(1, patch_put.call_count, "Host plugin was not used")

            # assert update goal state is only called once, non-forced
            self.assertEqual(1, wire_protocol.client.update_goal_state.call_count, "Unexpected call count")
            self.assertEqual(0, len(wire_protocol.client.update_goal_state.call_args[1]), "Unexpected parameters")

            # ensure the correct url is used
            self.assertEqual(sas_url, patch_put.call_args[0][0])

            # ensure host plugin is not set as default
            self.assertFalse(wire.HostPluginProtocol.is_default_channel())

    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.ensure_initialized",
           return_value=True)
    @patch("azurelinuxagent.common.protocol.wire.StatusBlob.upload",
           return_value=True)
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol._put_page_blob_status",
           side_effect=HttpError("503"))
    def test_fallback_channel_503(self, patch_put, patch_upload, _):
        """
        When host plugin returns a 503, we should fall back to the direct channel
        """
        with self.create_mock_protocol() as wire_protocol:
            wire_protocol.update_goal_state()

            # act
            wire_protocol.client.upload_status_blob()

            # assert direct route is called
            self.assertEqual(1, patch_upload.call_count, "Direct channel was not used")

            # assert host plugin route is called
            self.assertEqual(1, patch_put.call_count, "Host plugin was not used")

            # assert update goal state is only called once, non-forced
            self.assertEqual(1, wire_protocol.client.update_goal_state.call_count, "Update goal state unexpected call count")
            self.assertEqual(0, len(wire_protocol.client.update_goal_state.call_args[1]), "Update goal state unexpected call count")

            # ensure the correct url is used
            self.assertEqual(sas_url, patch_put.call_args[0][0])

            # ensure host plugin is not set as default
            self.assertFalse(wire.HostPluginProtocol.is_default_channel())

    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.ensure_initialized",
           return_value=True)
    @patch("azurelinuxagent.common.protocol.wire.StatusBlob.upload",
           return_value=True)
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol._put_page_blob_status",
           side_effect=ResourceGoneError("410"))
    @patch("azurelinuxagent.common.protocol.wire.WireClient.update_host_plugin_from_goal_state")
    def test_fallback_channel_410(self, patch_refresh_host_plugin, patch_put, patch_upload, _):
        """
        When host plugin returns a 410, we should force the goal state update and return
        """
        with self.create_mock_protocol() as wire_protocol:
            wire_protocol.update_goal_state()

            # act
            wire_protocol.client.upload_status_blob()

            # assert direct route is not called
            self.assertEqual(0, patch_upload.call_count, "Direct channel was used")

            # assert host plugin route is called
            self.assertEqual(1, patch_put.call_count, "Host plugin was not used")

            # assert update goal state is called with no arguments (forced=False), then update_host_plugin_from_goal_state is called
            self.assertEqual(1, wire_protocol.client.update_goal_state.call_count, "Update goal state unexpected call count")
            self.assertEqual(0, len(wire_protocol.client.update_goal_state.call_args[1]), "Update goal state unexpected argument count")
            self.assertEqual(1, patch_refresh_host_plugin.call_count, "Refresh host plugin unexpected call count")

            # ensure the correct url is used
            self.assertEqual(sas_url, patch_put.call_args[0][0])

            # ensure host plugin is not set as default
            self.assertFalse(wire.HostPluginProtocol.is_default_channel())

    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.ensure_initialized",
           return_value=True)
    @patch("azurelinuxagent.common.protocol.wire.StatusBlob.upload",
           return_value=False)
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol._put_page_blob_status",
           side_effect=HttpError("500"))
    def test_fallback_channel_failure(self, patch_put, patch_upload, _):
        """
        When host plugin returns a 500, and direct fails, we should raise a ProtocolError
        """
        with self.create_mock_protocol() as wire_protocol:
            wire_protocol.update_goal_state()

            # act
            self.assertRaises(wire.ProtocolError, wire_protocol.client.upload_status_blob)

            # assert direct route is not called
            self.assertEqual(1, patch_upload.call_count, "Direct channel was not used")

            # assert host plugin route is called
            self.assertEqual(1, patch_put.call_count, "Host plugin was not used")

            # assert update goal state is called twice, forced=True on the second
            self.assertEqual(1, wire_protocol.client.update_goal_state.call_count, "Update goal state unexpected call count")
            self.assertEqual(0, len(wire_protocol.client.update_goal_state.call_args[1]), "Update goal state unexpected call count")

            # ensure the correct url is used
            self.assertEqual(sas_url, patch_put.call_args[0][0])

            # ensure host plugin is not set as default
            self.assertFalse(wire.HostPluginProtocol.is_default_channel())

    @patch("azurelinuxagent.common.event.add_event")
    def test_put_status_error_reporting(self, patch_add_event):
        """
        Validate the telemetry when uploading status fails
        """
        wire.HostPluginProtocol.set_default_channel(False)
        with patch.object(wire.StatusBlob, "upload", return_value=False):
            with self.create_mock_protocol() as wire_protocol:
                wire_protocol_client = wire_protocol.client

                put_error = wire.HttpError("put status http error")
                with patch.object(restutil, "http_put", side_effect=put_error):
                    with patch.object(wire.HostPluginProtocol,
                                      "ensure_initialized", return_value=True):
                        self.assertRaises(wire.ProtocolError, wire_protocol_client.upload_status_blob)

                        # The agent tries to upload via HostPlugin and that fails due to
                        # http_put having a side effect of "put_error"
                        #
                        # The agent tries to upload using a direct connection, and that succeeds.
                        self.assertEqual(1, wire_protocol_client.status_blob.upload.call_count) # pylint: disable=no-member
                        # The agent never touches the default protocol is this code path, so no change.
                        self.assertFalse(wire.HostPluginProtocol.is_default_channel())
                        # The agent never logs telemetry event for direct fallback
                        self.assertEqual(1, patch_add_event.call_count)
                        self.assertEqual('ReportStatus', patch_add_event.call_args[1]['op'])
                        self.assertTrue('Falling back to direct' in patch_add_event.call_args[1]['message'])
                        self.assertEqual(True, patch_add_event.call_args[1]['is_success'])

    def test_validate_http_request_when_uploading_status(self):
        """Validate correct set of data is sent to HostGAPlugin when reporting VM status"""

        with mock_wire_protocol(DATA_FILE) as protocol:
            test_goal_state = protocol.client._goal_state # pylint: disable=protected-access
            plugin = protocol.client.get_host_plugin()

            status_blob = protocol.client.status_blob
            status_blob.data = faux_status
            status_blob.vm_status = restapi.VMStatus(message="Ready", status="Ready")

            exp_method = 'PUT'
            exp_url = hostplugin_status_url
            exp_data = self._hostplugin_data(
                status_blob.get_block_blob_headers(len(faux_status)),
                bytearray(faux_status, encoding='utf-8'))

            with patch.object(restutil, "http_request") as patch_http:
                patch_http.return_value = Mock(status=httpclient.OK)

                with patch.object(plugin, 'get_api_versions') as patch_api:
                    patch_api.return_value = API_VERSION
                    plugin.put_vm_status(status_blob, sas_url, block_blob_type)

                    self.assertTrue(patch_http.call_count == 2)

                    # first call is to host plugin
                    self._validate_hostplugin_args(
                        patch_http.call_args_list[0],
                        test_goal_state,
                        exp_method, exp_url, exp_data)

                    # second call is to health service
                    self.assertEqual('POST', patch_http.call_args_list[1][0][0])
                    self.assertEqual(health_service_url, patch_http.call_args_list[1][0][1])

    def test_validate_block_blob(self):
        with mock_wire_protocol(DATA_FILE) as protocol:
            test_goal_state = protocol.client._goal_state # pylint: disable=protected-access

            host_client = wire.HostPluginProtocol(wireserver_url,
                                                  test_goal_state.container_id,
                                                  test_goal_state.role_config_name)
            self.assertFalse(host_client.is_initialized)
            self.assertTrue(host_client.api_versions is None)
            self.assertTrue(host_client.health_service is not None)

            status_blob = protocol.client.status_blob
            status_blob.data = faux_status
            status_blob.type = block_blob_type
            status_blob.vm_status = restapi.VMStatus(message="Ready", status="Ready")

            exp_method = 'PUT'
            exp_url = hostplugin_status_url
            exp_data = self._hostplugin_data(
                status_blob.get_block_blob_headers(len(faux_status)),
                bytearray(faux_status, encoding='utf-8'))

            with patch.object(restutil, "http_request") as patch_http:
                patch_http.return_value = Mock(status=httpclient.OK)

                with patch.object(wire.HostPluginProtocol,
                                  "get_api_versions") as patch_get:
                    patch_get.return_value = api_versions
                    host_client.put_vm_status(status_blob, sas_url)

                    self.assertTrue(patch_http.call_count == 2)

                    # first call is to host plugin
                    self._validate_hostplugin_args(
                        patch_http.call_args_list[0],
                        test_goal_state,
                        exp_method, exp_url, exp_data)

                    # second call is to health service
                    self.assertEqual('POST', patch_http.call_args_list[1][0][0])
                    self.assertEqual(health_service_url, patch_http.call_args_list[1][0][1])

    def test_validate_page_blobs(self):
        """Validate correct set of data is sent for page blobs"""
        with mock_wire_protocol(DATA_FILE) as protocol:
            test_goal_state = protocol.client._goal_state # pylint: disable=protected-access

            host_client = wire.HostPluginProtocol(wireserver_url,
                                                  test_goal_state.container_id,
                                                  test_goal_state.role_config_name)

            self.assertFalse(host_client.is_initialized)
            self.assertTrue(host_client.api_versions is None)

            status_blob = protocol.client.status_blob
            status_blob.data = faux_status
            status_blob.type = page_blob_type
            status_blob.vm_status = restapi.VMStatus(message="Ready", status="Ready")

            exp_method = 'PUT'
            exp_url = hostplugin_status_url

            page_status = bytearray(status_blob.data, encoding='utf-8')
            page_size = int((len(page_status) + 511) / 512) * 512
            page_status = bytearray(status_blob.data.ljust(page_size), encoding='utf-8')
            page = bytearray(page_size)
            page[0: page_size] = page_status[0: len(page_status)]
            mock_response = MockResponse('', httpclient.OK)

            with patch.object(restutil, "http_request",
                              return_value=mock_response) as patch_http:
                with patch.object(wire.HostPluginProtocol,
                                  "get_api_versions") as patch_get:
                    patch_get.return_value = api_versions
                    host_client.put_vm_status(status_blob, sas_url)

                    self.assertTrue(patch_http.call_count == 3)

                    # first call is to host plugin
                    exp_data = self._hostplugin_data(
                        status_blob.get_page_blob_create_headers(
                            page_size))
                    self._validate_hostplugin_args(
                        patch_http.call_args_list[0],
                        test_goal_state,
                        exp_method, exp_url, exp_data)

                    # second call is to health service
                    self.assertEqual('POST', patch_http.call_args_list[1][0][0])
                    self.assertEqual(health_service_url, patch_http.call_args_list[1][0][1])

                    # last call is to host plugin
                    exp_data = self._hostplugin_data(
                        status_blob.get_page_blob_page_headers(
                            0, page_size),
                        page)
                    exp_data['requestUri'] += "?comp=page"
                    self._validate_hostplugin_args(
                        patch_http.call_args_list[2],
                        test_goal_state,
                        exp_method, exp_url, exp_data)

    def test_validate_http_request_for_put_vm_log(self):
        def http_put_handler(url, *args, **kwargs): # pylint: disable=inconsistent-return-statements
            if self.is_host_plugin_put_logs_request(url):
                http_put_handler.args, http_put_handler.kwargs = args, kwargs
                return MockResponse(body=b'', status_code=200)

        http_put_handler.args, http_put_handler.kwargs = [], {}

        with mock_wire_protocol(DATA_FILE, http_put_handler=http_put_handler) as protocol:
            test_goal_state = protocol.client.get_goal_state()

            expected_url = hostplugin.URI_FORMAT_PUT_LOG.format(wireserver_url, hostplugin.HOST_PLUGIN_PORT)
            expected_headers = {'x-ms-version': '2015-09-01',
                                "x-ms-containerid": test_goal_state.container_id,
                                "x-ms-vmagentlog-deploymentid": test_goal_state.role_config_name.split(".")[0],
                                "x-ms-client-name": AGENT_NAME,
                                "x-ms-client-version": AGENT_VERSION}

            host_client = wire.HostPluginProtocol(wireserver_url,
                                                  test_goal_state.container_id,
                                                  test_goal_state.role_config_name)

            self.assertFalse(host_client.is_initialized, "Host plugin should not be initialized!")

            content = b"test"
            host_client.put_vm_log(content)
            self.assertTrue(host_client.is_initialized, "Host plugin is not initialized!")

            urls = protocol.get_tracked_urls()

            self.assertEqual(expected_url, urls[0], "Unexpected request URL!")
            self.assertEqual(content, http_put_handler.args[0], "Unexpected content for HTTP PUT request!")

            headers = http_put_handler.kwargs['headers']
            for k in expected_headers:
                self.assertTrue(k in headers, "Header {0} not found in headers!".format(k))
                self.assertEqual(expected_headers[k], headers[k], "Request headers don't match!")

            # Special check for correlation id header value, check for pattern, not exact value
            self.assertTrue("x-ms-client-correlationid" in headers.keys(), "Correlation id not found in headers!")
            self.assertTrue(UUID_PATTERN.match(headers["x-ms-client-correlationid"]), "Correlation id is not in GUID form!")

    def test_put_vm_log_should_raise_an_exception_when_request_fails(self):
        def http_put_handler(url, *args, **kwargs): # pylint: disable=inconsistent-return-statements
            if self.is_host_plugin_put_logs_request(url):
                http_put_handler.args, http_put_handler.kwargs = args, kwargs
                return MockResponse(body=ustr('Gone'), status_code=410)

        http_put_handler.args, http_put_handler.kwargs = [], {}

        with mock_wire_protocol(DATA_FILE, http_put_handler=http_put_handler) as protocol:
            test_goal_state = protocol.client.get_goal_state()

            host_client = wire.HostPluginProtocol(wireserver_url,
                                                  test_goal_state.container_id,
                                                  test_goal_state.role_config_name)

            self.assertFalse(host_client.is_initialized, "Host plugin should not be initialized!")

            with self.assertRaises(HttpError) as context_manager:
                content = b"test"
                host_client.put_vm_log(content)

            self.assertIsInstance(context_manager.exception, HttpError)
            self.assertIn("410", ustr(context_manager.exception))
            self.assertIn("Gone", ustr(context_manager.exception))

    def test_validate_get_extension_artifacts(self):
        with mock_wire_protocol(DATA_FILE) as protocol:
            test_goal_state = protocol.client._goal_state # pylint: disable=protected-access

            expected_url = hostplugin.URI_FORMAT_GET_EXTENSION_ARTIFACT.format(wireserver_url, hostplugin.HOST_PLUGIN_PORT)
            expected_headers = {'x-ms-version': '2015-09-01',
                                "x-ms-containerid": test_goal_state.container_id,
                                "x-ms-host-config-name": test_goal_state.role_config_name,
                                "x-ms-artifact-location": sas_url}

            host_client = wire.HostPluginProtocol(wireserver_url,
                                                  test_goal_state.container_id,
                                                  test_goal_state.role_config_name)
            self.assertFalse(host_client.is_initialized)
            self.assertTrue(host_client.api_versions is None)
            self.assertTrue(host_client.health_service is not None)

            with patch.object(wire.HostPluginProtocol, "get_api_versions", return_value=api_versions) as patch_get: # pylint: disable=unused-variable
                actual_url, actual_headers = host_client.get_artifact_request(sas_url)
                self.assertTrue(host_client.is_initialized)
                self.assertFalse(host_client.api_versions is None)
                self.assertEqual(expected_url, actual_url)
                for k in expected_headers:
                    self.assertTrue(k in actual_headers)
                    self.assertEqual(expected_headers[k], actual_headers[k])

    def test_health(self):
        host_plugin = self._init_host()

        with patch("azurelinuxagent.common.utils.restutil.http_get") as patch_http_get:
            patch_http_get.return_value = MockResponse('', 200)
            result = host_plugin.get_health()
            self.assertEqual(1, patch_http_get.call_count)
            self.assertTrue(result)

            patch_http_get.return_value = MockResponse('', 500)
            result = host_plugin.get_health()
            self.assertFalse(result)

            patch_http_get.side_effect = IOError('client IO error')
            try:
                host_plugin.get_health()
                self.fail('IO error expected to be raised')
            except IOError:
                # expected
                pass

    def test_ensure_health_service_called(self):
        host_plugin = self._init_host()

        with patch("azurelinuxagent.common.utils.restutil.http_get", return_value=TestWireMockResponse(status_code=200, body=b'')) as patch_http_get:
            with patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_versions") as patch_report_versions:
                host_plugin.get_api_versions()
                self.assertEqual(1, patch_http_get.call_count)
                self.assertEqual(1, patch_report_versions.call_count)

    def test_put_status_healthy_signal(self):
        host_plugin = self._init_host()

        with patch("azurelinuxagent.common.utils.restutil.http_get") as patch_http_get:
            with patch("azurelinuxagent.common.utils.restutil.http_post") as patch_http_post:
                with patch("azurelinuxagent.common.utils.restutil.http_put") as patch_http_put:
                    status_blob = self._init_status_blob()
                    # get_api_versions
                    patch_http_get.return_value = MockResponse(api_versions, 200)
                    # put status blob
                    patch_http_put.return_value = MockResponse(None, 201)

                    host_plugin.put_vm_status(status_blob=status_blob, sas_url=sas_url)
                    self.assertEqual(1, patch_http_get.call_count)
                    self.assertEqual(hostplugin_versions_url, patch_http_get.call_args[0][0])

                    self.assertEqual(2, patch_http_put.call_count)
                    self.assertEqual(hostplugin_status_url, patch_http_put.call_args_list[0][0][0])
                    self.assertEqual(hostplugin_status_url, patch_http_put.call_args_list[1][0][0])

                    self.assertEqual(2, patch_http_post.call_count)

                    # signal for /versions
                    self.assertEqual(health_service_url, patch_http_post.call_args_list[0][0][0])
                    jstr = patch_http_post.call_args_list[0][0][1]
                    obj = json.loads(jstr)
                    self.assertEqual(1, len(obj['Observations']))
                    self.assertTrue(obj['Observations'][0]['IsHealthy'])
                    self.assertEqual('GuestAgentPluginVersions', obj['Observations'][0]['ObservationName'])

                    # signal for /status
                    self.assertEqual(health_service_url, patch_http_post.call_args_list[1][0][0])
                    jstr = patch_http_post.call_args_list[1][0][1]
                    obj = json.loads(jstr)
                    self.assertEqual(1, len(obj['Observations']))
                    self.assertTrue(obj['Observations'][0]['IsHealthy'])
                    self.assertEqual('GuestAgentPluginStatus', obj['Observations'][0]['ObservationName'])

    def test_put_status_unhealthy_signal_transient(self):
        host_plugin = self._init_host()

        with patch("azurelinuxagent.common.utils.restutil.http_get") as patch_http_get:
            with patch("azurelinuxagent.common.utils.restutil.http_post") as patch_http_post:
                with patch("azurelinuxagent.common.utils.restutil.http_put") as patch_http_put:
                    status_blob = self._init_status_blob()
                    # get_api_versions
                    patch_http_get.return_value = MockResponse(api_versions, 200)
                    # put status blob
                    patch_http_put.return_value = MockResponse(None, 500)

                    with self.assertRaises(HttpError):
                        host_plugin.put_vm_status(status_blob=status_blob, sas_url=sas_url)

                    self.assertEqual(1, patch_http_get.call_count)
                    self.assertEqual(hostplugin_versions_url, patch_http_get.call_args[0][0])

                    self.assertEqual(1, patch_http_put.call_count)
                    self.assertEqual(hostplugin_status_url, patch_http_put.call_args[0][0])

                    self.assertEqual(2, patch_http_post.call_count)

                    # signal for /versions
                    self.assertEqual(health_service_url, patch_http_post.call_args_list[0][0][0])
                    jstr = patch_http_post.call_args_list[0][0][1]
                    obj = json.loads(jstr)
                    self.assertEqual(1, len(obj['Observations']))
                    self.assertTrue(obj['Observations'][0]['IsHealthy'])
                    self.assertEqual('GuestAgentPluginVersions', obj['Observations'][0]['ObservationName'])

                    # signal for /status
                    self.assertEqual(health_service_url, patch_http_post.call_args_list[1][0][0])
                    jstr = patch_http_post.call_args_list[1][0][1]
                    obj = json.loads(jstr)
                    self.assertEqual(1, len(obj['Observations']))
                    self.assertTrue(obj['Observations'][0]['IsHealthy'])
                    self.assertEqual('GuestAgentPluginStatus', obj['Observations'][0]['ObservationName'])

    def test_put_status_unhealthy_signal_permanent(self):
        host_plugin = self._init_host()

        with patch("azurelinuxagent.common.utils.restutil.http_get") as patch_http_get:
            with patch("azurelinuxagent.common.utils.restutil.http_post") as patch_http_post:
                with patch("azurelinuxagent.common.utils.restutil.http_put") as patch_http_put:
                    status_blob = self._init_status_blob()
                    # get_api_versions
                    patch_http_get.return_value = MockResponse(api_versions, 200)
                    # put status blob
                    patch_http_put.return_value = MockResponse(None, 500)

                    host_plugin.status_error_state.is_triggered = Mock(return_value=True)

                    with self.assertRaises(HttpError):
                        host_plugin.put_vm_status(status_blob=status_blob, sas_url=sas_url)

                    self.assertEqual(1, patch_http_get.call_count)
                    self.assertEqual(hostplugin_versions_url, patch_http_get.call_args[0][0])

                    self.assertEqual(1, patch_http_put.call_count)
                    self.assertEqual(hostplugin_status_url, patch_http_put.call_args[0][0])

                    self.assertEqual(2, patch_http_post.call_count)

                    # signal for /versions
                    self.assertEqual(health_service_url, patch_http_post.call_args_list[0][0][0])
                    jstr = patch_http_post.call_args_list[0][0][1]
                    obj = json.loads(jstr)
                    self.assertEqual(1, len(obj['Observations']))
                    self.assertTrue(obj['Observations'][0]['IsHealthy'])
                    self.assertEqual('GuestAgentPluginVersions', obj['Observations'][0]['ObservationName'])

                    # signal for /status
                    self.assertEqual(health_service_url, patch_http_post.call_args_list[1][0][0])
                    jstr = patch_http_post.call_args_list[1][0][1]
                    obj = json.loads(jstr)
                    self.assertEqual(1, len(obj['Observations']))
                    self.assertFalse(obj['Observations'][0]['IsHealthy'])
                    self.assertEqual('GuestAgentPluginStatus', obj['Observations'][0]['ObservationName'])

    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.should_report", return_value=True)
    @patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_extension_artifact")
    def test_report_fetch_health(self, patch_report_artifact, patch_should_report):
        host_plugin = self._init_host()
        host_plugin.report_fetch_health(uri='', is_healthy=True)
        self.assertEqual(0, patch_should_report.call_count)

        host_plugin.report_fetch_health(uri='http://169.254.169.254/extensionArtifact', is_healthy=True)
        self.assertEqual(0, patch_should_report.call_count)

        host_plugin.report_fetch_health(uri='http://168.63.129.16:32526/status', is_healthy=True)
        self.assertEqual(0, patch_should_report.call_count)

        self.assertEqual(None, host_plugin.fetch_last_timestamp)
        host_plugin.report_fetch_health(uri='http://168.63.129.16:32526/extensionArtifact', is_healthy=True)
        self.assertNotEqual(None, host_plugin.fetch_last_timestamp)
        self.assertEqual(1, patch_should_report.call_count)
        self.assertEqual(1, patch_report_artifact.call_count)

    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.should_report", return_value=True)
    @patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_status")
    def test_report_status_health(self, patch_report_status, patch_should_report):
        host_plugin = self._init_host()
        self.assertEqual(None, host_plugin.status_last_timestamp)
        host_plugin.report_status_health(is_healthy=True)
        self.assertNotEqual(None, host_plugin.status_last_timestamp)
        self.assertEqual(1, patch_should_report.call_count)
        self.assertEqual(1, patch_report_status.call_count)

    def test_should_report(self):
        host_plugin = self._init_host()
        error_state = ErrorState(min_timedelta=datetime.timedelta(minutes=5))
        period = datetime.timedelta(minutes=1)
        last_timestamp = None

        # first measurement at 0s, should report
        is_healthy = True
        actual = host_plugin.should_report(is_healthy,
                                           error_state,
                                           last_timestamp,
                                           period)
        self.assertEqual(True, actual)

        # second measurement at 30s, should not report
        last_timestamp = datetime.datetime.utcnow() - datetime.timedelta(seconds=30)
        actual = host_plugin.should_report(is_healthy,
                                           error_state,
                                           last_timestamp,
                                           period)
        self.assertEqual(False, actual)

        # third measurement at 60s, should report
        last_timestamp = datetime.datetime.utcnow() - datetime.timedelta(seconds=60)
        actual = host_plugin.should_report(is_healthy,
                                           error_state,
                                           last_timestamp,
                                           period)
        self.assertEqual(True, actual)

        # fourth measurement unhealthy, should report and increment counter
        is_healthy = False
        self.assertEqual(0, error_state.count)
        actual = host_plugin.should_report(is_healthy,
                                           error_state,
                                           last_timestamp,
                                           period)
        self.assertEqual(1, error_state.count)
        self.assertEqual(True, actual)

        # fifth measurement, should not report and reset counter
        is_healthy = True
        last_timestamp = datetime.datetime.utcnow() - datetime.timedelta(seconds=30)
        self.assertEqual(1, error_state.count)
        actual = host_plugin.should_report(is_healthy,
                                           error_state,
                                           last_timestamp,
                                           period)
        self.assertEqual(0, error_state.count)
        self.assertEqual(False, actual)


class MockResponse: # pylint: disable=too-few-public-methods
    def __init__(self, body, status_code, reason=''):
        self.body = body
        self.status = status_code
        self.reason = reason

    def read(self):
        return self.body if sys.version_info[0] == 2 else bytes(self.body, encoding='utf-8')


if __name__ == '__main__':
    unittest.main()
