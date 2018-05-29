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
import json
import sys

from azurelinuxagent.common.future import ustr

if sys.version_info[0] == 3:
    import http.client as httpclient
    bytebuffer = memoryview
elif sys.version_info[0] == 2:
    import httplib as httpclient
    bytebuffer = buffer

import azurelinuxagent.common.protocol.restapi as restapi
import azurelinuxagent.common.protocol.wire as wire
import azurelinuxagent.common.protocol.hostplugin as hostplugin

from azurelinuxagent.common import event
from azurelinuxagent.common.exception import ProtocolError, HttpError
from azurelinuxagent.common.protocol.hostplugin import API_VERSION
from azurelinuxagent.common.utils import restutil

from tests.protocol.mockwiredata import WireProtocolData, DATA_FILE
from tests.tools import *

hostplugin_status_url = "http://168.63.129.16:32526/status"
sas_url = "http://sas_url"
wireserver_url = "168.63.129.16"

block_blob_type = 'BlockBlob'
page_blob_type = 'PageBlob'

api_versions = '["2015-09-01"]'
storage_version = "2014-02-14"

faux_status = "{ 'dummy' : 'data' }"
faux_status_b64 = base64.b64encode(bytes(bytearray(faux_status, encoding='utf-8')))
if PY_VERSION_MAJOR > 2:
    faux_status_b64 = faux_status_b64.decode('utf-8')

class TestHostPlugin(AgentTestCase):

    def _compare_data(self, actual, expected):
        for k in iter(expected.keys()):
            if k == 'content' or k == 'requestUri':
                if actual[k] != expected[k]:
                    print("Mismatch: Actual '{0}'='{1}', " \
                        "Expected '{0}'='{3}'".format(
                            k, actual[k], expected[k]))
                    return False
            elif k == 'headers':
                for h in expected['headers']:
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
            s = base64.b64encode(bytes(content))
            if PY_VERSION_MAJOR > 2:
                s = s.decode('utf-8')
            data['content'] = s
        return data
    
    def _hostplugin_headers(self, goal_state):
        return {
            'x-ms-version': '2015-09-01',
            'Content-type': 'application/json',
            'x-ms-containerid': goal_state.container_id,
            'x-ms-host-config-name': goal_state.role_config_name
        }
    
    def _validate_hostplugin_args(self, args, goal_state, exp_method, exp_url, exp_data):
        args, kwargs = args
        self.assertEqual(exp_method, args[0])
        self.assertEqual(exp_url, args[1])
        self.assertTrue(self._compare_data(json.loads(args[2]), exp_data))

        headers = kwargs['headers']
        self.assertEqual(headers['x-ms-containerid'], goal_state.container_id)
        self.assertEqual(headers['x-ms-host-config-name'], goal_state.role_config_name)

    def test_fallback(self):
        """
        Status now defaults to HostPlugin. Validate that any errors on the public
        channel are ignored.  Validate that the default channel is never changed
        as part of status upload.
        """
        test_goal_state = wire.GoalState(WireProtocolData(DATA_FILE).goal_state)
        status = restapi.VMStatus(status="Ready", message="Guest Agent is running")
        with patch.object(wire.HostPluginProtocol,
                          "ensure_initialized",
                          return_value=True):
            with patch.object(wire.StatusBlob, "upload", return_value=False) as patch_upload:
                with patch.object(wire.HostPluginProtocol,
                                  "_put_page_blob_status") as patch_put:
                    wire_protocol_client = wire.WireProtocol(wireserver_url).client
                    wire_protocol_client.get_goal_state = Mock(return_value=test_goal_state)
                    wire_protocol_client.ext_conf = wire.ExtensionsConfig(None)
                    wire_protocol_client.ext_conf.status_upload_blob = sas_url
                    wire_protocol_client.ext_conf.status_upload_blob_type = page_blob_type
                    wire_protocol_client.status_blob.set_vm_status(status)
                    wire_protocol_client.upload_status_blob()
                    self.assertEqual(patch_upload.call_count, 0)
                    self.assertTrue(patch_put.call_count == 1,
                                    "Fallback was not engaged")
                    self.assertTrue(patch_put.call_args[0][0] == sas_url)
                    self.assertFalse(wire.HostPluginProtocol.is_default_channel())

    def test_fallback_failure(self):
        """
        Validate that if host plugin fails and the direct connection fails the
        default channel remains unchanged.
        """
        test_goal_state = wire.GoalState(WireProtocolData(DATA_FILE).goal_state)
        status = restapi.VMStatus(status="Ready",
                                  message="Guest Agent is running")
        wire.HostPluginProtocol.set_default_channel(False)
        with patch.object(wire.HostPluginProtocol,
                          "ensure_initialized",
                          return_value=True):
            with patch.object(wire.StatusBlob,
                              "upload",
                              return_value=False) as patch_upload:
                with patch.object(wire.HostPluginProtocol,
                                  "_put_page_blob_status",
                                  side_effect=wire.HttpError("put failure")) as patch_put:
                    self.assertFalse(wire.HostPluginProtocol.is_default_channel())
                    client = wire.WireProtocol(wireserver_url).client
                    client.get_goal_state = Mock(return_value=test_goal_state)
                    client.ext_conf = wire.ExtensionsConfig(None)
                    client.ext_conf.status_upload_blob = sas_url
                    client.ext_conf.status_upload_blob_type = page_blob_type
                    client.status_blob.set_vm_status(status)
                    client.upload_status_blob()
                    self.assertEqual(1, patch_put.call_count)
                    self.assertEqual(1, patch_upload.call_count)
                    self.assertFalse(wire.HostPluginProtocol.is_default_channel())

    def test_put_status_error_reporting(self):
        """
        Validate the telemetry when uploading status fails
        """
        test_goal_state = wire.GoalState(WireProtocolData(DATA_FILE).goal_state)
        status = restapi.VMStatus(status="Ready",
                                  message="Guest Agent is running")
        wire.HostPluginProtocol.set_default_channel(False)
        with patch.object(wire.StatusBlob,
                          "upload",
                          return_value=False):
            wire_protocol_client = wire.WireProtocol(wireserver_url).client
            wire_protocol_client.get_goal_state = Mock(return_value=test_goal_state)
            wire_protocol_client.ext_conf = wire.ExtensionsConfig(None)
            wire_protocol_client.ext_conf.status_upload_blob = sas_url
            wire_protocol_client.status_blob.set_vm_status(status)
            put_error = wire.HttpError("put status http error")
            with patch.object(event,
                              "add_event") as patch_add_event:
                with patch.object(restutil,
                                  "http_put",
                                  side_effect=put_error) as patch_http_put:
                    with patch.object(wire.HostPluginProtocol,
                                      "ensure_initialized", return_value=True):
                        wire_protocol_client.upload_status_blob()

                        # The agent tries to upload via HostPlugin and that fails due to
                        # http_put having a side effect of "put_error"
                        #
                        # The agent tries to upload using a direct connection, and that succeeds.
                        self.assertEqual(1, wire_protocol_client.status_blob.upload.call_count)
                        # The agent never touches the default protocol is this code path, so no change.
                        self.assertFalse(wire.HostPluginProtocol.is_default_channel())
                        # The agent never logs a telemetry event for a bad HTTP call
                        self.assertEqual(patch_add_event.call_count, 0)

    def test_validate_http_request(self):
        """Validate correct set of data is sent to HostGAPlugin when reporting VM status"""

        wire_protocol_client = wire.WireProtocol(wireserver_url).client
        test_goal_state = wire.GoalState(WireProtocolData(DATA_FILE).goal_state)

        status_blob = wire_protocol_client.status_blob
        status_blob.data = faux_status
        status_blob.vm_status = restapi.VMStatus(message="Ready", status="Ready")

        exp_method = 'PUT'
        exp_url = hostplugin_status_url
        exp_data = self._hostplugin_data(
                        status_blob.get_block_blob_headers(len(faux_status)),
                        bytearray(faux_status, encoding='utf-8'))

        with patch.object(restutil, "http_request") as patch_http:
            patch_http.return_value = Mock(status=httpclient.OK)

            wire_protocol_client.get_goal_state = Mock(return_value=test_goal_state)
            plugin = wire_protocol_client.get_host_plugin()

            with patch.object(plugin, 'get_api_versions') as patch_api:
                patch_api.return_value = API_VERSION
                plugin.put_vm_status(status_blob, sas_url, block_blob_type)

                self.assertTrue(patch_http.call_count == 1)
                self._validate_hostplugin_args(
                    patch_http.call_args_list[0],
                    test_goal_state,
                    exp_method, exp_url, exp_data)

    def test_no_fallback(self):
        """
        Validate fallback to upload status using HostGAPlugin is not happening
        when status reporting via default method is successful
        """
        vmstatus = restapi.VMStatus(message="Ready", status="Ready")
        with patch.object(wire.HostPluginProtocol, "put_vm_status") as patch_put:
            with patch.object(wire.StatusBlob, "upload") as patch_upload:
                patch_upload.return_value = True
                wire_protocol_client = wire.WireProtocol(wireserver_url).client
                wire_protocol_client.ext_conf = wire.ExtensionsConfig(None)
                wire_protocol_client.ext_conf.status_upload_blob = sas_url
                wire_protocol_client.status_blob.vm_status = vmstatus
                wire_protocol_client.upload_status_blob()
                self.assertTrue(patch_put.call_count == 0, "Fallback was engaged")

    def test_validate_block_blob(self):
        """Validate correct set of data is sent to HostGAPlugin when reporting VM status"""
        wire_protocol_client = wire.WireProtocol(wireserver_url).client
        test_goal_state = wire.GoalState(WireProtocolData(DATA_FILE).goal_state)

        host_client = wire.HostPluginProtocol(wireserver_url,
                                              test_goal_state.container_id,
                                              test_goal_state.role_config_name)
        self.assertFalse(host_client.is_initialized)
        self.assertTrue(host_client.api_versions is None)

        status_blob = wire_protocol_client.status_blob
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

                self.assertTrue(patch_http.call_count == 1)
                self._validate_hostplugin_args(
                    patch_http.call_args_list[0],
                    test_goal_state,
                    exp_method, exp_url, exp_data)
    
    def test_validate_page_blobs(self):
        """Validate correct set of data is sent for page blobs"""
        wire_protocol_client = wire.WireProtocol(wireserver_url).client
        test_goal_state = wire.GoalState(WireProtocolData(DATA_FILE).goal_state)

        host_client = wire.HostPluginProtocol(wireserver_url,
                                              test_goal_state.container_id,
                                              test_goal_state.role_config_name)

        self.assertFalse(host_client.is_initialized)
        self.assertTrue(host_client.api_versions is None)

        status_blob = wire_protocol_client.status_blob
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

                self.assertTrue(patch_http.call_count == 2)

                exp_data = self._hostplugin_data(
                                status_blob.get_page_blob_create_headers(
                                page_size))
                self._validate_hostplugin_args(
                    patch_http.call_args_list[0],
                    test_goal_state,
                    exp_method, exp_url, exp_data)

                exp_data = self._hostplugin_data(
                                status_blob.get_page_blob_page_headers(
                                    0, page_size),
                                    page)
                exp_data['requestUri'] += "?comp=page" 
                self._validate_hostplugin_args(
                    patch_http.call_args_list[1],
                    test_goal_state,
                    exp_method, exp_url, exp_data)

    def test_validate_get_extension_artifacts(self):
        test_goal_state = wire.GoalState(WireProtocolData(DATA_FILE).goal_state)
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

        with patch.object(wire.HostPluginProtocol, "get_api_versions", return_value=api_versions) as patch_get:
            actual_url, actual_headers = host_client.get_artifact_request(sas_url)
            self.assertTrue(host_client.is_initialized)
            self.assertFalse(host_client.api_versions is None)
            self.assertEqual(expected_url, actual_url)
            for k in expected_headers:
                self.assertTrue(k in actual_headers)
                self.assertEqual(expected_headers[k], actual_headers[k])
    

class MockResponse:
    def __init__(self, body, status_code):
        self.body = body
        self.status = status_code

    def read(self):
        return self.body

if __name__ == '__main__':
    unittest.main()
