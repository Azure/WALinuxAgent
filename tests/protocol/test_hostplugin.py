# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
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
        Validate fallback to upload status using HostGAPlugin is happening when
        status reporting via default method is unsuccessful
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
                    self.assertEqual(patch_upload.call_count, 1)
                    self.assertTrue(patch_put.call_count == 1,
                                    "Fallback was not engaged")
                    self.assertTrue(patch_put.call_args[0][0] == sas_url)
                    self.assertTrue(wire.HostPluginProtocol.is_default_channel())
                    wire.HostPluginProtocol.set_default_channel(False)

    def test_fallback_failure(self):
        """
        Validate that when host plugin fails, the default channel is reset
        """
        test_goal_state = wire.GoalState(WireProtocolData(DATA_FILE).goal_state)
        status = restapi.VMStatus(status="Ready",
                                  message="Guest Agent is running")
        with patch.object(wire.HostPluginProtocol,
                          "ensure_initialized",
                          return_value=True):
            with patch.object(wire.StatusBlob,
                              "upload",
                              return_value=False):
                with patch.object(wire.HostPluginProtocol,
                                  "_put_page_blob_status",
                                  side_effect=wire.HttpError("put failure")) as patch_put:
                    client = wire.WireProtocol(wireserver_url).client
                    client.get_goal_state = Mock(return_value=test_goal_state)
                    client.ext_conf = wire.ExtensionsConfig(None)
                    client.ext_conf.status_upload_blob = sas_url
                    client.ext_conf.status_upload_blob_type = page_blob_type
                    client.status_blob.set_vm_status(status)
                    client.upload_status_blob()
                    self.assertTrue(patch_put.call_count == 1,
                                    "Fallback was not engaged")
                    self.assertFalse(wire.HostPluginProtocol.is_default_channel())

    def test_put_status_error_reporting(self):
        """
        Validate the telemetry when uploading status fails
        """
        test_goal_state = wire.GoalState(WireProtocolData(DATA_FILE).goal_state)
        status = restapi.VMStatus(status="Ready",
                                  message="Guest Agent is running")
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
                        self.assertFalse(wire.HostPluginProtocol.is_default_channel())
                        self.assertTrue(patch_add_event.call_count == 1)


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

    def test_read_response_error(self):
        """
        Validate the read_response_error method handles encoding correctly
        """
        responses = ['message', b'message', '\x80message\x80']
        response = MagicMock()
        response.status = 'status'
        response.reason = 'reason'
        with patch.object(response, 'read') as patch_response:
            for s in responses:
                patch_response.return_value = s
                result = hostplugin.HostPluginProtocol.read_response_error(response)
                self.assertTrue('[status: reason]' in result)
                self.assertTrue('message' in result)

    def test_read_response_bytes(self):
        response_bytes = '7b:0a:20:20:20:20:22:65:72:72:6f:72:43:6f:64:65:22:' \
                         '3a:20:22:54:68:65:20:62:6c:6f:62:20:74:79:70:65:20:' \
                         '69:73:20:69:6e:76:61:6c:69:64:20:66:6f:72:20:74:68:' \
                         '69:73:20:6f:70:65:72:61:74:69:6f:6e:2e:22:2c:0a:20:' \
                         '20:20:20:22:6d:65:73:73:61:67:65:22:3a:20:22:c3:af:' \
                         'c2:bb:c2:bf:3c:3f:78:6d:6c:20:76:65:72:73:69:6f:6e:' \
                         '3d:22:31:2e:30:22:20:65:6e:63:6f:64:69:6e:67:3d:22:' \
                         '75:74:66:2d:38:22:3f:3e:3c:45:72:72:6f:72:3e:3c:43:' \
                         '6f:64:65:3e:49:6e:76:61:6c:69:64:42:6c:6f:62:54:79:' \
                         '70:65:3c:2f:43:6f:64:65:3e:3c:4d:65:73:73:61:67:65:' \
                         '3e:54:68:65:20:62:6c:6f:62:20:74:79:70:65:20:69:73:' \
                         '20:69:6e:76:61:6c:69:64:20:66:6f:72:20:74:68:69:73:' \
                         '20:6f:70:65:72:61:74:69:6f:6e:2e:0a:52:65:71:75:65:' \
                         '73:74:49:64:3a:63:37:34:32:39:30:63:62:2d:30:30:30:' \
                         '31:2d:30:30:62:35:2d:30:36:64:61:2d:64:64:36:36:36:' \
                         '61:30:30:30:22:2c:0a:20:20:20:20:22:64:65:74:61:69:' \
                         '6c:73:22:3a:20:22:22:0a:7d'.split(':')
        expected_response = '[status: reason] {\n    "errorCode": "The blob ' \
                            'type is invalid for this operation.",\n    ' \
                            '"message": "<?xml version="1.0" ' \
                            'encoding="utf-8"?>' \
                            '<Error><Code>InvalidBlobType</Code><Message>The ' \
                            'blob type is invalid for this operation.\n' \
                            'RequestId:c74290cb-0001-00b5-06da-dd666a000",' \
                            '\n    "details": ""\n}'

        response_string = ''.join(chr(int(b, 16)) for b in response_bytes)
        response = MagicMock()
        response.status = 'status'
        response.reason = 'reason'
        with patch.object(response, 'read') as patch_response:
            patch_response.return_value = response_string
            result = hostplugin.HostPluginProtocol.read_response_error(response)
            self.assertEqual(result, expected_response)
            try:
                raise HttpError("{0}".format(result))
            except HttpError as e:
                self.assertTrue(result in ustr(e))

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
