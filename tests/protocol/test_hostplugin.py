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

import unittest

import azurelinuxagent.common.protocol.restapi as restapi
import azurelinuxagent.common.protocol.wire as wire
from tests.tools import *

wireserver_url = "168.63.129.16"
sas_url = "http://sas_url"
api_versions = '["2015-09-01"]'


class TestHostPlugin(AgentTestCase):
    def test_fallback(self):
        with patch.object(wire.HostPluginProtocol,
                          "put_vm_status") as patch_put:
            with patch.object(wire.StatusBlob, "upload") as patch_upload:
                patch_upload.return_value = False
                wire_protocol_client = wire.WireProtocol(wireserver_url).client
                wire_protocol_client.ext_conf = wire.ExtensionsConfig(None)
                wire_protocol_client.ext_conf.status_upload_blob = sas_url
                wire_protocol_client.upload_status_blob()
                self.assertTrue(patch_put.call_count == 1,
                                "Fallback was not engaged")
                self.assertTrue(patch_put.call_args[0][1] == sas_url)

    def test_fallback_data(self):
        from azurelinuxagent.common.protocol.hostplugin import API_VERSION
        from azurelinuxagent.common.utils import restutil
        exp_method = 'PUT'
        exp_url = 'http://{0}:32526/status'.format(wireserver_url)
        exp_data = '{"content": "UmVhZHk=", "headers": [{"headerName": ' \
                   '"x-ms-version", "headerValue": "2014-02-14"}, ' \
                   '{"headerName": "x-ms-blob-type", "headerValue": null}], ' \
                   '"requestUri": "http://sas_url"}'
        with patch.object(restutil, "http_request") as patch_http:
            wire_protocol_client = wire.WireProtocol(wireserver_url).client
            plugin = wire_protocol_client.host_plugin
            blob = wire_protocol_client.status_blob
            blob.vm_status = restapi.VMStatus()
            blob.vm_status.vmAgent.status = 'Ready'
            with patch.object(plugin, "get_api_versions") as patch_api:
                patch_api.return_value = API_VERSION
                plugin.put_vm_status(blob, sas_url)
                self.assertTrue(patch_http.call_count == 1)
                self.assertTrue(patch_http.call_args[0][0] == exp_method)
                self.assertTrue(patch_http.call_args[0][1] == exp_url)
                self.assertTrue(patch_http.call_args[0][2] == exp_data)

    def test_no_fallback(self):
        with patch.object(wire.HostPluginProtocol,
                          "put_vm_status") as patch_put:
            with patch.object(wire.StatusBlob, "upload") as patch_upload:
                patch_upload.return_value = True
                wire_protocol_client = wire.WireProtocol(wireserver_url).client
                wire_protocol_client.ext_conf = wire.ExtensionsConfig(None)
                wire_protocol_client.ext_conf.status_upload_blob = sas_url
                wire_protocol_client.upload_status_blob()
                self.assertTrue(patch_put.call_count == 0,
                                "Fallback was engaged")

    def test_init_put(self):
        expected_url = "http://168.63.129.16:32526/status"
        expected_headers = {'x-ms-version': '2015-09-01'}
        expected_content = '{"content": "b2s=", ' \
                           '"headers": [{"headerName": "x-ms-version", ' \
                           '"headerValue": "2014-02-14"}, ' \
                           '{"headerName": "x-ms-blob-type", "headerValue": ' \
                           '"BlockBlob"}], ' \
                           '"requestUri": "http://sas_url"}'

        host_client = wire.HostPluginProtocol(wireserver_url)
        self.assertFalse(host_client.is_initialized)
        self.assertTrue(host_client.api_versions is None)
        status_blob = wire.StatusBlob(None)
        status_blob.vm_status = restapi.VMStatus()
        status_blob.vm_status.vmAgent.status = 'ok'
        status_blob.type = "BlockBlob"
        with patch.object(wire.HostPluginProtocol,
                          "get_api_versions") as patch_get:
            patch_get.return_value = api_versions
            with patch.object(restapi.restutil, "http_put") as patch_put:
                patch_put.return_value = MagicMock()
                host_client.put_vm_status(status_blob, sas_url)
                self.assertTrue(host_client.is_initialized)
                self.assertFalse(host_client.api_versions is None)
                self.assertTrue(patch_put.call_count == 1)
                self.assertTrue(patch_put.call_args[0][0] == expected_url)
                self.assertTrue(patch_put.call_args[0][1] == expected_content)
                self.assertTrue(patch_put.call_args[0][2] == expected_headers)


if __name__ == '__main__':
    unittest.main()
