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

from azurelinuxagent.common.protocol.wire import *
from tests.protocol.mockwiredata import *

data_with_bom = b'\xef\xbb\xbfhehe'
testurl = 'http://foo'
wireserver_url = '168.63.129.16'

@patch("time.sleep")
@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.protocol.wire.restutil")
class TestWireProtocolGetters(AgentTestCase):
    def _test_getters(self, test_data, mock_restutil, MockCryptUtil, _):
        mock_restutil.http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol(wireserver_url)
        protocol.detect()
        protocol.get_vminfo()
        protocol.get_certs()
        ext_handlers, etag = protocol.get_ext_handlers()
        for ext_handler in ext_handlers.extHandlers:
            protocol.get_ext_handler_pkgs(ext_handler)

        crt1 = os.path.join(self.tmp_dir,
                            '33B0ABCE4673538650971C10F7D7397E71561F35.crt')
        crt2 = os.path.join(self.tmp_dir,
                            '4037FBF5F1F3014F99B5D6C7799E9B20E6871CB3.crt')
        prv2 = os.path.join(self.tmp_dir,
                            '4037FBF5F1F3014F99B5D6C7799E9B20E6871CB3.prv')

        self.assertTrue(os.path.isfile(crt1))
        self.assertTrue(os.path.isfile(crt2))
        self.assertTrue(os.path.isfile(prv2))

    def test_getters(self, *args):
        """Normal case"""
        test_data = WireProtocolData(DATA_FILE)
        self._test_getters(test_data, *args)

    def test_getters_no_ext(self, *args):
        """Provision with agent is not checked"""
        test_data = WireProtocolData(DATA_FILE_NO_EXT)
        self._test_getters(test_data, *args)

    def test_getters_ext_no_settings(self, *args):
        """Extensions without any settings"""
        test_data = WireProtocolData(DATA_FILE_EXT_NO_SETTINGS)
        self._test_getters(test_data, *args)

    def test_getters_ext_no_public(self, *args):
        """Extensions without any public settings"""
        test_data = WireProtocolData(DATA_FILE_EXT_NO_PUBLIC)
        self._test_getters(test_data, *args)

    def test_call_storage_kwargs(self,
                                 mock_restutil,
                                 mock_cryptutil,
                                 mock_sleep):
        from azurelinuxagent.common.utils import restutil
        with patch.object(restutil, 'http_get') as http_patch:
            http_req = restutil.http_get
            url = testurl
            headers = {}

            # no kwargs
            WireClient.call_storage_service(http_req)
            # kwargs, no chk_proxy
            WireClient.call_storage_service(http_req,
                                            url,
                                            headers)
            # kwargs, chk_proxy False
            WireClient.call_storage_service(http_req,
                                            url,
                                            headers,
                                            chk_proxy=False)
            # kwargs, chk_proxy True
            WireClient.call_storage_service(http_req,
                                            url,
                                            headers,
                                            chk_proxy=True)
            # assert
            self.assertTrue(http_patch.call_count == 4)
            for c in http_patch.call_args_list:
                self.assertTrue(c[-1]['chk_proxy'] == True)

    def test_get_host_ga_plugin(self, *args):
        wire_protocol_client = WireProtocol(wireserver_url).client
        goal_state = GoalState(WireProtocolData(DATA_FILE).goal_state)

        with patch.object(WireClient, "get_goal_state", return_value = goal_state) as patch_get_goal_state:
            host_plugin = wire_protocol_client.get_host_plugin()
            self.assertEqual(goal_state, host_plugin.goal_state)
            patch_get_goal_state.assert_called_once()

    def test_upload_status_blob_default(self, *args):
        wire_protocol_client = WireProtocol(wireserver_url).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.status_upload_blob = testurl

        with patch.object(WireClient, "get_goal_state") as patch_get_goal_state:
            with patch.object(HostPluginProtocol, "put_vm_status") as patch_host_ga_plugin_upload:
                with patch.object(StatusBlob, "upload", return_value = True) as patch_default_upload:
                    wire_protocol_client.upload_status_blob()

                    patch_default_upload.assert_called_once_with(testurl)
                    patch_get_goal_state.assert_not_called()
                    patch_host_ga_plugin_upload.assert_not_called()

    def test_upload_status_blob_host_ga_plugin(self, *args):
        wire_protocol_client = WireProtocol(wireserver_url).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.status_upload_blob = testurl
        goal_state = GoalState(WireProtocolData(DATA_FILE).goal_state)

        with patch.object(HostPluginProtocol, "put_vm_status") as patch_host_ga_plugin_upload:
            with patch.object(StatusBlob, "upload", return_value=False) as patch_default_upload:
                wire_protocol_client.get_goal_state = Mock(return_value = goal_state)
                wire_protocol_client.upload_status_blob()

                patch_default_upload.assert_called_once_with(testurl)
                wire_protocol_client.get_goal_state.assert_called_once()
                patch_host_ga_plugin_upload.assert_called_once_with(wire_protocol_client.status_blob, testurl)

    def test_get_in_vm_artifacts_profile_blob_not_available(self, *args):
        wire_protocol_client = WireProtocol(wireserver_url).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)

        # Test when in_vm_artifacts_profile_blob is null/None
        self.assertEqual(None, wire_protocol_client.get_in_vm_artifacts_profile())

        #Test when in_vm_artifacts_profile_blob is whitespace
        wire_protocol_client.ext_conf.in_vm_artifacts_profile_blob = "  "
        self.assertEqual(None, wire_protocol_client.get_in_vm_artifacts_profile())

    def test_get_in_vm_artifacts_profile_response_body_not_valid(self, *args):
        wire_protocol_client = WireProtocol(wireserver_url).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.in_vm_artifacts_profile_blob = testurl
        goal_state = GoalState(WireProtocolData(DATA_FILE).goal_state)
        wire_protocol_client.get_goal_state = Mock(return_value=goal_state)

        with patch.object(HostPluginProtocol, "get_extension_artifact_url_and_headers",
                          return_value = ['dummy_url', {}]) as host_plugin_get_artifact_url_and_headers:
            #Test when response body is None
            wire_protocol_client.call_storage_service = Mock(return_value=MockResponse(None, 200))
            in_vm_artifacts_profile = wire_protocol_client.get_in_vm_artifacts_profile()
            self.assertTrue(in_vm_artifacts_profile is None)

            #Test when response body is None
            wire_protocol_client.call_storage_service = Mock(return_value=MockResponse('   '.encode('utf-8'), 200))
            in_vm_artifacts_profile = wire_protocol_client.get_in_vm_artifacts_profile()
            self.assertTrue(in_vm_artifacts_profile is None)

            #Test when response body is None
            wire_protocol_client.call_storage_service = Mock(return_value=MockResponse('{ }'.encode('utf-8'), 200))
            in_vm_artifacts_profile = wire_protocol_client.get_in_vm_artifacts_profile()
            self.assertEqual(dict(), in_vm_artifacts_profile.__dict__,
                             'If in_vm_artifacts_profile_blob has empty json dictionary, in_vm_artifacts_profile '
                             'should contain nothing')

            host_plugin_get_artifact_url_and_headers.assert_called_with(testurl)


    def test_get_in_vm_artifacts_profile_default(self, *args):
        wire_protocol_client = WireProtocol(wireserver_url).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.in_vm_artifacts_profile_blob = testurl
        goal_state = GoalState(WireProtocolData(DATA_FILE).goal_state)
        wire_protocol_client.get_goal_state = Mock(return_value=goal_state)

        wire_protocol_client.call_storage_service = Mock(return_value=MockResponse('{"onHold": "true"}'.encode('utf-8'), 200))
        in_vm_artifacts_profile = wire_protocol_client.get_in_vm_artifacts_profile()
        self.assertEqual(dict(onHold='true'), in_vm_artifacts_profile.__dict__)
        self.assertTrue(in_vm_artifacts_profile.is_extension_handlers_handling_on_hold())

    def test_get_in_vm_artifacts_profile_host_ga_plugin(self, *args):
        wire_protocol_client = WireProtocol(wireserver_url).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.in_vm_artifacts_profile_blob = testurl
        goal_state = GoalState(WireProtocolData(DATA_FILE).goal_state)
        wire_protocol_client.get_goal_state = Mock(return_value=goal_state)

        wire_protocol_client._get_in_vm_artifacts_profile = Mock(side_effect=[None, '{"onHold": "true"}'.encode('utf-8')])

        with patch.object(HostPluginProtocol, "get_extension_artifact_url_and_headers",
                          return_value = ['dummy_url', {}]) as host_plugin_get_artifact_url_and_headers:
            in_vm_artifacts_profile = wire_protocol_client.get_in_vm_artifacts_profile()
            self.assertEqual(dict(onHold='true'), in_vm_artifacts_profile.__dict__)
            self.assertTrue(in_vm_artifacts_profile.is_extension_handlers_handling_on_hold())
            host_plugin_get_artifact_url_and_headers.assert_called_once_with(testurl)


class MockResponse:
    def __init__(self, body, status_code):
        self.body = body
        self.status = status_code

    def read(self):
        return self.body

if __name__ == '__main__':
    unittest.main()
