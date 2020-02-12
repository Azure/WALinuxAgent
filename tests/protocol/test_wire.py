# -*- encoding: utf-8 -*-
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

import json
import os
import stat
import tempfile
import time
import uuid
import unittest
import zipfile

from azurelinuxagent.common.exception import InvalidContainerError, ResourceGoneError, ProtocolError, \
    ExtensionDownloadError
from azurelinuxagent.common.future import httpclient
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.protocol.wire import WireProtocol, WireClient, GoalState, ExtensionsConfig, \
    InVMArtifactsProfile, VMAgentManifestUri, StatusBlob, VMStatus, INCARNATION_FILE_NAME, ExtHandlerVersionUri, \
    DataContractList, socket
from azurelinuxagent.common.telemetryevent import TelemetryEvent, TelemetryEventParam, TelemetryEventList
from azurelinuxagent.common.utils import fileutil, restutil
from azurelinuxagent.common.utils.shellutil import run_get_output
from azurelinuxagent.common.version import CURRENT_VERSION, DISTRO_NAME, DISTRO_VERSION
from tests.ga.test_monitor import random_generator
from tests.protocol import mockwiredata
from tests.protocol.mockwiredata import WireProtocolData
from tests.tools import ANY, MagicMock, Mock, patch, AgentTestCase, skip_if_predicate_true, running_under_travis

data_with_bom = b'\xef\xbb\xbfhehe'
testurl = 'http://foo'
testtype = 'BlockBlob'
WIRESERVER_URL = '168.63.129.16'


def get_event(message, duration=30000, evt_type="", is_internal=False, is_success=True,
              name="", op="Unknown", version=CURRENT_VERSION, eventId=1):
    event = TelemetryEvent(eventId, "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
    event.parameters.append(TelemetryEventParam('Name', name))
    event.parameters.append(TelemetryEventParam('Version', str(version)))
    event.parameters.append(TelemetryEventParam('IsInternal', is_internal))
    event.parameters.append(TelemetryEventParam('Operation', op))
    event.parameters.append(TelemetryEventParam('OperationSuccess', is_success))
    event.parameters.append(TelemetryEventParam('Message', message))
    event.parameters.append(TelemetryEventParam('Duration', duration))
    event.parameters.append(TelemetryEventParam('ExtensionType', evt_type))
    return event


@patch("time.sleep")
@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.protocol.healthservice.HealthService._report")
class TestWireProtocol(AgentTestCase):

    def setUp(self):
        super(TestWireProtocol, self).setUp()
        HostPluginProtocol.set_default_channel(False)

    def _test_getters(self, test_data, certsMustBePresent, __, MockCryptUtil, _):
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        with patch.object(restutil, 'http_get', test_data.mock_http_get):
            protocol = WireProtocol(WIRESERVER_URL)
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
            if certsMustBePresent:
                self.assertTrue(os.path.isfile(crt1))
                self.assertTrue(os.path.isfile(crt2))
                self.assertTrue(os.path.isfile(prv2))
            else:
                self.assertFalse(os.path.isfile(crt1))
                self.assertFalse(os.path.isfile(crt2))
                self.assertFalse(os.path.isfile(prv2))
            self.assertEqual("1", protocol.get_incarnation())

    def test_getters(self, *args):
        """Normal case"""
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        self._test_getters(test_data, True, *args)

    def test_getters_no_ext(self, *args):
        """Provision with agent is not checked"""
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_NO_EXT)
        self._test_getters(test_data, True, *args)

    def test_getters_ext_no_settings(self, *args):
        """Extensions without any settings"""
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_NO_SETTINGS)
        self._test_getters(test_data, True, *args)

    def test_getters_ext_no_public(self, *args):
        """Extensions without any public settings"""
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_EXT_NO_PUBLIC)
        self._test_getters(test_data, True, *args)

    def test_getters_ext_no_cert_format(self, *args):
        """Certificate format not specified"""
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_NO_CERT_FORMAT)
        self._test_getters(test_data, True, *args)

    def test_getters_ext_cert_format_not_pfx(self, *args):
        """Certificate format is not Pkcs7BlobWithPfxContents specified"""
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE_CERT_FORMAT_NOT_PFX)
        self._test_getters(test_data, False, *args)

    @patch("azurelinuxagent.common.protocol.healthservice.HealthService.report_host_plugin_extension_artifact")
    def test_getters_with_stale_goal_state(self, patch_report, *args):
        test_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        test_data.emulate_stale_goal_state = True

        self._test_getters(test_data, True, *args)
        # Ensure HostPlugin was invoked
        self.assertEqual(1, test_data.call_counts["/versions"])
        self.assertEqual(2, test_data.call_counts["extensionArtifact"])
        # Ensure the expected number of HTTP calls were made
        # -- Tracking calls to retrieve GoalState is problematic since it is
        #    fetched often; however, the dependent documents, such as the
        #    HostingEnvironmentConfig, will be retrieved the expected number
        self.assertEqual(1, test_data.call_counts["hostingenvuri"])
        self.assertEqual(1, patch_report.call_count)

    def test_call_storage_kwargs(self, *args):
        from azurelinuxagent.common.utils import restutil
        with patch.object(restutil, 'http_get') as http_patch:
            http_req = restutil.http_get
            url = testurl
            headers = {}

            # no kwargs -- Default to True
            WireClient.call_storage_service(http_req)

            # kwargs, no use_proxy -- Default to True
            WireClient.call_storage_service(http_req,
                                            url,
                                            headers)

            # kwargs, use_proxy None -- Default to True
            WireClient.call_storage_service(http_req,
                                            url,
                                            headers,
                                            use_proxy=None)

            # kwargs, use_proxy False -- Keep False
            WireClient.call_storage_service(http_req,
                                            url,
                                            headers,
                                            use_proxy=False)

            # kwargs, use_proxy True -- Keep True
            WireClient.call_storage_service(http_req,
                                            url,
                                            headers,
                                            use_proxy=True)
            # assert
            self.assertTrue(http_patch.call_count == 5)
            for i in range(0, 5):
                c = http_patch.call_args_list[i][-1]['use_proxy']
                self.assertTrue(c == (True if i != 3 else False))

    def test_status_blob_parsing(self, *args):
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.ext_conf = ExtensionsConfig(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).ext_conf)
        self.assertEqual(wire_protocol_client.ext_conf.status_upload_blob,
                         'https://test.blob.core.windows.net/vhds/test-cs12.test-cs12.test-cs12.status?'
                         'sr=b&sp=rw&se=9999-01-01&sk=key1&sv=2014-02-14&'
                         'sig=hfRh7gzUE7sUtYwke78IOlZOrTRCYvkec4hGZ9zZzXo')
        self.assertEqual(wire_protocol_client.ext_conf.status_upload_blob_type,
                         u'BlockBlob')
        pass

    def test_get_host_ga_plugin(self, *args):
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        goal_state = GoalState(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state)

        with patch.object(WireClient, "get_goal_state", return_value=goal_state) as patch_get_goal_state:
            host_plugin = wire_protocol_client.get_host_plugin()
            self.assertEqual(goal_state.container_id, host_plugin.container_id)
            self.assertEqual(goal_state.role_config_name, host_plugin.role_config_name)
            self.assertEqual(1, patch_get_goal_state.call_count)

    @patch("azurelinuxagent.common.utils.restutil.http_request", side_effect=IOError)
    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_host_plugin")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_download_ext_handler_pkg_fallback(self, patch_request, patch_get_host, patch_http, *args):
        ext_uri = 'extension_uri'
        host_uri = 'host_uri'
        destination = 'destination'
        patch_get_host.return_value = HostPluginProtocol(host_uri, 'container_id', 'role_config')
        patch_request.return_value = [host_uri, {}]

        WireProtocol(WIRESERVER_URL).download_ext_handler_pkg(ext_uri, destination)

        self.assertEqual(patch_http.call_count, 2)
        self.assertEqual(patch_request.call_count, 1)
        self.assertEqual(patch_http.call_args_list[0][0][1], ext_uri)
        self.assertEqual(patch_http.call_args_list[1][0][1], host_uri)

    @skip_if_predicate_true(running_under_travis, "Travis unit tests should not have external dependencies")
    def test_download_ext_handler_pkg_stream(self, *args):
        ext_uri = 'https://dcrdata.blob.core.windows.net/files/packer.zip'
        tmp = tempfile.mkdtemp()
        destination = os.path.join(tmp, 'test_download_ext_handler_pkg_stream.zip')

        success = WireProtocol(WIRESERVER_URL).download_ext_handler_pkg(ext_uri, destination)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(destination))

        # verify size
        self.assertEqual(33193077, os.stat(destination).st_size)

        # verify unzip
        zipfile.ZipFile(destination).extractall(tmp)
        packer = os.path.join(tmp, 'packer')
        self.assertTrue(os.path.exists(packer))
        fileutil.chmod(packer, os.stat(packer).st_mode | stat.S_IXUSR)

        # verify unpacked size
        self.assertEqual(105552030, os.stat(packer).st_size)

        # execute, verify result
        packer_version = '{0} --version'.format(packer)
        rc, stdout = run_get_output(packer_version)
        self.assertEqual(0, rc)
        self.assertEqual('1.3.5\n', stdout)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state")
    def test_upload_status_blob_default(self, *args):
        """
        Default status blob method is HostPlugin.
        """
        vmstatus = VMStatus(message="Ready", status="Ready")
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.status_upload_blob = testurl
        wire_protocol_client.ext_conf.status_upload_blob_type = testtype
        wire_protocol_client.status_blob.vm_status = vmstatus

        with patch.object(WireClient, "get_goal_state") as patch_get_goal_state:
            with patch.object(HostPluginProtocol, "put_vm_status") as patch_host_ga_plugin_upload:
                with patch.object(StatusBlob, "upload") as patch_default_upload:
                    HostPluginProtocol.set_default_channel(False)
                    wire_protocol_client.upload_status_blob()

                    # do not call the direct method unless host plugin fails
                    patch_default_upload.assert_not_called()
                    # host plugin always fetches a goal state
                    patch_get_goal_state.assert_called_once_with()
                    # host plugin uploads the status blob
                    patch_host_ga_plugin_upload.assert_called_once_with(ANY, testurl, 'BlockBlob')

    @patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state")
    def test_upload_status_blob_host_ga_plugin(self, *args):
        vmstatus = VMStatus(message="Ready", status="Ready")
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.status_upload_blob = testurl
        wire_protocol_client.ext_conf.status_upload_blob_type = testtype
        wire_protocol_client.status_blob.vm_status = vmstatus
        goal_state = GoalState(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state)

        with patch.object(HostPluginProtocol,
                          "ensure_initialized",
                          return_value=True):
            with patch.object(StatusBlob,
                              "upload",
                              return_value=False) as patch_default_upload:
                with patch.object(HostPluginProtocol,
                                  "_put_block_blob_status") as patch_http:
                    HostPluginProtocol.set_default_channel(False)
                    wire_protocol_client.get_goal_state = Mock(return_value=goal_state)
                    wire_protocol_client.upload_status_blob()
                    patch_default_upload.assert_not_called()
                    self.assertEqual(1, wire_protocol_client.get_goal_state.call_count)
                    patch_http.assert_called_once_with(testurl, wire_protocol_client.status_blob)
                    self.assertFalse(HostPluginProtocol.is_default_channel())

    @patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.ensure_initialized")
    def test_upload_status_blob_unknown_type_assumes_block(self, _, __, *args):
        vmstatus = VMStatus(message="Ready", status="Ready")
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.status_upload_blob = testurl
        wire_protocol_client.ext_conf.status_upload_blob_type = "NotALegalType"
        wire_protocol_client.status_blob.vm_status = vmstatus

        with patch.object(WireClient, "get_goal_state") as patch_get_goal_state:
            with patch.object(StatusBlob, "prepare") as patch_prepare:
                with patch.object(StatusBlob, "upload") as patch_default_upload:
                    HostPluginProtocol.set_default_channel(False)
                    wire_protocol_client.upload_status_blob()

                    patch_prepare.assert_called_once_with("BlockBlob")
                    patch_default_upload.assert_called_once_with(testurl)
                    patch_get_goal_state.assert_called_once_with()

    @patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state")
    def test_upload_status_blob_reports_prepare_error(self, *args):
        vmstatus = VMStatus(message="Ready", status="Ready")
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.status_upload_blob = testurl
        wire_protocol_client.ext_conf.status_upload_blob_type = testtype
        wire_protocol_client.status_blob.vm_status = vmstatus
        goal_state = GoalState(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state)

        with patch.object(StatusBlob, "prepare", side_effect=Exception) as mock_prepare:
            self.assertRaises(ProtocolError, wire_protocol_client.upload_status_blob)
            self.assertEqual(1, mock_prepare.call_count)

    def test_get_in_vm_artifacts_profile_blob_not_available(self, *args):
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)

        # Test when artifacts_profile_blob is null/None
        self.assertEqual(None, wire_protocol_client.get_artifacts_profile())

        # Test when artifacts_profile_blob is whitespace
        wire_protocol_client.ext_conf.artifacts_profile_blob = "  "
        self.assertEqual(None, wire_protocol_client.get_artifacts_profile())

    def test_get_in_vm_artifacts_profile_response_body_not_valid(self, *args):
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.artifacts_profile_blob = testurl
        goal_state = GoalState(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state)
        wire_protocol_client.get_goal_state = Mock(return_value=goal_state)

        with patch.object(HostPluginProtocol, "get_artifact_request",
                          return_value=['dummy_url', {}]) as host_plugin_get_artifact_url_and_headers:
            # Test when response body is None
            wire_protocol_client.call_storage_service = Mock(return_value=MockResponse(None, 200))
            in_vm_artifacts_profile = wire_protocol_client.get_artifacts_profile()
            self.assertTrue(in_vm_artifacts_profile is None)

            # Test when response body is None
            wire_protocol_client.call_storage_service = Mock(return_value=MockResponse('   '.encode('utf-8'), 200))
            in_vm_artifacts_profile = wire_protocol_client.get_artifacts_profile()
            self.assertTrue(in_vm_artifacts_profile is None)

            # Test when response body is None
            wire_protocol_client.call_storage_service = Mock(return_value=MockResponse('{ }'.encode('utf-8'), 200))
            in_vm_artifacts_profile = wire_protocol_client.get_artifacts_profile()
            self.assertEqual(dict(), in_vm_artifacts_profile.__dict__,
                             'If artifacts_profile_blob has empty json dictionary, in_vm_artifacts_profile '
                             'should contain nothing')

            host_plugin_get_artifact_url_and_headers.assert_called_with(testurl)

    @patch("azurelinuxagent.common.event.add_event")
    def test_artifacts_profile_json_parsing(self, patch_event, *args):
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.artifacts_profile_blob = testurl
        goal_state = GoalState(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state)
        wire_protocol_client.get_goal_state = Mock(return_value=goal_state)

        # response is invalid json
        wire_protocol_client.call_storage_service = Mock(return_value=MockResponse("invalid json".encode('utf-8'), 200))
        in_vm_artifacts_profile = wire_protocol_client.get_artifacts_profile()

        # ensure response is empty
        self.assertEqual(None, in_vm_artifacts_profile)

        # ensure event is logged
        self.assertEqual(1, patch_event.call_count)
        self.assertFalse(patch_event.call_args[1]['is_success'])
        self.assertTrue('invalid json' in patch_event.call_args[1]['message'])
        self.assertEqual('ArtifactsProfileBlob', patch_event.call_args[1]['op'])

    def test_get_in_vm_artifacts_profile_default(self, *args):
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.artifacts_profile_blob = testurl
        goal_state = GoalState(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state)
        wire_protocol_client.get_goal_state = Mock(return_value=goal_state)

        wire_protocol_client.call_storage_service = Mock(
            return_value=MockResponse('{"onHold": "true"}'.encode('utf-8'), 200))
        in_vm_artifacts_profile = wire_protocol_client.get_artifacts_profile()
        self.assertEqual(dict(onHold='true'), in_vm_artifacts_profile.__dict__)
        self.assertTrue(in_vm_artifacts_profile.is_on_hold())

    def test_fetch_manifest_fallback(self, *args):
        uri1 = ExtHandlerVersionUri()
        uri1.uri = 'ext_uri'
        uris = DataContractList(ExtHandlerVersionUri)
        uris.append(uri1)
        host_uri = 'host_uri'
        mock_host = HostPluginProtocol(host_uri,
                                       'container_id',
                                       'role_config')
        client = WireProtocol(WIRESERVER_URL).client

        with patch.object(WireClient, "fetch", return_value=None) as patch_fetch:
            with patch.object(WireClient, "get_host_plugin", return_value=mock_host):
                with patch.object(HostPluginProtocol, "get_artifact_request", return_value=[host_uri, {}]):
                    HostPluginProtocol.set_default_channel(False)
                    self.assertRaises(ExtensionDownloadError, client.fetch_manifest, uris)
                    self.assertEqual(patch_fetch.call_count, 2)
                    self.assertEqual(patch_fetch.call_args_list[0][0][0], uri1.uri)
                    self.assertEqual(patch_fetch.call_args_list[1][0][0], host_uri)

    # This test checks if the manifest_uri variable is set in the host object of WireClient
    # This variable is used when we make /extensionArtifact API calls to the HostGA
    def test_fetch_manifest_ensure_manifest_uri_is_set(self, *args):
        uri1 = ExtHandlerVersionUri()
        uri1.uri = 'ext_uri'
        uris = DataContractList(ExtHandlerVersionUri)
        uris.append(uri1)
        host_uri = 'host_uri'
        mock_host = HostPluginProtocol(host_uri, 'container_id', 'role_config')
        client = WireProtocol(WIRESERVER_URL).client
        manifest_return = "manifest.xml"

        with patch.object(WireClient, "get_host_plugin", return_value=mock_host):
            mock_host.get_artifact_request = MagicMock(return_value=[host_uri, {}])

            # First test tried to download directly from blob and asserts manifest_uri is set
            with patch.object(WireClient, "fetch", return_value=manifest_return) as patch_fetch:
                fetch_manifest_mock = client.fetch_manifest(uris)
                self.assertEqual(fetch_manifest_mock, manifest_return)
                self.assertEqual(patch_fetch.call_count, 1)
                self.assertEqual(mock_host.manifest_uri, uri1.uri)

            # Second test tries to download from the HostGA (by failing the direct download)
            # and asserts manifest_uri is set
            with patch.object(WireClient, "fetch") as patch_fetch:
                patch_fetch.side_effect = [None, manifest_return]
                fetch_manifest_mock = client.fetch_manifest(uris)
                self.assertEqual(fetch_manifest_mock, manifest_return)
                self.assertEqual(patch_fetch.call_count, 2)
                self.assertEqual(mock_host.manifest_uri, uri1.uri)
                self.assertTrue(HostPluginProtocol.is_default_channel())

    def test_get_in_vm_artifacts_profile_host_ga_plugin(self, *args):
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.ext_conf = ExtensionsConfig(None)
        wire_protocol_client.ext_conf.artifacts_profile_blob = testurl
        goal_state = GoalState(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state)
        wire_protocol_client.get_goal_state = Mock(return_value=goal_state)
        wire_protocol_client.fetch = Mock(side_effect=[None, '{"onHold": "true"}'])
        with patch.object(HostPluginProtocol,
                          "get_artifact_request",
                          return_value=['dummy_url', {}]) as artifact_request:
            in_vm_artifacts_profile = wire_protocol_client.get_artifacts_profile()
            self.assertTrue(in_vm_artifacts_profile is not None)
            self.assertEqual(dict(onHold='true'), in_vm_artifacts_profile.__dict__)
            self.assertTrue(in_vm_artifacts_profile.is_on_hold())
            artifact_request.assert_called_once_with(testurl)

    @patch("socket.gethostname", return_value="hostname")
    @patch("time.gmtime", return_value=time.localtime(1485543256))
    def test_report_vm_status(self, *args):
        status = 'status'
        message = 'message'

        client = WireProtocol(WIRESERVER_URL).client
        actual = StatusBlob(client=client)
        actual.set_vm_status(VMStatus(status=status, message=message))
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        formatted_msg = {
            'lang': 'en-US',
            'message': message
        }
        v1_ga_status = {
            'version': str(CURRENT_VERSION),
            'status': status,
            'formattedMessage': formatted_msg
        }
        v1_ga_guest_info = {
            'computerName': socket.gethostname(),
            'osName': DISTRO_NAME,
            'osVersion': DISTRO_VERSION,
            'version': str(CURRENT_VERSION),
        }
        v1_agg_status = {
            'guestAgentStatus': v1_ga_status,
            'handlerAggregateStatus': []
        }
        v1_vm_status = {
            'version': '1.1',
            'timestampUTC': timestamp,
            'aggregateStatus': v1_agg_status,
            'guestOSInfo': v1_ga_guest_info
        }
        self.assertEqual(json.dumps(v1_vm_status), actual.to_json())

    @patch("azurelinuxagent.common.utils.restutil.http_request")
    def test_send_event(self, mock_http_request, *args):
        mock_http_request.return_value = MockResponse("", 200)

        event_str = u'a test string'
        client = WireProtocol(WIRESERVER_URL).client
        client.send_event("foo", event_str)

        first_call = mock_http_request.call_args_list[0]
        args, kwargs = first_call
        method, url, body_received = args
        headers = kwargs['headers']

        # the headers should include utf-8 encoding...
        self.assertTrue("utf-8" in headers['Content-Type'])
        # the body is not encoded, just check for equality
        self.assertIn(event_str, body_received)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    def test_report_event_small_event(self, patch_send_event, *args):
        event_list = TelemetryEventList()
        client = WireProtocol(WIRESERVER_URL).client

        event_str = random_generator(10)
        event_list.events.append(get_event(message=event_str))

        event_str = random_generator(100)
        event_list.events.append(get_event(message=event_str))

        event_str = random_generator(1000)
        event_list.events.append(get_event(message=event_str))

        event_str = random_generator(10000)
        event_list.events.append(get_event(message=event_str))

        client.report_event(event_list)

        # It merges the messages into one message
        self.assertEqual(patch_send_event.call_count, 1)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    def test_report_event_multiple_events_to_fill_buffer(self, patch_send_event, *args):
        event_list = TelemetryEventList()
        client = WireProtocol(WIRESERVER_URL).client

        event_str = random_generator(2 ** 15)
        event_list.events.append(get_event(message=event_str))
        event_list.events.append(get_event(message=event_str))

        client.report_event(event_list)

        # It merges the messages into one message
        self.assertEqual(patch_send_event.call_count, 2)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_event")
    def test_report_event_large_event(self, patch_send_event, *args):
        event_list = TelemetryEventList()
        event_str = random_generator(2 ** 18)
        event_list.events.append(get_event(message=event_str))
        client = WireProtocol(WIRESERVER_URL).client
        client.report_event(event_list)

        self.assertEqual(patch_send_event.call_count, 0)


class TestWireClient(AgentTestCase):

    def test_get_ext_conf_without_uri(self, *args):
        test_goal_state = GoalState(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state)
        test_goal_state.ext_uri = None
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.get_goal_state = Mock(return_value=test_goal_state)

        with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch_cache",
                   return_value=mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).ext_conf):
            ext_conf = wire_protocol_client.get_ext_conf()

        self.assertEqual(0, len(ext_conf.ext_handlers.extHandlers))
        self.assertEqual(0, len(ext_conf.vmagent_manifests.vmAgentManifests))
        self.assertIsNone(ext_conf.status_upload_blob)
        self.assertIsNone(ext_conf.status_upload_blob_type)
        self.assertIsNone(ext_conf.artifacts_profile_blob)

    def test_get_ext_conf_with_uri(self, *args):
        test_goal_state = GoalState(mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state)
        wire_protocol_client = WireProtocol(WIRESERVER_URL).client
        wire_protocol_client.get_goal_state = Mock(return_value=test_goal_state)

        with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch_cache",
                   return_value=mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).ext_conf):
            ext_conf = wire_protocol_client.get_ext_conf()

        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertEqual(2, len(ext_conf.vmagent_manifests.vmAgentManifests))
        self.assertEqual("https://test.blob.core.windows.net/vhds/test-cs12.test-cs12.test-cs12.status?"
                         "sr=b&sp=rw&se=9999-01-01&sk=key1&sv=2014-02-14&sig=hfRh7gzUE7sUtYwke78IOlZOrTRCYvkec4hGZ9zZzXo", ext_conf.status_upload_blob)
        self.assertEqual("BlockBlob", ext_conf.status_upload_blob_type)
        self.assertEqual(None, ext_conf.artifacts_profile_blob)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_download_ext_handler_pkg_should_not_invoke_host_channel_when_direct_channel_succeeds(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        protocol = WireProtocol("foo.bar")
        HostPluginProtocol.set_default_channel(False)

        mock_successful_response = MockResponse(body=b"OK", status_code=200)
        destination = os.path.join(self.tmp_dir, "tmp_file")

        # Direct channel succeeds
        with patch("azurelinuxagent.common.utils.restutil._http_request", return_value=mock_successful_response):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state") as mock_update_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.stream", wraps=protocol.client.stream) \
                        as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireProtocol.download_ext_handler_pkg_through_host",
                               wraps=protocol.download_ext_handler_pkg_through_host) as patch_host:
                        ret = protocol.download_ext_handler_pkg("uri", destination)
                        self.assertEquals(ret, True)

                        self.assertEquals(patch_host.call_count, 0)
                        self.assertEquals(patch_direct.call_count, 1)
                        self.assertEquals(mock_update_goal_state.call_count, 0)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), False)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_download_ext_handler_pkg_should_use_host_channel_when_direct_channel_fails(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        protocol = WireProtocol("foo.bar")
        HostPluginProtocol.set_default_channel(False)

        mock_failed_response = MockResponse(body=b"", status_code=httpclient.GONE)
        mock_successful_response = MockResponse(body=b"OK", status_code=200)
        destination = os.path.join(self.tmp_dir, "tmp_file")

        # Direct channel fails, host channel succeeds. Goal state should not have been updated and host channel
        # should have been set as default.
        with patch("azurelinuxagent.common.utils.restutil._http_request",
                   side_effect=[mock_failed_response, mock_successful_response]):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state") as mock_update_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.stream", wraps=protocol.client.stream) \
                        as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireProtocol.download_ext_handler_pkg_through_host",
                               wraps=protocol.download_ext_handler_pkg_through_host) as patch_host:
                        ret = protocol.download_ext_handler_pkg("uri", destination)
                        self.assertEquals(ret, True)

                        self.assertEquals(patch_host.call_count, 1)
                        # The host channel calls the direct function under the covers
                        self.assertEquals(patch_direct.call_count, 1 + patch_host.call_count)
                        self.assertEquals(mock_update_goal_state.call_count, 0)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), True)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_download_ext_handler_pkg_should_retry_the_host_channel_after_refreshing_host_plugin(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        protocol = WireProtocol("foo.bar")
        HostPluginProtocol.set_default_channel(False)

        mock_failed_response = MockResponse(body=b"", status_code=httpclient.GONE)
        mock_successful_response = MockResponse(body=b"OK", status_code=200)
        destination = os.path.join(self.tmp_dir, "tmp_file")

        # Direct channel fails, host channel fails due to stale goal state, host channel succeeds after refresh.
        # As a consequence, goal state should have been updated and host channel should have been set as default.
        with patch("azurelinuxagent.common.utils.restutil._http_request",
                   side_effect=[mock_failed_response, mock_failed_response, mock_successful_response]):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_host_plugin_from_goal_state") as mock_update_host_plugin_from_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.stream", wraps=protocol.client.stream) \
                        as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireProtocol.download_ext_handler_pkg_through_host",
                               wraps=protocol.download_ext_handler_pkg_through_host) as patch_host:
                        ret = protocol.download_ext_handler_pkg("uri", destination)
                        self.assertEquals(ret, True)

                        self.assertEquals(patch_host.call_count, 2)
                        # The host channel calls the direct function under the covers
                        self.assertEquals(patch_direct.call_count, 1 + patch_host.call_count)
                        self.assertEquals(mock_update_host_plugin_from_goal_state.call_count, 1)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), True)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_download_ext_handler_pkg_should_not_change_default_channel_if_host_fails(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        protocol = WireProtocol("foo.bar")
        HostPluginProtocol.set_default_channel(False)

        mock_failed_response = MockResponse(body=b"", status_code=httpclient.GONE)
        destination = os.path.join(self.tmp_dir, "tmp_file")

        # Everything fails. Goal state should have been updated and host channel should not have been set as default.
        with patch("azurelinuxagent.common.utils.restutil._http_request", return_value=mock_failed_response):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_host_plugin_from_goal_state") as mock_update_host_plugin_from_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.stream", wraps=protocol.client.stream) \
                        as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireProtocol.download_ext_handler_pkg_through_host",
                               wraps=protocol.download_ext_handler_pkg_through_host) as patch_host:
                        ret = protocol.download_ext_handler_pkg("uri", destination)
                        self.assertEquals(ret, False)

                        self.assertEquals(patch_host.call_count, 2)
                        # The host channel calls the direct function under the covers
                        self.assertEquals(patch_direct.call_count, 1 + patch_host.call_count)
                        self.assertEquals(mock_update_host_plugin_from_goal_state.call_count, 1)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), False)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_fetch_manifest_should_not_invoke_host_channel_when_direct_channel_succeeds(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        client = WireClient("foo.bar")

        HostPluginProtocol.set_default_channel(False)
        mock_successful_response = MockResponse(body=b"OK", status_code=200)

        # Direct channel succeeds
        with patch("azurelinuxagent.common.utils.restutil._http_request", return_value=mock_successful_response):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state") as mock_update_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch", wraps=client.fetch) as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch_manifest_through_host",
                               wraps=client.fetch_manifest_through_host) as patch_host:
                        ret = client.fetch_manifest([VMAgentManifestUri(uri="uri1")])
                        self.assertEquals(ret, "OK")

                        self.assertEquals(patch_host.call_count, 0)
                        # The host channel calls the direct function under the covers
                        self.assertEquals(patch_direct.call_count, 1)
                        self.assertEquals(mock_update_goal_state.call_count, 0)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), False)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_fetch_manifest_should_use_host_channel_when_direct_channel_fails(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        client = WireClient("foo.bar")

        HostPluginProtocol.set_default_channel(False)

        mock_failed_response = MockResponse(body=b"", status_code=httpclient.GONE)
        mock_successful_response = MockResponse(body=b"OK", status_code=200)

        # Direct channel fails, host channel succeeds. Goal state should not have been updated and host channel
        # should have been set as default
        with patch("azurelinuxagent.common.utils.restutil._http_request",
                   side_effect=[mock_failed_response, mock_successful_response]):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state") as mock_update_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch", wraps=client.fetch) as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch_manifest_through_host",
                               wraps=client.fetch_manifest_through_host) as patch_host:
                        ret = client.fetch_manifest([VMAgentManifestUri(uri="uri1")])
                        self.assertEquals(ret, "OK")

                        self.assertEquals(patch_host.call_count, 1)
                        # The host channel calls the direct function under the covers
                        self.assertEquals(patch_direct.call_count, 1 + patch_host.call_count)
                        self.assertEquals(mock_update_goal_state.call_count, 0)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), True)

        # Reset default channel
        HostPluginProtocol.set_default_channel(False)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_fetch_manifest_should_retry_the_host_channel_after_refreshing_the_host_plugin(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        client = WireClient("foo.bar")

        HostPluginProtocol.set_default_channel(False)

        mock_failed_response = MockResponse(body=b"", status_code=httpclient.GONE)
        mock_successful_response = MockResponse(body=b"OK", status_code=200)

        # Direct channel fails, host channel fails due to stale goal state, host channel succeeds after refresh.
        # As a consequence, goal state should have been updated and host channel should have been set as default.
        with patch("azurelinuxagent.common.utils.restutil._http_request",
                   side_effect=[mock_failed_response, mock_failed_response, mock_successful_response]):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_host_plugin_from_goal_state") as mock_update_host_plugin_from_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch", wraps=client.fetch) as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch_manifest_through_host",
                               wraps=client.fetch_manifest_through_host) as patch_host:
                        ret = client.fetch_manifest([VMAgentManifestUri(uri="uri1")])
                        self.assertEquals(ret, "OK")

                        self.assertEquals(patch_host.call_count, 2)
                        # The host channel calls the direct function under the covers
                        self.assertEquals(patch_direct.call_count, 1 + patch_host.call_count)
                        self.assertEquals(mock_update_host_plugin_from_goal_state.call_count, 1)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), True)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_fetch_manifest_should_update_goal_state_and_not_change_default_channel_if_host_fails(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        client = WireClient("foo.bar")

        HostPluginProtocol.set_default_channel(False)
        mock_failed_response = MockResponse(body=b"", status_code=httpclient.GONE)

        # Everything fails. Goal state should have been updated and host channel should not have been set as default.
        with patch("azurelinuxagent.common.utils.restutil._http_request", return_value=mock_failed_response):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state") as mock_update_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch", wraps=client.fetch) as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch_manifest_through_host",
                               wraps=client.fetch_manifest_through_host) as patch_host:
                        with self.assertRaises(ExtensionDownloadError):
                            client.fetch_manifest([VMAgentManifestUri(uri="uri1")])

                            self.assertEquals(patch_host.call_count, 2)
                            # The host channel calls the direct function under the covers
                            self.assertEquals(patch_direct.call_count, 1 + patch_host.call_count)
                            self.assertEquals(mock_update_goal_state.call_count, 1)

                            self.assertEquals(HostPluginProtocol.is_default_channel(), False)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_get_artifacts_profile_should_not_invoke_host_channel_when_direct_channel_succeeds(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        client = WireClient("foo.bar")
        client.ext_conf = ExtensionsConfig(None)
        client.ext_conf.artifacts_profile_blob = "testurl"
        json_profile = b'{ "onHold": true }'

        HostPluginProtocol.set_default_channel(False)
        mock_successful_response = MockResponse(body=json_profile, status_code=200)

        # Direct channel succeeds
        with patch("azurelinuxagent.common.utils.restutil._http_request", return_value=mock_successful_response):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state") as mock_update_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch", wraps=client.fetch) as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireClient.get_artifacts_profile_through_host",
                               wraps=client.get_artifacts_profile_through_host) as patch_host:
                        ret = client.get_artifacts_profile()
                        self.assertIsInstance(ret, InVMArtifactsProfile)

                        self.assertEquals(patch_host.call_count, 0)
                        self.assertEquals(patch_direct.call_count, 1)
                        self.assertEquals(mock_update_goal_state.call_count, 0)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), False)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_get_artifacts_profile_should_use_host_channel_when_direct_channel_fails(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        client = WireClient("foo.bar")
        client.ext_conf = ExtensionsConfig(None)
        client.ext_conf.artifacts_profile_blob = "testurl"
        json_profile = b'{ "onHold": true }'

        HostPluginProtocol.set_default_channel(False)

        mock_failed_response = MockResponse(body=b"", status_code=httpclient.GONE)
        mock_successful_response = MockResponse(body=json_profile, status_code=200)

        # Direct channel fails, host channel succeeds. Goal state should not have been updated and host channel
        # should have been set as default
        with patch("azurelinuxagent.common.utils.restutil._http_request",
                   side_effect=[mock_failed_response, mock_successful_response]):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_goal_state") as mock_update_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch", wraps=client.fetch) as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireClient.get_artifacts_profile_through_host",
                               wraps=client.get_artifacts_profile_through_host) as patch_host:
                        ret = client.get_artifacts_profile()
                        self.assertIsInstance(ret, InVMArtifactsProfile)

                        self.assertEquals(patch_host.call_count, 1)
                        # The host channel calls the direct function under the covers
                        self.assertEquals(patch_direct.call_count, 1 + patch_host.call_count)
                        self.assertEquals(mock_update_goal_state.call_count, 0)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), True)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_get_artifacts_profile_should_retry_the_host_channel_after_refreshing_the_host_plugin(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        client = WireClient("foo.bar")
        client.ext_conf = ExtensionsConfig(None)
        client.ext_conf.artifacts_profile_blob = "testurl"
        json_profile = b'{ "onHold": true }'

        HostPluginProtocol.set_default_channel(False)

        mock_failed_response = MockResponse(body=b"", status_code=httpclient.GONE)
        mock_successful_response = MockResponse(body=json_profile, status_code=200)

        # Direct channel fails, host channel fails due to stale goal state, host channel succeeds after refresh.
        # As a consequence, host plugin should have been updated and host channel should have been set as default.
        with patch("azurelinuxagent.common.utils.restutil._http_request",
                   side_effect=[mock_failed_response, mock_failed_response, mock_successful_response]):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_host_plugin_from_goal_state") as mock_update_host_plugin_from_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch", wraps=client.fetch) as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireClient.get_artifacts_profile_through_host",
                               wraps=client.get_artifacts_profile_through_host) as patch_host:
                        ret = client.get_artifacts_profile()
                        self.assertIsInstance(ret, InVMArtifactsProfile)

                        self.assertEquals(patch_host.call_count, 2)
                        # The host channel calls the direct function under the covers
                        self.assertEquals(patch_direct.call_count, 1 + patch_host.call_count)
                        self.assertEquals(mock_update_host_plugin_from_goal_state.call_count, 1)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), True)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.get_goal_state")
    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.get_artifact_request")
    def test_get_artifacts_profile_should_refresh_the_host_plugin_and_not_change_default_channel_if_host_plugin_fails(self, mock_get_artifact_request, *args):
        mock_get_artifact_request.return_value = "dummy_url", "dummy_header"
        client = WireClient("foo.bar")
        client.ext_conf = ExtensionsConfig(None)
        client.ext_conf.artifacts_profile_blob = "testurl"
        json_profile = b'{ "onHold": true }'

        HostPluginProtocol.set_default_channel(False)

        mock_failed_response = MockResponse(body=b"", status_code=httpclient.GONE)

        # Everything fails. Goal state should have been updated and host channel should not have been set as default.
        with patch("azurelinuxagent.common.utils.restutil._http_request", return_value=mock_failed_response):
            with patch("azurelinuxagent.common.protocol.wire.WireClient.update_host_plugin_from_goal_state") as mock_update_host_plugin_from_goal_state:
                with patch("azurelinuxagent.common.protocol.wire.WireClient.fetch", wraps=client.fetch) as patch_direct:
                    with patch("azurelinuxagent.common.protocol.wire.WireClient.get_artifacts_profile_through_host",
                               wraps=client.get_artifacts_profile_through_host) as patch_host:
                        ret = client.get_artifacts_profile()
                        self.assertEquals(ret, None)

                        self.assertEquals(patch_host.call_count, 2)
                        # The host channel calls the direct function under the covers
                        self.assertEquals(patch_direct.call_count, 1 + patch_host.call_count)
                        self.assertEquals(mock_update_host_plugin_from_goal_state.call_count, 1)

                        self.assertEquals(HostPluginProtocol.is_default_channel(), False)

    def test_send_request_using_appropriate_channel_should_not_invoke_host_channel_when_direct_channel_succeeds(self, *args):
        xml_text = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state
        client = WireClient(WIRESERVER_URL)
        client.goal_state = GoalState(xml_text)
        client.get_host_plugin().set_default_channel(False)

        def direct_func(*args):
            direct_func.counter += 1
            return 42

        def host_func(*args):
            host_func.counter += 1
            return None

        direct_func.counter = 0
        host_func.counter = 0

        # Assert we've only called the direct channel functions and that it succeeded.
        ret = client.send_request_using_appropriate_channel(direct_func, host_func)
        self.assertEquals(42, ret)
        self.assertEquals(1, direct_func.counter)
        self.assertEquals(0, host_func.counter)

    def test_send_request_using_appropriate_channel_should_not_use_direct_channel_when_host_channel_is_default(self, *args):
        xml_text = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state
        client = WireClient(WIRESERVER_URL)
        client.goal_state = GoalState(xml_text)
        client.get_host_plugin().set_default_channel(True)

        def direct_func(*args):
            direct_func.counter += 1
            return 42

        def host_func(*args):
            host_func.counter += 1
            return 43

        direct_func.counter = 0
        host_func.counter = 0

        # Assert we've only called the host channel function since it's the default channel
        ret = client.send_request_using_appropriate_channel(direct_func, host_func)
        self.assertEquals(43, ret)
        self.assertEquals(0, direct_func.counter)
        self.assertEquals(1, host_func.counter)

    def test_send_request_using_appropriate_channel_should_use_host_channel_when_direct_channel_fails(self, *args):
        xml_text = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state
        client = WireClient(WIRESERVER_URL)
        client.goal_state = GoalState(xml_text)
        host = client.get_host_plugin()
        host.set_default_channel(False)

        def direct_func(*args):
            direct_func.counter += 1
            raise InvalidContainerError()

        def host_func(*args):
            host_func.counter += 1
            return 42

        direct_func.counter = 0
        host_func.counter = 0

        # Assert we've called both the direct channel function and the host channel function, which succeeded.
        # After the host channel succeeds, the host plugin should have been set as the default channel.
        ret = client.send_request_using_appropriate_channel(direct_func, host_func)
        self.assertEquals(42, ret)
        self.assertEquals(1, direct_func.counter)
        self.assertEquals(1, host_func.counter)
        self.assertEquals(True, host.is_default_channel())

    def test_send_request_using_appropriate_channel_should_retry_the_host_channel_after_reloading_goal_state(self, *args):
        xml_text = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE).goal_state
        client = WireClient(WIRESERVER_URL)
        client.goal_state = GoalState(xml_text)
        client.get_host_plugin().set_default_channel(False)

        def direct_func(*args):
            direct_func.counter += 1
            raise InvalidContainerError()

        def host_func(*args):
            host_func.counter += 1
            if host_func.counter == 1:
                raise ResourceGoneError("Resource is gone")
            return 42

        direct_func.counter = 0
        host_func.counter = 0

        # Assert we've called both the direct channel function (once) and the host channel function (twice).
        # After the host channel succeeds, the host plugin should have been set as the default channel.
        with patch('azurelinuxagent.common.protocol.wire.WireClient.update_host_plugin_from_goal_state') as mock_update_host_plugin_from_goal_state:
            ret = client.send_request_using_appropriate_channel(direct_func, host_func)
            self.assertEquals(42, ret)
            self.assertEquals(1, direct_func.counter)
            self.assertEquals(2, host_func.counter)
            self.assertEquals(1, mock_update_host_plugin_from_goal_state.call_count)
            self.assertEquals(True, client.get_host_plugin().is_default_channel())


class GoalStateTestCase(AgentTestCase):
    """
    Base class for UpdateGoalStateTestCase and UpdateHostPluginFromGoalStateTestCase
    """
    def setUp(self):
        AgentTestCase.setUp(self)

        self.mock_data = mockwiredata.WireProtocolData(mockwiredata.DATA_FILE)
        self.mock_http_get = patch("azurelinuxagent.common.utils.restutil.http_get", side_effect=self.mock_data.mock_http_get)
        self.mock_crypt_util = patch("azurelinuxagent.common.protocol.wire.CryptUtil", side_effect=self.mock_data.mock_crypt_util)
        self.mock_http_get.start()
        self.mock_crypt_util.start()

        # Use the WireProtocol to create a test WireClient.
        # WireProtocol.detect() creates the transport certs needed to retrieve the goal state and also sets the initial goal state.
        # WireClient.get_host_plugin() forces the host plugin to be instantiated
        protocol = WireProtocol(WIRESERVER_URL)
        protocol.detect()
        self.wire_client = protocol.client
        self.wire_client.get_host_plugin()

    def tearDown(self):
        self.mock_crypt_util.stop()
        self.mock_http_get.stop()
        AgentTestCase.tearDown(self)


class UpdateGoalStateTestCase(GoalStateTestCase):
    """
    Tests for WireClient.update_goal_state()
    """
    def test_it_should_update_the_goal_state_and_the_host_plugin_when_the_incarnation_changes(self):
        # if the incarnation changes the behavior is the same for forced and non-forced updates
        for forced in [True, False]:
            self.mock_data.reload()  # start each iteration of the test with fresh mock data

            #
            # Update the mock data with random values; include at least one field from each of the components
            # in the goal state to ensure the entire state was updated. Note that numeric entities, e.g. incarnation, are
            # actually represented as strings in the goal state.
            #
            # Note that the shared config is not parsed by the agent, so we modify the XML data directly. Also, the
            # certificates are encrypted and it is hard to update a single field; instead, we update the entire list with
            # empty.
            #
            new_incarnation = str(uuid.uuid4())
            new_container_id = str(uuid.uuid4())
            new_role_config_name = str(uuid.uuid4())
            new_hosting_env_deployment_name = str(uuid.uuid4())
            new_shared_conf = WireProtocolData.replace_xml_attribute_value(self.mock_data.shared_config, "Deployment", "name", str(uuid.uuid4()))
            new_sequence_number = str(uuid.uuid4())

            if '<Format>Pkcs7BlobWithPfxContents</Format>' not in self.mock_data.certs:
                raise Exception('This test requires a non-empty certificate list')

            self.mock_data.set_incarnation(new_incarnation)
            self.mock_data.set_container_id(new_container_id)
            self.mock_data.set_role_config_name(new_role_config_name)
            self.mock_data.set_hosting_env_deployment_name(new_hosting_env_deployment_name)
            self.mock_data.shared_config = new_shared_conf
            self.mock_data.set_extensions_config_sequence_number(new_sequence_number)
            self.mock_data.certs = r'''<?xml version="1.0" encoding="utf-8"?>
                <CertificateFile><Version>2012-11-30</Version>
                  <Incarnation>12</Incarnation>
                  <Format>CertificatesNonPfxPackage</Format>
                  <Data>NotPFXData</Data>
                </CertificateFile>
            '''

            if forced:
                self.wire_client.update_goal_state(forced=True)
            else:
                self.wire_client.update_goal_state()

            sequence_number = self.wire_client.ext_conf.ext_handlers.extHandlers[0].properties.extensions[0].sequenceNumber

            self.assertEqual(self.wire_client.goal_state.incarnation, new_incarnation)
            self.assertEqual(self.wire_client.hosting_env.deployment_name, new_hosting_env_deployment_name)
            self.assertEqual(self.wire_client.shared_conf.xml_text, new_shared_conf)
            self.assertEqual(sequence_number, new_sequence_number)
            self.assertEqual(len(self.wire_client.certs.cert_list.certificates), 0)

            self.assertEqual(self.wire_client.host_plugin.container_id, new_container_id)
            self.assertEqual(self.wire_client.host_plugin.role_config_name, new_role_config_name)

    def test_non_forced_update_should_not_update_the_goal_state_nor_the_host_plugin_when_the_incarnation_does_not_change(self):
        # The container id, role config name and shared config can change without the incarnation changing; capture the initial
        # goal state and then change those fields.
        goal_state = self.wire_client.goal_state.xml_text
        shared_conf = self.wire_client.shared_conf.xml_text
        container_id = self.wire_client.host_plugin.container_id
        role_config_name = self.wire_client.host_plugin.role_config_name

        self.mock_data.set_container_id(str(uuid.uuid4()))
        self.mock_data.set_role_config_name(str(uuid.uuid4()))
        self.mock_data.shared_config = WireProtocolData.replace_xml_attribute_value(self.mock_data.shared_config, "Deployment", "name", str(uuid.uuid4()))

        self.wire_client.update_goal_state()

        self.assertEqual(self.wire_client.goal_state.xml_text, goal_state)
        self.assertEqual(self.wire_client.shared_conf.xml_text, shared_conf)

        self.assertEqual(self.wire_client.host_plugin.container_id, container_id)
        self.assertEqual(self.wire_client.host_plugin.role_config_name, role_config_name)

    def test_forced_update_should_update_the_goal_state_and_the_host_plugin_when_the_incarnation_does_not_change(self):
        # The container id, role config name and shared config can change without the incarnation changing
        incarnation = self.wire_client.goal_state.incarnation
        new_container_id = str(uuid.uuid4())
        new_role_config_name = str(uuid.uuid4())
        new_shared_conf = WireProtocolData.replace_xml_attribute_value(self.mock_data.shared_config, "Deployment", "name", str(uuid.uuid4()))

        self.mock_data.set_container_id(new_container_id)
        self.mock_data.set_role_config_name(new_role_config_name)
        self.mock_data.shared_config = new_shared_conf

        self.wire_client.update_goal_state(forced=True)

        self.assertEqual(self.wire_client.goal_state.incarnation, incarnation)
        self.assertEqual(self.wire_client.shared_conf.xml_text, new_shared_conf)

        self.assertEqual(self.wire_client.host_plugin.container_id, new_container_id)
        self.assertEqual(self.wire_client.host_plugin.role_config_name, new_role_config_name)


class UpdateHostPluginFromGoalStateTestCase(GoalStateTestCase):
    """
    Tests for WireClient.update_host_plugin_from_goal_state()
    """
    def test_it_should_update_the_host_plugin_with_or_without_incarnation_changes(self):
        # the behavior should be the same whether the incarnation changes or not
        for incarnation_change in [True, False]:
            self.mock_data.reload()  # start each iteration of the test with fresh mock data

            new_container_id = str(uuid.uuid4())
            new_role_config_name = str(uuid.uuid4())

            goal_state = self.mock_data.goal_state
            shared_conf = self.mock_data.shared_config
            if incarnation_change:
                self.mock_data.set_incarnation(str(uuid.uuid4()))
            self.mock_data.set_container_id(new_container_id)
            self.mock_data.set_role_config_name(new_role_config_name)
            self.mock_data.shared_config = WireProtocolData.replace_xml_attribute_value(self.mock_data.shared_config, "Deployment", "name", str(uuid.uuid4()))

            self.wire_client.update_host_plugin_from_goal_state()

            self.assertEqual(self.wire_client.host_plugin.container_id, new_container_id)
            self.assertEqual(self.wire_client.host_plugin.role_config_name, new_role_config_name)

            # it should not update the goal state
            self.assertEqual(self.wire_client.goal_state.xml_text, goal_state)
            self.assertEqual(self.wire_client.shared_conf.xml_text, shared_conf)


class MockResponse:
    def __init__(self, body, status_code):
        self.body = body
        self.status = status_code

    def read(self, *_):
        return self.body


if __name__ == '__main__':
    unittest.main()
