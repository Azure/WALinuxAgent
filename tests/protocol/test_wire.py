# -*- encoding: utf-8 -*- # pylint: disable=too-many-lines
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

import contextlib
import json
import os
import re
import socket
import time
import unittest
import uuid

from azurelinuxagent.common.exception import InvalidContainerError, ResourceGoneError, ProtocolError, \
    ExtensionDownloadError, HttpError
from azurelinuxagent.common.protocol.goal_state import ExtensionsConfig
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.protocol.restapi import VMAgentManifestUri
from azurelinuxagent.common.protocol.wire import WireProtocol, WireClient, \
    InVMArtifactsProfile, StatusBlob, VMStatus
from azurelinuxagent.common.telemetryevent import TelemetryEventList, GuestAgentExtensionEventsSchema, \
    TelemetryEventParam, TelemetryEvent
from azurelinuxagent.common.utils import restutil
from azurelinuxagent.common.version import CURRENT_VERSION, DISTRO_NAME, DISTRO_VERSION
from tests.ga.test_monitor import random_generator
from tests.protocol import mockwiredata
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates
from tests.protocol.mockwiredata import DATA_FILE_NO_EXT
from tests.protocol.mockwiredata import WireProtocolData
from tests.tools import Mock, patch, AgentTestCase

data_with_bom = b'\xef\xbb\xbfhehe' # pylint: disable=invalid-name
testurl = 'http://foo' # pylint: disable=invalid-name
testtype = 'BlockBlob' # pylint: disable=invalid-name
WIRESERVER_URL = '168.63.129.16'


def get_event(message, duration=30000, evt_type="", is_internal=False, is_success=True, # pylint: disable=invalid-name,too-many-arguments
              name="", op="Unknown", version=CURRENT_VERSION, eventId=1):
    event = TelemetryEvent(eventId, "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Name, name))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Version, str(version)))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.IsInternal, is_internal))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Operation, op))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.OperationSuccess, is_success))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Message, message))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.Duration, duration))
    event.parameters.append(TelemetryEventParam(GuestAgentExtensionEventsSchema.ExtensionType, evt_type))
    return event


@contextlib.contextmanager
def create_mock_protocol(artifacts_profile_blob=None, status_upload_blob=None, status_upload_blob_type=None):
    with mock_wire_protocol(DATA_FILE_NO_EXT) as protocol:
        # These tests use mock wire data that dont have any extensions (extension config will be empty).
        # Populate the upload blob and artifacts profile blob.
        ext_conf = ExtensionsConfig(None)
        ext_conf.artifacts_profile_blob = artifacts_profile_blob
        ext_conf.status_upload_blob = status_upload_blob
        ext_conf.status_upload_blob_type = status_upload_blob_type
        protocol.client._goal_state.ext_conf = ext_conf # pylint: disable=protected-access

        yield protocol


# pylint: disable=too-many-public-methods
@patch("time.sleep")
@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.protocol.healthservice.HealthService._report")
class TestWireProtocol(AgentTestCase):

    def setUp(self):
        super(TestWireProtocol, self).setUp()
        HostPluginProtocol.set_default_channel(False)

    def _test_getters(self, test_data, certsMustBePresent, __, MockCryptUtil, _): # pylint: disable=invalid-name
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        with patch.object(restutil, 'http_get', test_data.mock_http_get):
            protocol = WireProtocol(WIRESERVER_URL)
            protocol.detect()
            protocol.get_vminfo()
            protocol.get_certs()
            ext_handlers, etag = protocol.get_ext_handlers() # pylint: disable=unused-variable
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

    def test_call_storage_kwargs(self, *args): # pylint: disable=unused-argument
        from azurelinuxagent.common.utils import restutil # pylint: disable=redefined-outer-name,reimported
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
                c = http_patch.call_args_list[i][-1]['use_proxy'] # pylint: disable=invalid-name
                self.assertTrue(c == (True if i != 3 else False)) # pylint: disable=simplifiable-if-expression

    def test_status_blob_parsing(self, *args): # pylint: disable=unused-argument
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            self.assertEqual(protocol.client.get_ext_conf().status_upload_blob,
                             'https://test.blob.core.windows.net/vhds/test-cs12.test-cs12.test-cs12.status?'
                             'sr=b&sp=rw&se=9999-01-01&sk=key1&sv=2014-02-14&'
                             'sig=hfRh7gzUE7sUtYwke78IOlZOrTRCYvkec4hGZ9zZzXo')
            self.assertEqual(protocol.client.get_ext_conf().status_upload_blob_type, u'BlockBlob')

    def test_get_host_ga_plugin(self, *args): # pylint: disable=unused-argument
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            host_plugin = protocol.client.get_host_plugin()
            goal_state = protocol.client.get_goal_state()
            self.assertEqual(goal_state.container_id, host_plugin.container_id)
            self.assertEqual(goal_state.role_config_name, host_plugin.role_config_name)

    def test_upload_status_blob_should_use_the_host_channel_by_default(self, *_):
        def http_put_handler(url, *_, **__): # pylint: disable=inconsistent-return-statements
            if protocol.get_endpoint() in url and url.endswith('/status'):
                return MockResponse(body=b'', status_code=200)

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_put_handler=http_put_handler) as protocol:
            HostPluginProtocol.set_default_channel(False)
            protocol.client.status_blob.vm_status = VMStatus(message="Ready", status="Ready")

            protocol.client.upload_status_blob()

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 1, 'Expected one post request to the host: [{0}]'.format(urls))

    def test_upload_status_blob_host_ga_plugin(self, *_):
        with create_mock_protocol(status_upload_blob=testurl, status_upload_blob_type=testtype) as protocol:
            protocol.client.status_blob.vm_status = VMStatus(message="Ready", status="Ready")

            with patch.object(HostPluginProtocol, "ensure_initialized", return_value=True):
                with patch.object(StatusBlob, "upload", return_value=False) as patch_default_upload:
                    with patch.object(HostPluginProtocol, "_put_block_blob_status") as patch_http:
                        HostPluginProtocol.set_default_channel(False)
                        protocol.client.upload_status_blob()
                        patch_default_upload.assert_not_called()
                        patch_http.assert_called_once_with(testurl, protocol.client.status_blob)
                        self.assertFalse(HostPluginProtocol.is_default_channel())

    @patch("azurelinuxagent.common.protocol.hostplugin.HostPluginProtocol.ensure_initialized")
    def test_upload_status_blob_unknown_type_assumes_block(self, *_):
        with create_mock_protocol(status_upload_blob=testurl, status_upload_blob_type="NotALegalType") as protocol:
            protocol.client.status_blob.vm_status = VMStatus(message="Ready", status="Ready")

            with patch.object(StatusBlob, "prepare") as patch_prepare:
                with patch.object(StatusBlob, "upload") as patch_default_upload:
                    HostPluginProtocol.set_default_channel(False)
                    protocol.client.upload_status_blob()

                    patch_prepare.assert_called_once_with("BlockBlob")
                    patch_default_upload.assert_called_once_with(testurl)

    def test_upload_status_blob_reports_prepare_error(self, *_):
        with create_mock_protocol(status_upload_blob=testurl, status_upload_blob_type=testtype) as protocol:
            protocol.client.status_blob.vm_status = VMStatus(message="Ready", status="Ready")

            with patch.object(StatusBlob, "prepare", side_effect=Exception) as mock_prepare:
                self.assertRaises(ProtocolError, protocol.client.upload_status_blob)
                self.assertEqual(1, mock_prepare.call_count)

    def test_get_in_vm_artifacts_profile_blob_not_available(self, *_):
        # Test when artifacts_profile_blob is null/None
        with mock_wire_protocol(DATA_FILE_NO_EXT) as protocol:
            protocol.client._goal_state.ext_conf = ExtensionsConfig(None) # pylint: disable=protected-access

            self.assertEqual(None, protocol.client.get_artifacts_profile())

        # Test when artifacts_profile_blob is whitespace
        with create_mock_protocol(artifacts_profile_blob="  ") as protocol:
            self.assertEqual(None, protocol.client.get_artifacts_profile())

    def test_get_in_vm_artifacts_profile_response_body_not_valid(self, *_):
        with create_mock_protocol(artifacts_profile_blob=testurl) as protocol:
            with patch.object(HostPluginProtocol, "get_artifact_request", return_value=['dummy_url', {}]) as host_plugin_get_artifact_url_and_headers:
                # Test when response body is None
                protocol.client.call_storage_service = Mock(return_value=MockResponse(None, 200))
                in_vm_artifacts_profile = protocol.client.get_artifacts_profile()
                self.assertTrue(in_vm_artifacts_profile is None)

                # Test when response body is None
                protocol.client.call_storage_service = Mock(return_value=MockResponse('   '.encode('utf-8'), 200))
                in_vm_artifacts_profile = protocol.client.get_artifacts_profile()
                self.assertTrue(in_vm_artifacts_profile is None)

                # Test when response body is None
                protocol.client.call_storage_service = Mock(return_value=MockResponse('{ }'.encode('utf-8'), 200))
                in_vm_artifacts_profile = protocol.client.get_artifacts_profile()
                self.assertEqual(dict(), in_vm_artifacts_profile.__dict__,
                                 'If artifacts_profile_blob has empty json dictionary, in_vm_artifacts_profile '
                                 'should contain nothing')

                host_plugin_get_artifact_url_and_headers.assert_called_with(testurl)

    @patch("azurelinuxagent.common.event.add_event")
    def test_artifacts_profile_json_parsing(self, patch_event, *args): # pylint: disable=unused-argument
        with create_mock_protocol(artifacts_profile_blob=testurl) as protocol:
            # response is invalid json
            protocol.client.call_storage_service = Mock(return_value=MockResponse("invalid json".encode('utf-8'), 200))
            in_vm_artifacts_profile = protocol.client.get_artifacts_profile()

            # ensure response is empty
            self.assertEqual(None, in_vm_artifacts_profile)

            # ensure event is logged
            self.assertEqual(1, patch_event.call_count)
            self.assertFalse(patch_event.call_args[1]['is_success'])
            self.assertTrue('invalid json' in patch_event.call_args[1]['message'])
            self.assertEqual('ArtifactsProfileBlob', patch_event.call_args[1]['op'])

    def test_get_in_vm_artifacts_profile_default(self, *args): # pylint: disable=unused-argument
        with create_mock_protocol(artifacts_profile_blob=testurl) as protocol:
            protocol.client.call_storage_service = Mock(return_value=MockResponse('{"onHold": "true"}'.encode('utf-8'), 200))
            in_vm_artifacts_profile = protocol.client.get_artifacts_profile()
            self.assertEqual(dict(onHold='true'), in_vm_artifacts_profile.__dict__)
            self.assertTrue(in_vm_artifacts_profile.is_on_hold())

    @patch("socket.gethostname", return_value="hostname")
    @patch("time.gmtime", return_value=time.localtime(1485543256))
    def test_report_vm_status(self, *args): # pylint: disable=unused-argument
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
    def test_send_encoded_event(self, mock_http_request, *args):
        mock_http_request.return_value = MockResponse("", 200)

        event_str = u'a test string'
        client = WireProtocol(WIRESERVER_URL).client
        client.send_encoded_event("foo", event_str.encode('utf-8'))

        first_call = mock_http_request.call_args_list[0]
        args, kwargs = first_call
        method, url, body_received = args # pylint: disable=unused-variable
        headers = kwargs['headers']

        # the headers should include utf-8 encoding...
        self.assertTrue("utf-8" in headers['Content-Type'])
        # the body is encoded, decode and check for equality
        self.assertIn(event_str, body_received.decode('utf-8'))

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_encoded_event")
    def test_report_event_small_event(self, patch_send_event, *args): # pylint: disable=unused-argument
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

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_encoded_event")
    def test_report_event_multiple_events_to_fill_buffer(self, patch_send_event, *args): # pylint: disable=unused-argument
        event_list = TelemetryEventList()
        client = WireProtocol(WIRESERVER_URL).client

        event_str = random_generator(2 ** 15)
        event_list.events.append(get_event(message=event_str))
        event_list.events.append(get_event(message=event_str))

        client.report_event(event_list)

        # It merges the messages into one message
        self.assertEqual(patch_send_event.call_count, 2)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_encoded_event")
    def test_report_event_large_event(self, patch_send_event, *args): # pylint: disable=unused-argument
        event_list = TelemetryEventList()
        event_str = random_generator(2 ** 18)
        event_list.events.append(get_event(message=event_str))
        client = WireProtocol(WIRESERVER_URL).client
        client.report_event(event_list)

        self.assertEqual(patch_send_event.call_count, 0)


class TestWireClient(HttpRequestPredicates, AgentTestCase):
    def test_get_ext_conf_without_extensions_should_retrieve_vmagent_manifests_info(self, *args): # pylint: disable=unused-argument
        # Basic test for get_ext_conf() when extensions are not present in the config. The test verifies that
        # get_ext_conf() fetches the correct data by comparing the returned data with the test data provided the
        # mock_wire_protocol.
        with mock_wire_protocol(mockwiredata.DATA_FILE_NO_EXT) as protocol:
            ext_conf = protocol.client.get_ext_conf()

            ext_handlers_names = [ext_handler.name for ext_handler in ext_conf.ext_handlers.extHandlers]
            self.assertEqual(0, len(ext_conf.ext_handlers.extHandlers),
                             "Unexpected number of extension handlers in the extension config: [{0}]".format(ext_handlers_names))
            vmagent_manifests = [manifest.family for manifest in ext_conf.vmagent_manifests.vmAgentManifests]
            self.assertEqual(0, len(ext_conf.vmagent_manifests.vmAgentManifests),
                             "Unexpected number of vmagent manifests in the extension config: [{0}]".format(vmagent_manifests))
            self.assertIsNone(ext_conf.status_upload_blob,
                              "Status upload blob in the extension config is expected to be None")
            self.assertIsNone(ext_conf.status_upload_blob_type,
                              "Type of status upload blob in the extension config is expected to be None")
            self.assertIsNone(ext_conf.artifacts_profile_blob,
                              "Artifacts profile blob in the extensions config is expected to be None")

    def test_get_ext_conf_with_extensions_should_retrieve_ext_handlers_and_vmagent_manifests_info(self):
        # Basic test for get_ext_conf() when extensions are present in the config. The test verifies that get_ext_conf()
        # fetches the correct data by comparing the returned data with the test data provided the mock_wire_protocol.
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            wire_protocol_client = protocol.client
            ext_conf = wire_protocol_client.get_ext_conf()

            ext_handlers_names = [ext_handler.name for ext_handler in ext_conf.ext_handlers.extHandlers]
            self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers),
                             "Unexpected number of extension handlers in the extension config: [{0}]".format(ext_handlers_names))
            vmagent_manifests = [manifest.family for manifest in ext_conf.vmagent_manifests.vmAgentManifests]
            self.assertEqual(2, len(ext_conf.vmagent_manifests.vmAgentManifests),
                             "Unexpected number of vmagent manifests in the extension config: [{0}]".format(vmagent_manifests))
            self.assertEqual("https://test.blob.core.windows.net/vhds/test-cs12.test-cs12.test-cs12.status?sr=b&sp=rw"
                             "&se=9999-01-01&sk=key1&sv=2014-02-14&sig=hfRh7gzUE7sUtYwke78IOlZOrTRCYvkec4hGZ9zZzXo",
                             ext_conf.status_upload_blob, "Unexpected value for status upload blob URI")
            self.assertEqual("BlockBlob", ext_conf.status_upload_blob_type,
                             "Unexpected status upload blob type in the extension config")
            self.assertEqual(None, ext_conf.artifacts_profile_blob,
                             "Artifacts profile blob in the extension config should have been None")

    def test_download_ext_handler_pkg_should_not_invoke_host_channel_when_direct_channel_succeeds(self):
        extension_url = 'https://fake_host/fake_extension.zip'
        target_file = os.path.join(self.tmp_dir, 'fake_extension.zip')

        def http_get_handler(url, *_, **__):
            if url == extension_url:
                return MockResponse(body=b'', status_code=200)
            if self.is_host_plugin_extension_artifact_request(url):
                self.fail('The host channel should not have been used')
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_get_handler=http_get_handler) as protocol:
            HostPluginProtocol.set_default_channel(False)

            success = protocol.download_ext_handler_pkg(extension_url, target_file)

            urls = protocol.get_tracked_urls()
            self.assertEqual(success, True, 'The download should have succeeded')
            self.assertEqual(len(urls), 1, "Unexpected number of HTTP requests: [{0}]".format(urls))
            self.assertEqual(urls[0], extension_url, "The extension should have been downloaded over the direct channel")
            self.assertTrue(os.path.exists(target_file), 'The extension package was not downloaded')
            self.assertEqual(HostPluginProtocol.is_default_channel(), False, "The host channel should not have been set as the default")

    def test_download_ext_handler_pkg_should_use_host_channel_when_direct_channel_fails_and_set_host_as_default(self):
        extension_url = 'https://fake_host/fake_extension.zip'
        target_file = os.path.join(self.tmp_dir, 'fake_extension.zip')

        def http_get_handler(url, *_, **kwargs):
            if url == extension_url:
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_extension_request(url, kwargs, extension_url):
                return MockResponse(body=b'', status_code=200)
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_get_handler=http_get_handler) as protocol:
            HostPluginProtocol.set_default_channel(False)

            success = protocol.download_ext_handler_pkg(extension_url, target_file)

            urls = protocol.get_tracked_urls()
            self.assertEqual(success, True, 'The download should have succeeded')
            self.assertEqual(len(urls), 2, "Unexpected number of HTTP requests: [{0}]".format(urls))
            self.assertEqual(urls[0], extension_url, "The first attempt should have been over the direct channel")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The retry attempt should have been over the host channel")
            self.assertTrue(os.path.exists(target_file), 'The extension package was not downloaded')
            self.assertEqual(HostPluginProtocol.is_default_channel(), True, "The host channel should have been set as the default")

    def test_download_ext_handler_pkg_should_retry_the_host_channel_after_refreshing_host_plugin(self):
        extension_url = 'https://fake_host/fake_extension.zip'
        target_file = os.path.join(self.tmp_dir, 'fake_extension.zip')

        def http_get_handler(url, *args, **kwargs): # pylint: disable=unused-argument
            if url == extension_url:
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_extension_request(url, kwargs, extension_url):
                # fake a stale goal state then succeed once the goal state has been refreshed
                if http_get_handler.goal_state_requests == 0:
                    http_get_handler.goal_state_requests += 1
                    return ResourceGoneError("Exception to fake a stale goal")
                return MockResponse(body=b'', status_code=200)
            if self.is_goal_state_request(url):
                protocol.track_url(url)  # track requests for the goal state
            return None
        http_get_handler.goal_state_requests = 0

        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            HostPluginProtocol.set_default_channel(False)

            try:
                # initialization of the host plugin triggers a request for the goal state; do it here before we start tracking those requests.
                protocol.client.get_host_plugin()

                protocol.set_http_handlers(http_get_handler=http_get_handler)

                success = protocol.download_ext_handler_pkg(extension_url, target_file)

                urls = protocol.get_tracked_urls()
                self.assertEqual(success, True, 'The download should have succeeded')
                self.assertEqual(len(urls), 4, "Unexpected number of HTTP requests: [{0}]".format(urls))
                self.assertEqual(urls[0], extension_url, "The first attempt should have been over the direct channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second attempt should have been over the host channel")
                self.assertTrue(self.is_goal_state_request(urls[2]), "The host channel should have been refreshed the goal state")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]), "The third attempt should have been over the host channel")
                self.assertTrue(os.path.exists(target_file), 'The extension package was not downloaded')
                self.assertEqual(HostPluginProtocol.is_default_channel(), True, "The host channel should have been set as the default")
            finally:
                HostPluginProtocol.set_default_channel(False)

    def test_download_ext_handler_pkg_should_not_change_default_channel_when_all_channels_fail(self):
        extension_url = 'https://fake_host/fake_extension.zip'

        def http_get_handler(url, *_, **kwargs):
            if url == extension_url:
                return HttpError("Exception to fake error on direct channel")
            if self.is_host_plugin_extension_request(url, kwargs, extension_url):
                return ResourceGoneError("Exception to fake error on host channel")
            if self.is_goal_state_request(url):
                protocol.track_url(url)  # keep track of goal state requests
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            HostPluginProtocol.set_default_channel(False)

            # initialization of the host plugin triggers a request for the goal state; do it here before we start tracking those requests.
            protocol.client.get_host_plugin()

            protocol.set_http_handlers(http_get_handler=http_get_handler)

            success = protocol.download_ext_handler_pkg(extension_url, "/an-invalid-directory/an-invalid-file.zip")

            urls = protocol.get_tracked_urls()
            self.assertEqual(success, False, "The download should have failed")
            self.assertEqual(len(urls), 4, "Unexpected number of HTTP requests: [{0}]".format(urls))
            self.assertEqual(urls[0], extension_url, "The first attempt should have been over the direct channel")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second attempt should have been over the host channel")
            self.assertTrue(self.is_goal_state_request(urls[2]), "The host channel should have been refreshed the goal state")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]), "The third attempt should have been over the host channel")
            self.assertEqual(HostPluginProtocol.is_default_channel(), False, "The host channel should not have been set as the default")

    def test_fetch_manifest_should_not_invoke_host_channel_when_direct_channel_succeeds(self):
        manifest_url = 'https://fake_host/fake_manifest.xml'
        manifest_xml = '<?xml version="1.0" encoding="utf-8"?><PluginVersionManifest/>'

        def http_get_handler(url, *_, **__):
            if url == manifest_url:
                return MockResponse(body=manifest_xml.encode('utf-8'), status_code=200)
            if url.endswith('/extensionArtifact'):
                self.fail('The Host GA Plugin should not have been invoked')
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_get_handler=http_get_handler) as protocol:
            HostPluginProtocol.set_default_channel(False)

            manifest = protocol.client.fetch_manifest([VMAgentManifestUri(uri=manifest_url)])

            urls = protocol.get_tracked_urls()
            self.assertEqual(manifest, manifest_xml, 'The expected manifest was not downloaded')
            self.assertEqual(len(urls), 1, "Unexpected number of HTTP requests: [{0}]".format(urls))
            self.assertEqual(urls[0], manifest_url, "The manifest should have been downloaded over the direct channel")
            self.assertEqual(HostPluginProtocol.is_default_channel(), False, "The default channel should not have changed")

    def test_fetch_manifest_should_use_host_channel_when_direct_channel_fails_and_set_it_to_default(self):
        manifest_url = 'https://fake_host/fake_manifest.xml'
        manifest_xml = '<?xml version="1.0" encoding="utf-8"?><PluginVersionManifest/>'

        def http_get_handler(url, *_, **kwargs):
            if url == manifest_url:
                return ResourceGoneError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_extension_request(url, kwargs, manifest_url):
                return MockResponse(body=manifest_xml.encode('utf-8'), status_code=200)
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_get_handler=http_get_handler) as protocol:
            HostPluginProtocol.set_default_channel(False)

            try:
                manifest = protocol.client.fetch_manifest([VMAgentManifestUri(uri=manifest_url)])

                urls = protocol.get_tracked_urls()
                self.assertEqual(manifest, manifest_xml, 'The expected manifest was not downloaded')
                self.assertEqual(len(urls), 2, "Unexpected number of HTTP requests: [{0}]".format(urls))
                self.assertEqual(urls[0], manifest_url, "The first attempt should have been over the direct channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The retry should have been over the host channel")
                self.assertEqual(HostPluginProtocol.is_default_channel(), True, "The host should have been set as the default channel")
            finally:
                HostPluginProtocol.set_default_channel(False)  # Reset default channel

    def test_fetch_manifest_should_retry_the_host_channel_after_refreshing_the_host_plugin_and_set_the_host_as_default(self):
        manifest_url = 'https://fake_host/fake_manifest.xml'
        manifest_xml = '<?xml version="1.0" encoding="utf-8"?><PluginVersionManifest/>'

        def http_get_handler(url, *_, **kwargs):
            if url == manifest_url:
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_extension_request(url, kwargs, manifest_url): # pylint: disable=no-else-return
                # fake a stale goal state then succeed once the goal state has been refreshed
                if http_get_handler.goal_state_requests == 0:
                    http_get_handler.goal_state_requests += 1
                    return ResourceGoneError("Exception to fake a stale goal state")
                return MockResponse(body=manifest_xml.encode('utf-8'), status_code=200)
            elif self.is_goal_state_request(url):
                protocol.track_url(url)  # keep track of goal state requests
            return None
        http_get_handler.goal_state_requests = 0

        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            HostPluginProtocol.set_default_channel(False)

            try:
                # initialization of the host plugin triggers a request for the goal state; do it here before we start tracking those requests.
                protocol.client.get_host_plugin()

                protocol.set_http_handlers(http_get_handler=http_get_handler)
                manifest = protocol.client.fetch_manifest([VMAgentManifestUri(uri=manifest_url)])

                urls = protocol.get_tracked_urls()
                self.assertEqual(manifest, manifest_xml)
                self.assertEqual(len(urls), 4, "Unexpected number of HTTP requests: [{0}]".format(urls))
                self.assertEqual(urls[0], manifest_url, "The first attempt should have been over the direct channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second attempt should have been over the host channel")
                self.assertTrue(self.is_goal_state_request(urls[2]), "The host channel should have been refreshed the goal state")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]), "The third attempt should have been over the host channel")
                self.assertEqual(HostPluginProtocol.is_default_channel(), True, "The host should have been set as the default channel")
            finally:
                HostPluginProtocol.set_default_channel(False)  # Reset default channel

    def test_fetch_manifest_should_update_goal_state_and_not_change_default_channel_if_host_fails(self):
        manifest_url = 'https://fake_host/fake_manifest.xml'

        def http_get_handler(url, *_, **kwargs):
            if url == manifest_url or self.is_host_plugin_extension_request(url, kwargs, manifest_url): # pylint: disable=no-else-return
                return ResourceGoneError("Exception to fake an error on either channel")
            elif self.is_goal_state_request(url):
                protocol.track_url(url)  # keep track of goal state requests
            return None

        # Everything fails. Goal state should have been updated and host channel should not have been set as default.
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            HostPluginProtocol.set_default_channel(False)

            # initialization of the host plugin triggers a request for the goal state; do it here before we start
            # tracking those requests.
            protocol.client.get_host_plugin()

            protocol.set_http_handlers(http_get_handler=http_get_handler)

            with self.assertRaises(ExtensionDownloadError):
                protocol.client.fetch_manifest([VMAgentManifestUri(uri=manifest_url)])

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 4, "Unexpected number of HTTP requests: [{0}]".format(urls))
            self.assertEqual(urls[0], manifest_url, "The first attempt should have been over the direct channel")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]),
                            "The second attempt should have been over the host channel")
            self.assertTrue(self.is_goal_state_request(urls[2]),
                            "The host channel should have been refreshed the goal state")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]),
                            "The third attempt should have been over the host channel")
            self.assertEqual(HostPluginProtocol.is_default_channel(), False,
                              "The host should not have been set as the default channel")

            self.assertEqual(HostPluginProtocol.is_default_channel(), False)

    def test_get_artifacts_profile_should_not_invoke_host_channel_when_direct_channel_succeeds(self):
        def http_get_handler(url, *_, **__): # pylint: disable=useless-return
            if self.is_in_vm_artifacts_profile_request(url):
                protocol.track_url(url)
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_ARTIFACTS_PROFILE, http_get_handler=http_get_handler) as protocol:
            HostPluginProtocol.set_default_channel(False)

            return_value = protocol.client.get_artifacts_profile()

            self.assertIsInstance(return_value, InVMArtifactsProfile, 'The request did not return a valid artifacts profile: {0}'.format(return_value))
            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 1, "Unexpected HTTP requests: [{0}]".format(urls))
            self.assertEqual(HostPluginProtocol.is_default_channel(), False)

    def test_get_artifacts_profile_should_use_host_channel_when_direct_channel_fails(self):
        def http_get_handler(url, *_, **kwargs):
            if self.is_in_vm_artifacts_profile_request(url):
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_in_vm_artifacts_profile_request(url, kwargs):
                protocol.track_url(url)
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_ARTIFACTS_PROFILE) as protocol:
            HostPluginProtocol.set_default_channel(False)

            try:
                protocol.set_http_handlers(http_get_handler=http_get_handler)

                return_value = protocol.client.get_artifacts_profile()

                self.assertIsNotNone(return_value, "The artifacts profile request should have succeeded")
                self.assertIsInstance(return_value, InVMArtifactsProfile, 'The request did not return a valid artifacts profile: {0}'.format(return_value))
                self.assertTrue(return_value.onHold, 'The OnHold property should be True') # pylint: disable=no-member
                urls = protocol.get_tracked_urls()
                self.assertEqual(len(urls), 2, "Invalid number of requests: [{0}]".format(urls))
                self.assertTrue(self.is_in_vm_artifacts_profile_request(urls[0]), "The first request should have been over the direct channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second request should have been over the host channel")
                self.assertEqual(HostPluginProtocol.is_default_channel(), True, "The default channel should have changed to the host")
            finally:
                HostPluginProtocol.set_default_channel(False)

    def test_get_artifacts_profile_should_retry_the_host_channel_after_refreshing_the_host_plugin(self):
        def http_get_handler(url, *_, **kwargs):
            if self.is_in_vm_artifacts_profile_request(url):
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_in_vm_artifacts_profile_request(url, kwargs):
                if http_get_handler.host_plugin_calls == 0:
                    http_get_handler.host_plugin_calls += 1
                    return ResourceGoneError("Exception to fake a stale goal state")
                protocol.track_url(url)
            if self.is_goal_state_request(url):
                protocol.track_url(url)
            return None
        http_get_handler.host_plugin_calls = 0

        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_ARTIFACTS_PROFILE) as protocol:
            HostPluginProtocol.set_default_channel(False)

            try:
                # initialization of the host plugin triggers a request for the goal state; do it here before we start tracking those requests.
                protocol.client.get_host_plugin()

                protocol.set_http_handlers(http_get_handler=http_get_handler)

                return_value = protocol.client.get_artifacts_profile()

                self.assertIsNotNone(return_value, "The artifacts profile request should have succeeded")
                self.assertIsInstance(return_value, InVMArtifactsProfile, 'The request did not return a valid artifacts profile: {0}'.format(return_value))
                self.assertTrue(return_value.onHold, 'The OnHold property should be True') # pylint: disable=no-member
                urls = protocol.get_tracked_urls()
                self.assertEqual(len(urls), 4, "Invalid number of requests: [{0}]".format(urls))
                self.assertTrue(self.is_in_vm_artifacts_profile_request(urls[0]), "The first request should have been over the direct channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second request should have been over the host channel")
                self.assertTrue(self.is_goal_state_request(urls[2]), "The goal state should have been refreshed before retrying the host channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]), "The retry request should have been over the host channel")
                self.assertEqual(HostPluginProtocol.is_default_channel(), True, "The default channel should have changed to the host")
            finally:
                HostPluginProtocol.set_default_channel(False)

    def test_get_artifacts_profile_should_refresh_the_host_plugin_and_not_change_default_channel_if_host_plugin_fails(self):
        def http_get_handler(url, *_, **kwargs):
            if self.is_in_vm_artifacts_profile_request(url):
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_in_vm_artifacts_profile_request(url, kwargs):
                return ResourceGoneError("Exception to fake a stale goal state")
            if self.is_goal_state_request(url):
                protocol.track_url(url)
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_ARTIFACTS_PROFILE) as protocol:
            HostPluginProtocol.set_default_channel(False)

            # initialization of the host plugin triggers a request for the goal state; do it here before we start tracking those requests.
            protocol.client.get_host_plugin()

            protocol.set_http_handlers(http_get_handler=http_get_handler)

            return_value = protocol.client.get_artifacts_profile()

            self.assertIsNone(return_value, "The artifacts profile request should have failed")
            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 4, "Invalid number of requests: [{0}]".format(urls))
            self.assertTrue(self.is_in_vm_artifacts_profile_request(urls[0]), "The first request should have been over the direct channel")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second request should have been over the host channel")
            self.assertTrue(self.is_goal_state_request(urls[2]), "The goal state should have been refreshed before retrying the host channel")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]), "The retry request should have been over the host channel")
            self.assertEqual(HostPluginProtocol.is_default_channel(), False, "The default channel should not have changed")

    def test_upload_logs_should_not_refresh_plugin_when_first_attempt_succeeds(self):
        def http_put_handler(url, *_, **__): # pylint: disable=inconsistent-return-statements
            if self.is_host_plugin_put_logs_request(url):
                return MockResponse(body=b'', status_code=200)

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_put_handler=http_put_handler) as protocol:
            content = b"test"
            protocol.client.upload_logs(content)

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 1, 'Expected one post request to the host: [{0}]'.format(urls))

    def test_upload_logs_should_retry_the_host_channel_after_refreshing_the_host_plugin(self):
        def http_put_handler(url, *_, **__):
            if self.is_host_plugin_put_logs_request(url):
                if http_put_handler.host_plugin_calls == 0:
                    http_put_handler.host_plugin_calls += 1
                    return ResourceGoneError("Exception to fake a stale goal state")
                protocol.track_url(url)
            return None
        http_put_handler.host_plugin_calls = 0

        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_ARTIFACTS_PROFILE, http_put_handler=http_put_handler) \
                as protocol:
            content = b"test"
            protocol.client.upload_logs(content)

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 2, "Invalid number of requests: [{0}]".format(urls))
            self.assertTrue(self.is_host_plugin_put_logs_request(urls[0]),
                            "The first request should have been over the host channel")
            self.assertTrue(self.is_host_plugin_put_logs_request(urls[1]),
                            "The second request should have been over the host channel")

    def test_send_request_using_appropriate_channel_should_not_invoke_host_channel_when_direct_channel_succeeds(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.client.get_host_plugin().set_default_channel(False)

            def direct_func(*args): # pylint: disable=unused-argument
                direct_func.counter += 1
                return 42

            def host_func(*args): # pylint: disable=useless-return,unused-argument
                host_func.counter += 1
                return None

            direct_func.counter = 0
            host_func.counter = 0

            # Assert we've only called the direct channel functions and that it succeeded.
            ret = protocol.client.send_request_using_appropriate_channel(direct_func, host_func)
            self.assertEqual(42, ret)
            self.assertEqual(1, direct_func.counter)
            self.assertEqual(0, host_func.counter)

    def test_send_request_using_appropriate_channel_should_not_use_direct_channel_when_host_channel_is_default(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.client.get_host_plugin().set_default_channel(True)

            def direct_func(*args): # pylint: disable=unused-argument
                direct_func.counter += 1
                return 42

            def host_func(*args): # pylint: disable=unused-argument
                host_func.counter += 1
                return 43

            direct_func.counter = 0
            host_func.counter = 0

            # Assert we've only called the host channel function since it's the default channel
            ret = protocol.client.send_request_using_appropriate_channel(direct_func, host_func)
            self.assertEqual(43, ret)
            self.assertEqual(0, direct_func.counter)
            self.assertEqual(1, host_func.counter)

    def test_send_request_using_appropriate_channel_should_use_host_channel_when_direct_channel_fails(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            host = protocol.client.get_host_plugin()
            host.set_default_channel(False)

            def direct_func(*args): # pylint: disable=unused-argument
                direct_func.counter += 1
                raise InvalidContainerError()

            def host_func(*args): # pylint: disable=unused-argument
                host_func.counter += 1
                return 42

            direct_func.counter = 0
            host_func.counter = 0

            # Assert we've called both the direct channel function and the host channel function, which succeeded.
            # After the host channel succeeds, the host plugin should have been set as the default channel.
            ret = protocol.client.send_request_using_appropriate_channel(direct_func, host_func)
            self.assertEqual(42, ret)
            self.assertEqual(1, direct_func.counter)
            self.assertEqual(1, host_func.counter)
            self.assertEqual(True, host.is_default_channel())

    def test_send_request_using_appropriate_channel_should_retry_the_host_channel_after_reloading_goal_state(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.client.get_host_plugin().set_default_channel(False)

            def direct_func(*args): # pylint: disable=unused-argument
                direct_func.counter += 1
                raise InvalidContainerError()

            def host_func(*args): # pylint: disable=unused-argument
                host_func.counter += 1
                if host_func.counter == 1:
                    raise ResourceGoneError("Resource is gone")
                return 42

            direct_func.counter = 0
            host_func.counter = 0

            # Assert we've called both the direct channel function (once) and the host channel function (twice).
            # After the host channel succeeds, the host plugin should have been set as the default channel.
            with patch(
                    'azurelinuxagent.common.protocol.wire.WireClient.update_host_plugin_from_goal_state') as mock_update_host_plugin_from_goal_state:
                ret = protocol.client.send_request_using_appropriate_channel(direct_func, host_func)
                self.assertEqual(42, ret)
                self.assertEqual(1, direct_func.counter)
                self.assertEqual(2, host_func.counter)
                self.assertEqual(1, mock_update_host_plugin_from_goal_state.call_count)
                self.assertEqual(True, protocol.client.get_host_plugin().is_default_channel())


class UpdateGoalStateTestCase(AgentTestCase):
    """
    Tests for WireClient.update_goal_state()
    """

    def test_it_should_update_the_goal_state_and_the_host_plugin_when_the_incarnation_changes(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.client.get_host_plugin()

            # if the incarnation changes the behavior is the same for forced and non-forced updates
            for forced in [True, False]:
                protocol.mock_wire_data.reload()  # start each iteration of the test with fresh mock data

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
                new_shared_conf = WireProtocolData.replace_xml_attribute_value(protocol.mock_wire_data.shared_config, "Deployment", "name", str(uuid.uuid4()))
                new_sequence_number = str(uuid.uuid4())

                if '<Format>Pkcs7BlobWithPfxContents</Format>' not in protocol.mock_wire_data.certs:
                    raise Exception('This test requires a non-empty certificate list')

                protocol.mock_wire_data.set_incarnation(new_incarnation)
                protocol.mock_wire_data.set_container_id(new_container_id)
                protocol.mock_wire_data.set_role_config_name(new_role_config_name)
                protocol.mock_wire_data.set_hosting_env_deployment_name(new_hosting_env_deployment_name)
                protocol.mock_wire_data.shared_config = new_shared_conf
                protocol.mock_wire_data.set_extensions_config_sequence_number(new_sequence_number)
                protocol.mock_wire_data.certs = r'''<?xml version="1.0" encoding="utf-8"?>
                    <CertificateFile><Version>2012-11-30</Version>
                      <Incarnation>12</Incarnation>
                      <Format>CertificatesNonPfxPackage</Format>
                      <Data>NotPFXData</Data>
                    </CertificateFile>
                '''

                if forced:
                    protocol.client.update_goal_state(forced=True)
                else:
                    protocol.client.update_goal_state()

                sequence_number = protocol.client.get_ext_conf().ext_handlers.extHandlers[0].properties.extensions[0].sequenceNumber

                self.assertEqual(protocol.client.get_goal_state().incarnation, new_incarnation)
                self.assertEqual(protocol.client.get_hosting_env().deployment_name, new_hosting_env_deployment_name)
                self.assertEqual(protocol.client.get_shared_conf().xml_text, new_shared_conf)
                self.assertEqual(sequence_number, new_sequence_number)
                self.assertEqual(len(protocol.client.get_certs().cert_list.certificates), 0)

                self.assertEqual(protocol.client.get_host_plugin().container_id, new_container_id)
                self.assertEqual(protocol.client.get_host_plugin().role_config_name, new_role_config_name)

    def test_non_forced_update_should_not_update_the_goal_state_nor_the_host_plugin_when_the_incarnation_does_not_change(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.client.get_host_plugin()

            # The container id, role config name and shared config can change without the incarnation changing; capture the initial
            # goal state and then change those fields.
            goal_state = protocol.client.get_goal_state().xml_text
            shared_conf = protocol.client.get_shared_conf().xml_text
            container_id = protocol.client.get_host_plugin().container_id
            role_config_name = protocol.client.get_host_plugin().role_config_name

            protocol.mock_wire_data.set_container_id(str(uuid.uuid4()))
            protocol.mock_wire_data.set_role_config_name(str(uuid.uuid4()))
            protocol.mock_wire_data.shared_config = WireProtocolData.replace_xml_attribute_value(
                protocol.mock_wire_data.shared_config, "Deployment", "name", str(uuid.uuid4()))

            protocol.client.update_goal_state()

            self.assertEqual(protocol.client.get_goal_state().xml_text, goal_state)
            self.assertEqual(protocol.client.get_shared_conf().xml_text, shared_conf)

            self.assertEqual(protocol.client.get_host_plugin().container_id, container_id)
            self.assertEqual(protocol.client.get_host_plugin().role_config_name, role_config_name)

    def test_forced_update_should_update_the_goal_state_and_the_host_plugin_when_the_incarnation_does_not_change(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.client.get_host_plugin()

            # The container id, role config name and shared config can change without the incarnation changing
            incarnation = protocol.client.get_goal_state().incarnation
            new_container_id = str(uuid.uuid4())
            new_role_config_name = str(uuid.uuid4())
            new_shared_conf = WireProtocolData.replace_xml_attribute_value(
                protocol.mock_wire_data.shared_config, "Deployment", "name", str(uuid.uuid4()))

            protocol.mock_wire_data.set_container_id(new_container_id)
            protocol.mock_wire_data.set_role_config_name(new_role_config_name)
            protocol.mock_wire_data.shared_config = new_shared_conf

            protocol.client.update_goal_state(forced=True)

            self.assertEqual(protocol.client.get_goal_state().incarnation, incarnation)
            self.assertEqual(protocol.client.get_shared_conf().xml_text, new_shared_conf)

            self.assertEqual(protocol.client.get_host_plugin().container_id, new_container_id)
            self.assertEqual(protocol.client.get_host_plugin().role_config_name, new_role_config_name)
# pylint: enable=too-many-public-methods

class TryUpdateGoalStateTestCase(HttpRequestPredicates, AgentTestCase):
    """
    Tests for WireClient.try_update_goal_state()
    """
    def test_it_should_return_true_on_success(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            self.assertTrue(protocol.client.try_update_goal_state(), "try_update_goal_state should have succeeded")

    def test_it_should_return_false_on_failure(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            def http_get_handler(url, *_, **__):
                if self.is_goal_state_request(url):
                    return HttpError('Exception to fake an error retrieving the goal state')
                return None

            protocol.set_http_handlers(http_get_handler=http_get_handler)

            self.assertFalse(protocol.client.try_update_goal_state(), "try_update_goal_state should have failed")

    def test_it_should_log_errors_only_when_the_error_state_changes(self): # pylint: disable=too-many-locals
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            def http_get_handler(url, *_, **__):
                if self.is_goal_state_request(url):
                    if fail_goal_state_request:
                        return HttpError('Exception to fake an error retrieving the goal state')
                return None

            protocol.set_http_handlers(http_get_handler=http_get_handler)

            @contextlib.contextmanager
            def create_log_and_telemetry_mocks():
                with patch("azurelinuxagent.common.protocol.wire.logger", autospec=True) as logger_patcher:
                    with patch("azurelinuxagent.common.protocol.wire.add_event") as add_event_patcher:
                        yield logger_patcher, add_event_patcher

            calls_to_strings = lambda calls: (str(c) for c in calls)
            filter_calls = lambda calls, regex=None: (c for c in calls_to_strings(calls) if regex is None or re.match(regex, c))
            logger_calls = lambda regex=None: [m for m in filter_calls(logger.method_calls, regex)] # pylint: disable=used-before-assignment,unnecessary-comprehension
            warnings = lambda: logger_calls(r'call.warn\(.*An error occurred while retrieving the goal state.*')
            periodic_warnings = lambda: logger_calls(r'call.periodic_warn\(.*Attempts to retrieve the goal state are failing.*')
            success_messages = lambda: logger_calls(r'call.info\(.*Retrieving the goal state recovered from previous errors.*')
            telemetry_calls = lambda regex=None: [m for m in filter_calls(add_event.mock_calls, regex)] # pylint: disable=used-before-assignment,unnecessary-comprehension
            goal_state_events = lambda: telemetry_calls(r".*op='FetchGoalState'.*")

            #
            # Initially calls to retrieve the goal state are successful...
            #
            fail_goal_state_request = False
            with create_log_and_telemetry_mocks() as (logger, add_event):
                protocol.client.try_update_goal_state()

                lc = logger_calls() # pylint: disable=invalid-name
                self.assertTrue(len(lc) == 0, "A successful call should not produce any log messages: [{0}]".format(lc))

                tc = telemetry_calls() # pylint: disable=invalid-name
                self.assertTrue(len(tc) == 0, "A successful call should not produce any telemetry events: [{0}]".format(tc))

            #
            # ... then an error happens...
            #
            fail_goal_state_request = True
            with create_log_and_telemetry_mocks() as (logger, add_event):
                protocol.client.try_update_goal_state()

                w = warnings() # pylint: disable=invalid-name
                pw = periodic_warnings() # pylint: disable=invalid-name
                self.assertEqual(len(w), 1, "A failure should have produced a warning: [{0}]".format(w))
                self.assertEqual(len(pw), 1, "A failure should have produced a periodic warning: [{0}]".format(pw))

                gs = goal_state_events() # pylint: disable=invalid-name
                self.assertTrue(len(gs) == 1 and 'is_success=False' in gs[0], "A failure should produce a telemetry event (success=false): [{0}]".format(gs))

            #
            # ... and errors continue happening...
            #
            with create_log_and_telemetry_mocks() as (logger, add_event):
                protocol.client.try_update_goal_state()
                protocol.client.try_update_goal_state()
                protocol.client.try_update_goal_state()

                w = warnings() # pylint: disable=invalid-name
                pw = periodic_warnings() # pylint: disable=invalid-name
                self.assertTrue(len(w) == 0, "Subsequent failures should not produce warnings: [{0}]".format(w))
                self.assertEqual(len(pw), 3, "Subsequent failures should produce periodic warnings: [{0}]".format(pw))

                tc = telemetry_calls() # pylint: disable=invalid-name
                self.assertTrue(len(tc) == 0, "Subsequent failures should not produce any telemetry events: [{0}]".format(tc))

            #
            # ... until we finally succeed
            #
            fail_goal_state_request = False
            with create_log_and_telemetry_mocks() as (logger, add_event):
                protocol.client.try_update_goal_state()

                s = success_messages() # pylint: disable=invalid-name
                w = warnings() # pylint: disable=invalid-name
                pw = periodic_warnings() # pylint: disable=invalid-name
                self.assertEqual(len(s), 1, "Recovering after failures should have produced an info message: [{0}]".format(s))
                self.assertTrue(len(w) == 0 and len(pw) == 0, "Recovering after failures should have not produced any warnings: [{0}] [{1}]".format(w, pw))

                gs = goal_state_events() # pylint: disable=invalid-name
                self.assertTrue(len(gs) == 1 and 'is_success=True' in gs[0], "Recovering after failures should produce a telemetry event (success=true): [{0}]".format(gs))


class UpdateHostPluginFromGoalStateTestCase(AgentTestCase):
    """
    Tests for WireClient.update_host_plugin_from_goal_state()
    """

    def test_it_should_update_the_host_plugin_with_or_without_incarnation_changes(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.client.get_host_plugin()

            # the behavior should be the same whether the incarnation changes or not
            for incarnation_change in [True, False]:
                protocol.mock_wire_data.reload()  # start each iteration of the test with fresh mock data

                new_container_id = str(uuid.uuid4())
                new_role_config_name = str(uuid.uuid4())

                goal_state_xml_text = protocol.mock_wire_data.goal_state
                shared_conf_xml_text = protocol.mock_wire_data.shared_config

                if incarnation_change:
                    protocol.mock_wire_data.set_incarnation(str(uuid.uuid4()))

                protocol.mock_wire_data.set_container_id(new_container_id)
                protocol.mock_wire_data.set_role_config_name(new_role_config_name)
                protocol.mock_wire_data.shared_config = WireProtocolData.replace_xml_attribute_value(
                    protocol.mock_wire_data.shared_config, "Deployment", "name", str(uuid.uuid4()))

                protocol.client.update_host_plugin_from_goal_state()

                self.assertEqual(protocol.client.get_host_plugin().container_id, new_container_id)
                self.assertEqual(protocol.client.get_host_plugin().role_config_name, new_role_config_name)

                # it should not update the goal state
                self.assertEqual(protocol.client.get_goal_state().xml_text, goal_state_xml_text)
                self.assertEqual(protocol.client.get_shared_conf().xml_text, shared_conf_xml_text)


class MockResponse: # pylint: disable=too-few-public-methods
    def __init__(self, body, status_code):
        self.body = body
        self.status = status_code

    def read(self, *_):
        return self.body


if __name__ == '__main__':
    unittest.main()
