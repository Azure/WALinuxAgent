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

import contextlib
import json
import os
import socket
import time
import unittest
import uuid

from azurelinuxagent.common.agent_supported_feature import SupportedFeatureNames, get_supported_feature_by_name, \
    get_agent_supported_features_list_for_crp
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import ResourceGoneError, ProtocolError, \
    ExtensionDownloadError, HttpError
from azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config import ExtensionsGoalStateFromExtensionsConfig
from azurelinuxagent.common.protocol.goal_state import GoalStateProperties
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.protocol.wire import WireProtocol, WireClient, \
    StatusBlob, VMStatus
from azurelinuxagent.common.telemetryevent import GuestAgentExtensionEventsSchema, \
    TelemetryEventParam, TelemetryEvent
from azurelinuxagent.common.utils import restutil
from azurelinuxagent.common.version import CURRENT_VERSION, DISTRO_NAME, DISTRO_VERSION
from azurelinuxagent.ga.exthandlers import get_exthandlers_handler
from tests.ga.test_monitor import random_generator
from tests.protocol import mockwiredata
from tests.protocol.mocks import mock_wire_protocol, MockHttpResponse
from tests.protocol.HttpRequestPredicates import HttpRequestPredicates
from tests.protocol.mockwiredata import DATA_FILE_NO_EXT, DATA_FILE
from tests.protocol.mockwiredata import WireProtocolData
from tests.tools import patch, AgentTestCase, load_bin_data

data_with_bom = b'\xef\xbb\xbfhehe'
testurl = 'http://foo'
testtype = 'BlockBlob'
WIRESERVER_URL = '168.63.129.16'


def get_event(message, duration=30000, evt_type="", is_internal=False, is_success=True,
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
def create_mock_protocol():
    with mock_wire_protocol(DATA_FILE_NO_EXT) as protocol:
        yield protocol


@patch("time.sleep")
@patch("azurelinuxagent.common.protocol.wire.CryptUtil")
@patch("azurelinuxagent.common.protocol.healthservice.HealthService._report")
class TestWireProtocol(AgentTestCase, HttpRequestPredicates):

    def setUp(self):
        super(TestWireProtocol, self).setUp()
        HostPluginProtocol.is_default_channel = False

    def _test_getters(self, test_data, certsMustBePresent, __, MockCryptUtil, _):
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        with patch.object(restutil, 'http_get', test_data.mock_http_get):
            protocol = WireProtocol(WIRESERVER_URL)
            protocol.detect()
            protocol.get_vminfo()
            protocol.get_certs()
            ext_handlers = protocol.get_goal_state().extensions_goal_state.extensions
            for ext_handler in ext_handlers:
                protocol.get_goal_state().fetch_extension_manifest(ext_handler.name, ext_handler.manifest_uris)

            crt1 = os.path.join(self.tmp_dir,
                                '38B85D88F03D1A8E1C671EB169274C09BC4D4703.crt')
            crt2 = os.path.join(self.tmp_dir,
                                'BD447EF71C3ADDF7C837E84D630F3FAC22CCD22F.crt')
            prv2 = os.path.join(self.tmp_dir,
                                'BD447EF71C3ADDF7C837E84D630F3FAC22CCD22F.prv')
            if certsMustBePresent:
                self.assertTrue(os.path.isfile(crt1))
                self.assertTrue(os.path.isfile(crt2))
                self.assertTrue(os.path.isfile(prv2))
            else:
                self.assertFalse(os.path.isfile(crt1))
                self.assertFalse(os.path.isfile(crt2))
                self.assertFalse(os.path.isfile(prv2))
            self.assertEqual("1", protocol.get_goal_state().incarnation)

    @staticmethod
    def _get_telemetry_events_generator(event_list):
        def _yield_events():
            for telemetry_event in event_list:
                yield telemetry_event

        return _yield_events()

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
        self.assertEqual(1, test_data.call_counts["hostingEnvironmentConfig"])
        self.assertEqual(1, patch_report.call_count)

    def test_call_storage_kwargs(self, *args):  # pylint: disable=unused-argument
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

    def test_status_blob_parsing(self, *args):  # pylint: disable=unused-argument
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state
            self.assertIsInstance(extensions_goal_state, ExtensionsGoalStateFromExtensionsConfig)
            self.assertEqual(extensions_goal_state.status_upload_blob,
                             'https://test.blob.core.windows.net/vhds/test-cs12.test-cs12.test-cs12.status?'
                             'sr=b&sp=rw&se=9999-01-01&sk=key1&sv=2014-02-14&'
                             'sig=hfRh7gzUE7sUtYwke78IOlZOrTRCYvkec4hGZ9zZzXo')
            self.assertEqual(protocol.get_goal_state().extensions_goal_state.status_upload_blob_type, u'BlockBlob')

    def test_get_host_ga_plugin(self, *args):  # pylint: disable=unused-argument
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            host_plugin = protocol.client.get_host_plugin()
            goal_state = protocol.client.get_goal_state()
            self.assertEqual(goal_state.container_id, host_plugin.container_id)
            self.assertEqual(goal_state.role_config_name, host_plugin.role_config_name)

    def test_upload_status_blob_should_use_the_host_channel_by_default(self, *_):
        def http_put_handler(url, *_, **__):  # pylint: disable=inconsistent-return-statements
            if protocol.get_endpoint() in url and url.endswith('/status'):
                return MockHttpResponse(200)

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_put_handler=http_put_handler) as protocol:
            HostPluginProtocol.is_default_channel = False
            protocol.client.status_blob.vm_status = VMStatus(message="Ready", status="Ready")

            protocol.client.upload_status_blob()

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 1, 'Expected one post request to the host: [{0}]'.format(urls))

    def test_upload_status_blob_host_ga_plugin(self, *_):
        with create_mock_protocol() as protocol:
            protocol.client.status_blob.vm_status = VMStatus(message="Ready", status="Ready")

            with patch.object(HostPluginProtocol, "ensure_initialized", return_value=True):
                with patch.object(StatusBlob, "upload", return_value=False) as patch_default_upload:
                    with patch.object(HostPluginProtocol, "_put_block_blob_status") as patch_http:
                        HostPluginProtocol.is_default_channel = False
                        protocol.client.upload_status_blob()
                        patch_default_upload.assert_not_called()
                        patch_http.assert_called_once_with(testurl, protocol.client.status_blob)
                        self.assertFalse(HostPluginProtocol.is_default_channel)

    def test_upload_status_blob_reports_prepare_error(self, *_):
        with create_mock_protocol() as protocol:
            protocol.client.status_blob.vm_status = VMStatus(message="Ready", status="Ready")

            with patch.object(StatusBlob, "prepare", side_effect=Exception) as mock_prepare:
                self.assertRaises(ProtocolError, protocol.client.upload_status_blob)
                self.assertEqual(1, mock_prepare.call_count)

    def test_get_in_vm_artifacts_profile_blob_not_available(self, *_):
        data_file = mockwiredata.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_in_vm_empty_artifacts_profile.xml"

        with mock_wire_protocol(data_file) as protocol:
            self.assertFalse(protocol.get_goal_state().extensions_goal_state.on_hold)

    def test_it_should_set_on_hold_to_false_when_the_in_vm_artifacts_profile_is_not_valid(self, *_):
        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_ARTIFACTS_PROFILE) as protocol:
            extensions_on_hold = protocol.get_goal_state().extensions_goal_state.on_hold
            self.assertTrue(extensions_on_hold, "Extensions should be on hold in the test data")

            def http_get_handler(url, *_, **kwargs):
                if self.is_in_vm_artifacts_profile_request(url) or self.is_host_plugin_in_vm_artifacts_profile_request(url, kwargs):
                    return mock_response
                return None
            protocol.set_http_handlers(http_get_handler=http_get_handler)

            mock_response = MockHttpResponse(200, body=None)
            protocol.client.reset_goal_state()
            extensions_on_hold = protocol.get_goal_state().extensions_goal_state.on_hold
            self.assertFalse(extensions_on_hold, "Extensions should not be on hold when the in-vm artifacts profile response body is None")

            mock_response = MockHttpResponse(200, '   '.encode('utf-8'))
            protocol.client.reset_goal_state()
            extensions_on_hold = protocol.get_goal_state().extensions_goal_state.on_hold
            self.assertFalse(extensions_on_hold, "Extensions should not be on hold when the in-vm artifacts profile response is an empty string")

            mock_response = MockHttpResponse(200, '{ }'.encode('utf-8'))
            protocol.client.reset_goal_state()
            extensions_on_hold = protocol.get_goal_state().extensions_goal_state.on_hold
            self.assertFalse(extensions_on_hold, "Extensions should not be on hold when the in-vm artifacts profile response is an empty json object")

            with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.add_event") as add_event:
                mock_response = MockHttpResponse(200, 'invalid json'.encode('utf-8'))
                protocol.client.reset_goal_state()

                extensions_on_hold = protocol.get_goal_state().extensions_goal_state.on_hold
                self.assertFalse(extensions_on_hold, "Extensions should not be on hold when the in-vm artifacts profile response is not valid json")

                events = [kwargs for _, kwargs in add_event.call_args_list if kwargs['op'] == WALAEventOperation.ArtifactsProfileBlob]
                self.assertEqual(1, len(events), "Expected 1 event for operation ArtifactsProfileBlob. Got: {0}".format(events))
                self.assertFalse(events[0]['is_success'], "Expected ArtifactsProfileBlob's success to be False")
                self.assertTrue("Can't parse the artifacts profile blob" in events[0]['message'], "Expected 'Can't parse the artifacts profile blob as the reason for the operation failure. Got: {0}".format(events[0]['message']))

    @patch("socket.gethostname", return_value="hostname")
    @patch("time.gmtime", return_value=time.localtime(1485543256))
    def test_report_vm_status(self, *args):  # pylint: disable=unused-argument
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

        supported_features = []
        for _, feature in get_agent_supported_features_list_for_crp().items():
            supported_features.append(
                {
                    "Key": feature.name,
                    "Value": feature.version
                }
            )

        v1_vm_status = {
            'version': '1.1',
            'timestampUTC': timestamp,
            'aggregateStatus': v1_agg_status,
            'guestOSInfo': v1_ga_guest_info,
            'supportedFeatures': supported_features
        }
        self.assertEqual(json.dumps(v1_vm_status), actual.to_json())

    def test_it_should_report_supported_features_in_status_blob_if_supported(self, *_):
        with mock_wire_protocol(DATA_FILE) as protocol:

            def mock_http_put(url, *args, **__):
                if not HttpRequestPredicates.is_host_plugin_status_request(url):
                    # Skip reading the HostGA request data as its encoded
                    protocol.aggregate_status = json.loads(args[0])

            protocol.aggregate_status = {}
            protocol.set_http_handlers(http_put_handler=mock_http_put)
            exthandlers_handler = get_exthandlers_handler(protocol)

            with patch("azurelinuxagent.common.agent_supported_feature._MultiConfigFeature.is_supported", True):
                with patch("azurelinuxagent.common.agent_supported_feature._GAVersioningGovernanceFeature.is_supported", True):
                    exthandlers_handler.run()
                    exthandlers_handler.report_ext_handlers_status()

                    self.assertIsNotNone(protocol.aggregate_status, "Aggregate status should not be None")
                    self.assertIn("supportedFeatures", protocol.aggregate_status, "supported features not reported")
                    multi_config_feature = get_supported_feature_by_name(SupportedFeatureNames.MultiConfig)
                    found = False
                    for feature in protocol.aggregate_status['supportedFeatures']:
                        if feature['Key'] == multi_config_feature.name and feature['Value'] == multi_config_feature.version:
                            found = True
                            break
                    self.assertTrue(found, "Multi-config name should be present in supportedFeatures")

                    ga_versioning_feature = get_supported_feature_by_name(SupportedFeatureNames.GAVersioningGovernance)
                    found = False
                    for feature in protocol.aggregate_status['supportedFeatures']:
                        if feature['Key'] == ga_versioning_feature.name and feature['Value'] == ga_versioning_feature.version:
                            found = True
                            break
                    self.assertTrue(found, "ga versioning name should be present in supportedFeatures")

            # Feature should not be reported if not present
            with patch("azurelinuxagent.common.agent_supported_feature._MultiConfigFeature.is_supported", False):
                with patch("azurelinuxagent.common.agent_supported_feature._GAVersioningGovernanceFeature.is_supported", False):

                    exthandlers_handler.run()
                    exthandlers_handler.report_ext_handlers_status()

                    self.assertIsNotNone(protocol.aggregate_status, "Aggregate status should not be None")
                    if "supportedFeatures" not in protocol.aggregate_status:
                        # In the case Multi-config and GA Versioning only features available, 'supportedFeatures' should not be
                        # reported in the status blob as its not supported as of now.
                        # Asserting no other feature was available to report back to crp
                        self.assertEqual(0, len(get_agent_supported_features_list_for_crp()),
                                         "supportedFeatures should be available if there are more features")
                        return

                    # If there are other features available, confirm MultiConfig and GA versioning was not reported
                    multi_config_feature = get_supported_feature_by_name(SupportedFeatureNames.MultiConfig)
                    found = False
                    for feature in protocol.aggregate_status['supportedFeatures']:
                        if feature['Key'] == multi_config_feature.name and feature['Value'] == multi_config_feature.version:
                            found = True
                            break
                    self.assertFalse(found, "Multi-config name should not be present in supportedFeatures")

                    ga_versioning_feature = get_supported_feature_by_name(SupportedFeatureNames.GAVersioningGovernance)
                    found = False
                    for feature in protocol.aggregate_status['supportedFeatures']:
                        if feature['Key'] == ga_versioning_feature.name and feature['Value'] == ga_versioning_feature.version:
                            found = True
                            break
                    self.assertFalse(found, "ga versioning name should not be present in supportedFeatures")

    @patch("azurelinuxagent.common.utils.restutil.http_request")
    def test_send_encoded_event(self, mock_http_request, *args):
        mock_http_request.return_value = MockHttpResponse(200)

        event_str = u'a test string'
        client = WireProtocol(WIRESERVER_URL).client
        client.send_encoded_event("foo", event_str.encode('utf-8'))

        first_call = mock_http_request.call_args_list[0]
        args, kwargs = first_call
        method, url, body_received, timeout = args  # pylint: disable=unused-variable
        headers = kwargs['headers']

        # the headers should include utf-8 encoding...
        self.assertTrue("utf-8" in headers['Content-Type'])
        # the body is encoded, decode and check for equality
        self.assertIn(event_str, body_received.decode('utf-8'))

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_encoded_event")
    def test_report_event_small_event(self, patch_send_event, *args):  # pylint: disable=unused-argument
        event_list = []
        client = WireProtocol(WIRESERVER_URL).client

        event_str = random_generator(10)
        event_list.append(get_event(message=event_str))

        event_str = random_generator(100)
        event_list.append(get_event(message=event_str))

        event_str = random_generator(1000)
        event_list.append(get_event(message=event_str))

        event_str = random_generator(10000)
        event_list.append(get_event(message=event_str))

        client.report_event(self._get_telemetry_events_generator(event_list))

        # It merges the messages into one message
        self.assertEqual(patch_send_event.call_count, 1)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_encoded_event")
    def test_report_event_multiple_events_to_fill_buffer(self, patch_send_event, *args):  # pylint: disable=unused-argument
        event_list = []
        client = WireProtocol(WIRESERVER_URL).client

        event_str = random_generator(2 ** 15)
        event_list.append(get_event(message=event_str))
        event_list.append(get_event(message=event_str))

        client.report_event(self._get_telemetry_events_generator(event_list))

        # It merges the messages into one message
        self.assertEqual(patch_send_event.call_count, 2)

    @patch("azurelinuxagent.common.protocol.wire.WireClient.send_encoded_event")
    def test_report_event_large_event(self, patch_send_event, *args):  # pylint: disable=unused-argument
        event_list = []
        event_str = random_generator(2 ** 18)
        event_list.append(get_event(message=event_str))
        client = WireProtocol(WIRESERVER_URL).client
        client.report_event(self._get_telemetry_events_generator(event_list))

        self.assertEqual(patch_send_event.call_count, 0)


class TestWireClient(HttpRequestPredicates, AgentTestCase):
    def test_get_ext_conf_without_extensions_should_retrieve_vmagent_manifests_info(self, *args):  # pylint: disable=unused-argument
        # Basic test for extensions_goal_state when extensions are not present in the config. The test verifies that
        # extensions_goal_state fetches the correct data by comparing the returned data with the test data provided the
        # mock_wire_protocol.
        with mock_wire_protocol(mockwiredata.DATA_FILE_NO_EXT) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state

            ext_handlers_names = [ext_handler.name for ext_handler in extensions_goal_state.extensions]
            self.assertEqual(0, len(extensions_goal_state.extensions),
                             "Unexpected number of extension handlers in the extension config: [{0}]".format(ext_handlers_names))
            vmagent_families = [manifest.name for manifest in extensions_goal_state.agent_families]
            self.assertEqual(0, len(extensions_goal_state.agent_families),
                             "Unexpected number of vmagent manifests in the extension config: [{0}]".format(vmagent_families))
            self.assertFalse(extensions_goal_state.on_hold,
                              "Extensions On Hold is expected to be False")

    def test_get_ext_conf_with_extensions_should_retrieve_ext_handlers_and_vmagent_manifests_info(self):
        # Basic test for extensions_goal_state when extensions are present in the config. The test verifies that extensions_goal_state
        # fetches the correct data by comparing the returned data with the test data provided the mock_wire_protocol.
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state

            ext_handlers_names = [ext_handler.name for ext_handler in extensions_goal_state.extensions]
            self.assertEqual(1, len(extensions_goal_state.extensions),
                             "Unexpected number of extension handlers in the extension config: [{0}]".format(ext_handlers_names))
            vmagent_families = [manifest.name for manifest in extensions_goal_state.agent_families]
            self.assertEqual(2, len(extensions_goal_state.agent_families),
                             "Unexpected number of vmagent manifests in the extension config: [{0}]".format(vmagent_families))
            self.assertEqual("https://test.blob.core.windows.net/vhds/test-cs12.test-cs12.test-cs12.status?sr=b&sp=rw"
                             "&se=9999-01-01&sk=key1&sv=2014-02-14&sig=hfRh7gzUE7sUtYwke78IOlZOrTRCYvkec4hGZ9zZzXo",
                             extensions_goal_state.status_upload_blob, "Unexpected value for status upload blob URI")
            self.assertEqual("BlockBlob", extensions_goal_state.status_upload_blob_type,
                             "Unexpected status upload blob type in the extension config")
            self.assertFalse(extensions_goal_state.on_hold,
                              "Extensions On Hold is expected to be False")

    def test_download_zip_package_should_expand_and_delete_the_package(self):
        extension_url = 'https://fake_host/fake_extension.zip'
        target_file = os.path.join(self.tmp_dir, 'fake_extension.zip')
        target_directory = os.path.join(self.tmp_dir, "fake_extension")

        def http_get_handler(url, *_, **__):
            if url == extension_url or self.is_host_plugin_extension_artifact_request(url):
                return MockHttpResponse(200, body=load_bin_data("ga/fake_extension.zip"))
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_get_handler=http_get_handler) as protocol:
            protocol.client.download_zip_package("extension package", [extension_url], target_file, target_directory, use_verify_header=False)

            self.assertTrue(os.path.exists(target_directory), "The extension package was not downloaded")
            self.assertFalse(os.path.exists(target_file), "The extension package was not deleted")

    def test_download_zip_package_should_not_invoke_host_channel_when_direct_channel_succeeds(self):
        extension_url = 'https://fake_host/fake_extension.zip'
        target_file = os.path.join(self.tmp_dir, 'fake_extension.zip')
        target_directory = os.path.join(self.tmp_dir, "fake_extension")

        def http_get_handler(url, *_, **__):
            if url == extension_url:
                return MockHttpResponse(200, body=load_bin_data("ga/fake_extension.zip"))
            if self.is_host_plugin_extension_artifact_request(url):
                self.fail('The host channel should not have been used')
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_get_handler=http_get_handler) as protocol:
            HostPluginProtocol.is_default_channel = False

            protocol.client.download_zip_package("extension package", [extension_url], target_file, target_directory, use_verify_header=False)

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 1, "Unexpected number of HTTP requests: [{0}]".format(urls))
            self.assertEqual(urls[0], extension_url, "The extension should have been downloaded over the direct channel")
            self.assertTrue(os.path.exists(target_directory), "The extension package was not downloaded")
            self.assertFalse(HostPluginProtocol.is_default_channel, "The host channel should not have been set as the default")

    def test_download_zip_package_should_use_host_channel_when_direct_channel_fails_and_set_host_as_default(self):
        extension_url = 'https://fake_host/fake_extension.zip'
        target_file = os.path.join(self.tmp_dir, 'fake_extension.zip')
        target_directory = os.path.join(self.tmp_dir, "fake_extension")

        def http_get_handler(url, *_, **kwargs):
            if url == extension_url:
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_extension_request(url, kwargs, extension_url):
                return MockHttpResponse(200, body=load_bin_data("ga/fake_extension.zip"))
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_get_handler=http_get_handler) as protocol:
            HostPluginProtocol.is_default_channel = False

            protocol.client.download_zip_package("extension package", [extension_url], target_file, target_directory, use_verify_header=False)

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 2, "Unexpected number of HTTP requests: [{0}]".format(urls))
            self.assertEqual(urls[0], extension_url, "The first attempt should have been over the direct channel")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The retry attempt should have been over the host channel")
            self.assertTrue(os.path.exists(target_directory), 'The extension package was not downloaded')
            self.assertTrue(HostPluginProtocol.is_default_channel, "The host channel should have been set as the default")

    def test_download_zip_package_should_retry_the_host_channel_after_refreshing_host_plugin(self):
        extension_url = 'https://fake_host/fake_extension.zip'
        target_file = os.path.join(self.tmp_dir, 'fake_extension.zip')
        target_directory = os.path.join(self.tmp_dir, "fake_extension")

        def http_get_handler(url, *_, **kwargs):
            if url == extension_url:
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_extension_request(url, kwargs, extension_url):
                # fake a stale goal state then succeed once the goal state has been refreshed
                if http_get_handler.goal_state_requests == 0:
                    http_get_handler.goal_state_requests += 1
                    return ResourceGoneError("Exception to fake a stale goal")
                return MockHttpResponse(200, body=load_bin_data("ga/fake_extension.zip"))
            if self.is_goal_state_request(url):
                protocol.track_url(url)  # track requests for the goal state
            return None
        http_get_handler.goal_state_requests = 0

        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            HostPluginProtocol.is_default_channel = False

            try:
                # initialization of the host plugin triggers a request for the goal state; do it here before we start tracking those requests.
                protocol.client.get_host_plugin()

                protocol.set_http_handlers(http_get_handler=http_get_handler)

                protocol.client.download_zip_package("extension package", [extension_url], target_file, target_directory, use_verify_header=False)

                urls = protocol.get_tracked_urls()
                self.assertEqual(len(urls), 4, "Unexpected number of HTTP requests: [{0}]".format(urls))
                self.assertEqual(urls[0], extension_url, "The first attempt should have been over the direct channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second attempt should have been over the host channel")
                self.assertTrue(self.is_goal_state_request(urls[2]), "The host channel should have been refreshed the goal state")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]), "The third attempt should have been over the host channel")
                self.assertTrue(os.path.exists(target_directory), 'The extension package was not downloaded')
                self.assertTrue(HostPluginProtocol.is_default_channel, "The host channel should have been set as the default")
            finally:
                HostPluginProtocol.is_default_channel = False

    def test_download_zip_package_should_not_change_default_channel_when_all_channels_fail(self):
        extension_url = 'https://fake_host/fake_extension.zip'
        target_file = os.path.join(self.tmp_dir, "fake_extension.zip")
        target_directory = os.path.join(self.tmp_dir, "fake_extension")

        def http_get_handler(url, *_, **kwargs):
            if url == extension_url or self.is_host_plugin_extension_request(url, kwargs, extension_url):
                return MockHttpResponse(status=404, body=b"content not found", reason="Not Found")
            if self.is_goal_state_request(url):
                protocol.track_url(url)  # keep track of goal state requests
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            HostPluginProtocol.is_default_channel = False

            # initialization of the host plugin triggers a request for the goal state; do it here before we start tracking those requests.
            protocol.client.get_host_plugin()

            protocol.set_http_handlers(http_get_handler=http_get_handler)

            with self.assertRaises(ExtensionDownloadError):
                protocol.client.download_zip_package("extension package", [extension_url], target_file, target_directory, use_verify_header=False)

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 2, "Unexpected number of HTTP requests: [{0}]".format(urls))
            self.assertEqual(urls[0], extension_url, "The first attempt should have been over the direct channel")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second attempt should have been over the host channel")
            self.assertFalse(os.path.exists(target_file), "The extension package was downloaded and it shouldn't have")
            self.assertFalse(HostPluginProtocol.is_default_channel, "The host channel should not have been set as the default")

    def test_invalid_zip_should_raise_an_error(self):
        extension_url = 'https://fake_host/fake_extension.zip'
        target_file = os.path.join(self.tmp_dir, "fake_extension.zip")
        target_directory = os.path.join(self.tmp_dir, "fake_extension")

        def http_get_handler(url, *_, **kwargs):
            if url == extension_url or self.is_host_plugin_extension_request(url, kwargs, extension_url):
                return MockHttpResponse(status=200, body=b"NOT A ZIP")
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.set_http_handlers(http_get_handler=http_get_handler)

            with self.assertRaises(ExtensionDownloadError):
                protocol.client.download_zip_package("extension package", [extension_url], target_file, target_directory, use_verify_header=False)

            self.assertFalse(os.path.exists(target_file), "The extension package should have been deleted")
            self.assertFalse(os.path.exists(target_directory), "The extension directory should not have been created")

    def test_fetch_manifest_should_not_invoke_host_channel_when_direct_channel_succeeds(self):
        manifest_url = 'https://fake_host/fake_manifest.xml'
        manifest_xml = '<?xml version="1.0" encoding="utf-8"?><PluginVersionManifest/>'

        def http_get_handler(url, *_, **__):
            if url == manifest_url:
                return MockHttpResponse(200, manifest_xml.encode('utf-8'))
            if url.endswith('/extensionArtifact'):
                self.fail('The Host GA Plugin should not have been invoked')
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_get_handler=http_get_handler) as protocol:
            HostPluginProtocol.is_default_channel = False

            manifest = protocol.client.fetch_manifest("test", [manifest_url], use_verify_header=False)

            urls = protocol.get_tracked_urls()
            self.assertEqual(manifest, manifest_xml, 'The expected manifest was not downloaded')
            self.assertEqual(len(urls), 1, "Unexpected number of HTTP requests: [{0}]".format(urls))
            self.assertEqual(urls[0], manifest_url, "The manifest should have been downloaded over the direct channel")
            self.assertFalse(HostPluginProtocol.is_default_channel, "The default channel should not have changed")

    def test_fetch_manifest_should_use_host_channel_when_direct_channel_fails_and_set_it_to_default(self):
        manifest_url = 'https://fake_host/fake_manifest.xml'
        manifest_xml = '<?xml version="1.0" encoding="utf-8"?><PluginVersionManifest/>'

        def http_get_handler(url, *_, **kwargs):
            if url == manifest_url:
                return ResourceGoneError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_extension_request(url, kwargs, manifest_url):
                return MockHttpResponse(200, body=manifest_xml.encode('utf-8'))
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE, http_get_handler=http_get_handler) as protocol:
            HostPluginProtocol.is_default_channel = False

            try:
                manifest = protocol.client.fetch_manifest("test", [manifest_url], use_verify_header=False)

                urls = protocol.get_tracked_urls()
                self.assertEqual(manifest, manifest_xml, 'The expected manifest was not downloaded')
                self.assertEqual(len(urls), 2, "Unexpected number of HTTP requests: [{0}]".format(urls))
                self.assertEqual(urls[0], manifest_url, "The first attempt should have been over the direct channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The retry should have been over the host channel")
                self.assertTrue(HostPluginProtocol.is_default_channel, "The host should have been set as the default channel")
            finally:
                HostPluginProtocol.is_default_channel = False  # Reset default channel

    def test_fetch_manifest_should_retry_the_host_channel_after_refreshing_the_host_plugin_and_set_the_host_as_default(self):
        manifest_url = 'https://fake_host/fake_manifest.xml'
        manifest_xml = '<?xml version="1.0" encoding="utf-8"?><PluginVersionManifest/>'

        def http_get_handler(url, *_, **kwargs):
            if url == manifest_url:
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_extension_request(url, kwargs, manifest_url):
                # fake a stale goal state then succeed once the goal state has been refreshed
                if http_get_handler.goal_state_requests == 0:
                    http_get_handler.goal_state_requests += 1
                    return ResourceGoneError("Exception to fake a stale goal state")
                return MockHttpResponse(200, manifest_xml.encode('utf-8'))
            elif self.is_goal_state_request(url):
                protocol.track_url(url)  # keep track of goal state requests
            return None
        http_get_handler.goal_state_requests = 0

        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            HostPluginProtocol.is_default_channel = False

            try:
                # initialization of the host plugin triggers a request for the goal state; do it here before we start tracking those requests.
                protocol.client.get_host_plugin()

                protocol.set_http_handlers(http_get_handler=http_get_handler)
                manifest = protocol.client.fetch_manifest("test", [manifest_url], use_verify_header=False)

                urls = protocol.get_tracked_urls()
                self.assertEqual(manifest, manifest_xml)
                self.assertEqual(len(urls), 4, "Unexpected number of HTTP requests: [{0}]".format(urls))
                self.assertEqual(urls[0], manifest_url, "The first attempt should have been over the direct channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second attempt should have been over the host channel")
                self.assertTrue(self.is_goal_state_request(urls[2]), "The host channel should have been refreshed the goal state")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]), "The third attempt should have been over the host channel")
                self.assertTrue(HostPluginProtocol.is_default_channel, "The host should have been set as the default channel")
            finally:
                HostPluginProtocol.is_default_channel = False  # Reset default channel

    def test_fetch_manifest_should_update_goal_state_and_not_change_default_channel_if_host_fails(self):
        manifest_url = 'https://fake_host/fake_manifest.xml'

        def http_get_handler(url, *_, **kwargs):
            if url == manifest_url or self.is_host_plugin_extension_request(url, kwargs, manifest_url):
                return ResourceGoneError("Exception to fake an error on either channel")
            elif self.is_goal_state_request(url):
                protocol.track_url(url)  # keep track of goal state requests
            return None

        # Everything fails. Goal state should have been updated and host channel should not have been set as default.
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            HostPluginProtocol.is_default_channel = False

            # initialization of the host plugin triggers a request for the goal state; do it here before we start
            # tracking those requests.
            protocol.client.get_host_plugin()

            protocol.set_http_handlers(http_get_handler=http_get_handler)

            with self.assertRaises(ExtensionDownloadError):
                protocol.client.fetch_manifest("test", [manifest_url], use_verify_header=False)

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 4, "Unexpected number of HTTP requests: [{0}]".format(urls))
            self.assertEqual(urls[0], manifest_url, "The first attempt should have been over the direct channel")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second attempt should have been over the host channel")
            self.assertTrue(self.is_goal_state_request(urls[2]), "The host channel should have been refreshed the goal state")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]), "The third attempt should have been over the host channel")
            self.assertFalse(HostPluginProtocol.is_default_channel, "The host should not have been set as the default channel")

            self.assertEqual(HostPluginProtocol.is_default_channel, False)

    def test_get_artifacts_profile_should_not_invoke_host_channel_when_direct_channel_succeeds(self):
        def http_get_handler(url, *_, **__):
            if self.is_in_vm_artifacts_profile_request(url):
                protocol.track_url(url)
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_ARTIFACTS_PROFILE) as protocol:
            protocol.set_http_handlers(http_get_handler=http_get_handler)
            HostPluginProtocol.is_default_channel = False

            protocol.client.reset_goal_state()

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 1, "Unexpected HTTP requests: [{0}]".format(urls))
            self.assertFalse(HostPluginProtocol.is_default_channel, "The host should not have been set as the default channel")

    def test_get_artifacts_profile_should_use_host_channel_when_direct_channel_fails(self):
        def http_get_handler(url, *_, **kwargs):
            if self.is_in_vm_artifacts_profile_request(url):
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_in_vm_artifacts_profile_request(url, kwargs):
                protocol.track_url(url)
            return None

        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_ARTIFACTS_PROFILE) as protocol:
            protocol.set_http_handlers(http_get_handler=http_get_handler)

            HostPluginProtocol.is_default_channel = False
            try:
                protocol.client.reset_goal_state()

                urls = protocol.get_tracked_urls()
                self.assertEqual(len(urls), 2, "Invalid number of requests: [{0}]".format(urls))
                self.assertTrue(self.is_in_vm_artifacts_profile_request(urls[0]), "The first request should have been over the direct channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second request should have been over the host channel")
                self.assertTrue(HostPluginProtocol.is_default_channel, "The default channel should have changed to the host")
            finally:
                HostPluginProtocol.is_default_channel = False

    def test_get_artifacts_profile_should_retry_the_host_channel_after_refreshing_the_host_plugin(self):
        def http_get_handler(url, *_, **kwargs):
            if self.is_in_vm_artifacts_profile_request(url):
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_in_vm_artifacts_profile_request(url, kwargs):
                if http_get_handler.host_plugin_calls == 0:
                    http_get_handler.host_plugin_calls += 1
                    return ResourceGoneError("Exception to fake a stale goal state")
                protocol.track_url(url)
            if self.is_goal_state_request(url) and http_get_handler.host_plugin_calls == 1:
                protocol.track_url(url)
            return None
        http_get_handler.host_plugin_calls = 0

        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_ARTIFACTS_PROFILE) as protocol:
            HostPluginProtocol.is_default_channel = False

            try:
                # initialization of the host plugin triggers a request for the goal state; do it here before we start tracking those requests.
                protocol.client.get_host_plugin()

                protocol.set_http_handlers(http_get_handler=http_get_handler)

                protocol.client.reset_goal_state()

                urls = protocol.get_tracked_urls()
                self.assertEqual(len(urls), 4, "Invalid number of requests: [{0}]".format(urls))
                self.assertTrue(self.is_in_vm_artifacts_profile_request(urls[0]), "The first request should have been over the direct channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second request should have been over the host channel")
                self.assertTrue(self.is_goal_state_request(urls[2]), "The goal state should have been refreshed before retrying the host channel")
                self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]), "The retry request should have been over the host channel")
                self.assertTrue(HostPluginProtocol.is_default_channel, "The default channel should have changed to the host")
            finally:
                HostPluginProtocol.is_default_channel = False

    def test_get_artifacts_profile_should_refresh_the_host_plugin_and_not_change_default_channel_if_host_plugin_fails(self):
        def http_get_handler(url, *_, **kwargs):
            if self.is_in_vm_artifacts_profile_request(url):
                return HttpError("Exception to fake an error on the direct channel")
            if self.is_host_plugin_in_vm_artifacts_profile_request(url, kwargs):
                http_get_handler.host_plugin_calls += 1
                return ResourceGoneError("Exception to fake a stale goal state")
            if self.is_goal_state_request(url) and http_get_handler.host_plugin_calls == 1:
                protocol.track_url(url)
            return None
        http_get_handler.host_plugin_calls = 0

        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_ARTIFACTS_PROFILE) as protocol:
            HostPluginProtocol.is_default_channel = False

            # initialization of the host plugin triggers a request for the goal state; do it here before we start tracking those requests.
            protocol.client.get_host_plugin()

            protocol.set_http_handlers(http_get_handler=http_get_handler)

            protocol.client.reset_goal_state()

            urls = protocol.get_tracked_urls()
            self.assertEqual(len(urls), 4, "Invalid number of requests: [{0}]".format(urls))
            self.assertTrue(self.is_in_vm_artifacts_profile_request(urls[0]), "The first request should have been over the direct channel")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[1]), "The second request should have been over the host channel")
            self.assertTrue(self.is_goal_state_request(urls[2]), "The goal state should have been refreshed before retrying the host channel")
            self.assertTrue(self.is_host_plugin_extension_artifact_request(urls[3]), "The retry request should have been over the host channel")
            self.assertFalse(HostPluginProtocol.is_default_channel, "The default channel should not have changed")

    @staticmethod
    def _set_and_fail_helper_channel_functions(fail_direct=False, fail_host=False):
        def direct_func(*_):
            direct_func.counter += 1
            if direct_func.fail:
                raise Exception("Direct channel failed")
            return "direct"

        def host_func(*_):
            host_func.counter += 1
            if host_func.fail:
                raise Exception("Host channel failed")
            return "host"

        direct_func.counter = 0
        direct_func.fail = fail_direct

        host_func.counter = 0
        host_func.fail = fail_host

        return direct_func, host_func

    def test_download_using_appropriate_channel_should_not_invoke_secondary_when_primary_channel_succeeds(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            # Scenario #1: Direct channel default
            HostPluginProtocol.is_default_channel = False

            direct_func, host_func = self._set_and_fail_helper_channel_functions()
            # Assert we're only calling the primary channel (direct) and that it succeeds.
            for iteration in range(5):
                ret = protocol.client._download_using_appropriate_channel(direct_func, host_func)
                self.assertEqual("direct", ret)
                self.assertEqual(iteration + 1, direct_func.counter)
                self.assertEqual(0, host_func.counter)
                self.assertFalse(HostPluginProtocol.is_default_channel)

            # Scenario #2: Host channel default
            HostPluginProtocol.is_default_channel = True
            direct_func, host_func = self._set_and_fail_helper_channel_functions()

            # Assert we're only calling the primary channel (host) and that it succeeds.
            for iteration in range(5):
                ret = protocol.client._download_using_appropriate_channel(direct_func, host_func)
                self.assertEqual("host", ret)
                self.assertEqual(0, direct_func.counter)
                self.assertEqual(iteration + 1, host_func.counter)
                self.assertTrue(HostPluginProtocol.is_default_channel)

    def test_download_using_appropriate_channel_should_not_change_default_channel_if_none_succeeds(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            # Scenario #1: Direct channel is default
            HostPluginProtocol.is_default_channel = False
            direct_func, host_func = self._set_and_fail_helper_channel_functions(fail_direct=True, fail_host=True)

            # Assert we keep trying both channels, but the default channel doesn't change
            for iteration in range(5):
                with self.assertRaises(HttpError):
                    protocol.client._download_using_appropriate_channel(direct_func, host_func)
                self.assertEqual(iteration + 1, direct_func.counter)
                self.assertEqual(iteration + 1, host_func.counter)
                self.assertFalse(HostPluginProtocol.is_default_channel)

            # Scenario #2: Host channel is default
            HostPluginProtocol.is_default_channel = True
            direct_func, host_func = self._set_and_fail_helper_channel_functions(fail_direct=True, fail_host=True)

            # Assert we keep trying both channels, but the default channel doesn't change
            for iteration in range(5):
                with self.assertRaises(HttpError):
                    protocol.client._download_using_appropriate_channel(direct_func, host_func)
                self.assertEqual(iteration + 1, direct_func.counter)
                self.assertEqual(iteration + 1, host_func.counter)
                self.assertTrue(HostPluginProtocol.is_default_channel)

    def test_download_using_appropriate_channel_should_change_default_channel_when_secondary_succeeds(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            # Scenario #1: Direct channel is default
            HostPluginProtocol.is_default_channel = False
            direct_func, host_func = self._set_and_fail_helper_channel_functions(fail_direct=True, fail_host=False)

            # Assert we've called both channels and the default channel changed
            ret = protocol.client._download_using_appropriate_channel(direct_func, host_func)
            self.assertEqual("host", ret)
            self.assertEqual(1, direct_func.counter)
            self.assertEqual(1, host_func.counter)
            self.assertTrue(HostPluginProtocol.is_default_channel)

            # If host keeps succeeding, assert we keep calling only that channel and not changing the default.
            for iteration in range(5):
                ret = protocol.client._download_using_appropriate_channel(direct_func, host_func)
                self.assertEqual("host", ret)
                self.assertEqual(1, direct_func.counter)
                self.assertEqual(1 + iteration + 1, host_func.counter)
                self.assertTrue(HostPluginProtocol.is_default_channel)

            # Scenario #2: Host channel is default
            HostPluginProtocol.is_default_channel = True
            direct_func, host_func = self._set_and_fail_helper_channel_functions(fail_direct=False, fail_host=True)

            # Assert we've called both channels and the default channel changed
            ret = protocol.client._download_using_appropriate_channel(direct_func, host_func)
            self.assertEqual("direct", ret)
            self.assertEqual(1, direct_func.counter)
            self.assertEqual(1, host_func.counter)
            self.assertFalse(HostPluginProtocol.is_default_channel)

            # If direct keeps succeeding, assert we keep calling only that channel and not changing the default.
            for iteration in range(5):
                ret = protocol.client._download_using_appropriate_channel(direct_func, host_func)
                self.assertEqual("direct", ret)
                self.assertEqual(1 + iteration + 1, direct_func.counter)
                self.assertEqual(1, host_func.counter)
                self.assertFalse(HostPluginProtocol.is_default_channel)


class UpdateGoalStateTestCase(HttpRequestPredicates, AgentTestCase):
    """
    Tests for WireClient.update_goal_state() and WireClient.reset_goal_state()
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
                new_sequence_number = 12345

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
                    protocol.client.reset_goal_state()
                else:
                    protocol.client.update_goal_state()

                sequence_number = protocol.get_goal_state().extensions_goal_state.extensions[0].settings[0].sequenceNumber

                self.assertEqual(protocol.client.get_goal_state().incarnation, new_incarnation)
                self.assertEqual(protocol.client.get_hosting_env().deployment_name, new_hosting_env_deployment_name)
                self.assertEqual(protocol.client.get_shared_conf().xml_text, new_shared_conf)
                self.assertEqual(sequence_number, new_sequence_number)
                self.assertEqual(len(protocol.client.get_certs().cert_list.certificates), 0)

                self.assertEqual(protocol.client.get_host_plugin().container_id, new_container_id)
                self.assertEqual(protocol.client.get_host_plugin().role_config_name, new_role_config_name)

    def test_non_forced_update_should_not_update_the_goal_state_but_should_update_the_host_plugin_when_the_incarnation_does_not_change(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.client.get_host_plugin()

            # The container id, role config name and shared config can change without the incarnation changing; capture the initial
            # goal state and then change those fields.
            container_id = protocol.client.get_goal_state().container_id
            role_config_name = protocol.client.get_goal_state().role_config_name

            new_container_id = str(uuid.uuid4())
            new_role_config_name = str(uuid.uuid4())
            protocol.mock_wire_data.set_container_id(new_container_id)
            protocol.mock_wire_data.set_role_config_name(new_role_config_name)
            protocol.mock_wire_data.shared_config = WireProtocolData.replace_xml_attribute_value(
                protocol.mock_wire_data.shared_config, "Deployment", "name", str(uuid.uuid4()))

            protocol.client.update_goal_state()

            self.assertEqual(protocol.client.get_goal_state().container_id, container_id)
            self.assertEqual(protocol.client.get_goal_state().role_config_name, role_config_name)

            self.assertEqual(protocol.client.get_host_plugin().container_id, new_container_id)
            self.assertEqual(protocol.client.get_host_plugin().role_config_name, new_role_config_name)

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

            protocol.client.reset_goal_state()

            self.assertEqual(protocol.client.get_goal_state().incarnation, incarnation)
            self.assertEqual(protocol.client.get_shared_conf().xml_text, new_shared_conf)

            self.assertEqual(protocol.client.get_host_plugin().container_id, new_container_id)
            self.assertEqual(protocol.client.get_host_plugin().role_config_name, new_role_config_name)

    def test_reset_should_init_provided_goal_state_properties(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.client.reset_goal_state(goal_state_properties=GoalStateProperties.All & ~GoalStateProperties.ExtensionsGoalState)

            with self.assertRaises(ProtocolError) as context:
                _ = protocol.client.get_certs()

            expected_message = "Certificates is not in goal state properties"
            self.assertIn(expected_message, str(context.exception))

    def test_reset_should_init_the_goal_state(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            new_container_id = str(uuid.uuid4())
            new_role_config_name = str(uuid.uuid4())
            protocol.mock_wire_data.set_container_id(new_container_id)
            protocol.mock_wire_data.set_role_config_name(new_role_config_name)

            protocol.client.reset_goal_state()

            self.assertEqual(protocol.client.get_goal_state().container_id, new_container_id)
            self.assertEqual(protocol.client.get_goal_state().role_config_name, new_role_config_name)


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

                if incarnation_change:
                    protocol.mock_wire_data.set_incarnation(str(uuid.uuid4()))

                protocol.mock_wire_data.set_container_id(new_container_id)
                protocol.mock_wire_data.set_role_config_name(new_role_config_name)
                protocol.mock_wire_data.shared_config = WireProtocolData.replace_xml_attribute_value(
                    protocol.mock_wire_data.shared_config, "Deployment", "name", str(uuid.uuid4()))

                protocol.client.update_host_plugin_from_goal_state()

                self.assertEqual(protocol.client.get_host_plugin().container_id, new_container_id)
                self.assertEqual(protocol.client.get_host_plugin().role_config_name, new_role_config_name)


if __name__ == '__main__':
    unittest.main()
