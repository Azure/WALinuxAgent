# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

import contextlib
import datetime
import glob
import os
import re
import subprocess
import shutil
import time

from azurelinuxagent.common import conf
from azurelinuxagent.common.future import httpclient, urlparse, UTC
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateSource, GoalStateChannel
from azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config import ExtensionsGoalStateFromExtensionsConfig
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import ExtensionsGoalStateFromVmSettings
from azurelinuxagent.common.protocol import hostplugin
from azurelinuxagent.common.protocol.goal_state import GoalState, _GET_GOAL_STATE_MAX_ATTEMPTS, GoalStateProperties
from azurelinuxagent.common.exception import ProtocolError
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.archive import ARCHIVE_DIRECTORY_NAME
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.protocol.restapi import ExtensionRequestedState
from tests.lib.mock_wire_protocol import mock_wire_protocol, MockHttpResponse
from tests.lib import wire_protocol_data
from tests.lib.http_request_predicates import HttpRequestPredicates
from tests.lib.tools import AgentTestCase, patch, load_data


class GoalStateTestCase(AgentTestCase, HttpRequestPredicates):
    def test_it_should_use_vm_settings_by_default(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            protocol.mock_wire_data.set_etag(888)
            extensions_goal_state = GoalState(protocol.client).extensions_goal_state
            self.assertTrue(
                isinstance(extensions_goal_state, ExtensionsGoalStateFromVmSettings),
                'The extensions goal state should have been created from the vmSettings (got: {0})'.format(type(extensions_goal_state)))

    def _assert_is_extensions_goal_state_from_extensions_config(self, extensions_goal_state):
        self.assertTrue(
            isinstance(extensions_goal_state, ExtensionsGoalStateFromExtensionsConfig),
            'The extensions goal state should have been created from the extensionsConfig (got: {0})'.format(type(extensions_goal_state)))

    def test_it_should_use_extensions_config_when_fast_track_is_disabled(self):
        with patch("azurelinuxagent.common.conf.get_enable_fast_track", return_value=False):
            with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
                self._assert_is_extensions_goal_state_from_extensions_config(GoalState(protocol.client).extensions_goal_state)

    def test_it_should_use_extensions_config_when_fast_track_is_not_supported(self):
        def http_get_handler(url, *_, **__):
            if self.is_host_plugin_vm_settings_request(url):
                return MockHttpResponse(httpclient.NOT_FOUND)
            return None

        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS, http_get_handler=http_get_handler) as protocol:
            self._assert_is_extensions_goal_state_from_extensions_config(GoalState(protocol.client).extensions_goal_state)

    def test_it_should_use_extensions_config_when_the_host_ga_plugin_version_is_not_supported(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-unsupported_version.json"

        with mock_wire_protocol(data_file) as protocol:
            self._assert_is_extensions_goal_state_from_extensions_config(GoalState(protocol.client).extensions_goal_state)

    def test_it_should_retry_get_vm_settings_on_resource_gone_error(self):
        # Requests to the hostgaplugin incude the Container ID and the RoleConfigName as headers; when the hostgaplugin returns GONE (HTTP status 410) the agent
        # needs to get a new goal state and retry the request with updated values for the Container ID and RoleConfigName headers.
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            # Do not mock the vmSettings request at the level of azurelinuxagent.common.utils.restutil.http_request. The GONE status is handled
            # in the internal _http_request, which we mock below.
            protocol.do_not_mock = lambda method, url: method == "GET" and self.is_host_plugin_vm_settings_request(url)

            request_headers = []  # we expect a retry with new headers and use this array to persist the headers of each request

            def http_get_vm_settings(_method, _host, _relative_url, _timeout, **kwargs):
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
                protocol.client.update_goal_state()

            self.assertEqual(2, len(request_headers), "We expected 2 requests for vmSettings: the original request and the retry request")
            self.assertEqual("GET_VM_SETTINGS_TEST_CONTAINER_ID", request_headers[1][hostplugin._HEADER_CONTAINER_ID], "The retry request did not include the expected header for the ContainerId")
            self.assertEqual("GET_VM_SETTINGS_TEST_ROLE_CONFIG_NAME", request_headers[1][hostplugin._HEADER_HOST_CONFIG_NAME], "The retry request did not include the expected header for the RoleConfigName")

    def test_fetch_goal_state_should_raise_on_incomplete_goal_state(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:
            protocol.mock_wire_data.data_files = wire_protocol_data.DATA_FILE_NOOP_GS
            protocol.mock_wire_data.reload()
            protocol.mock_wire_data.set_incarnation(2)

            with patch('time.sleep') as mock_sleep:
                with self.assertRaises(ProtocolError):
                    GoalState(protocol.client)
                self.assertEqual(_GET_GOAL_STATE_MAX_ATTEMPTS, mock_sleep.call_count, "Unexpected number of retries")

    def test_fetching_the_goal_state_should_save_the_shared_config(self):
        # SharedConfig.xml is used by other components (Azsec and Singularity/HPC Infiniband); verify that we do not delete it
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            _ = GoalState(protocol.client)

            shared_config = os.path.join(conf.get_lib_dir(), 'SharedConfig.xml')
            self.assertTrue(os.path.exists(shared_config), "{0} should have been created".format(shared_config))

    def test_fetching_the_goal_state_should_save_the_goal_state_to_the_history_directory(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            protocol.mock_wire_data.set_incarnation(999)
            protocol.mock_wire_data.set_etag(888)

            _ = GoalState(protocol.client, save_to_history=True)

            self._assert_directory_contents(
                self._find_history_subdirectory("999-888"),
                ["GoalState.xml", "ExtensionsConfig.xml", "VmSettings.json", "Certificates.json", "SharedConfig.xml", "HostingEnvironmentConfig.xml"])

    @staticmethod
    def _get_history_directory():
        return os.path.join(conf.get_lib_dir(), ARCHIVE_DIRECTORY_NAME)

    def _find_history_subdirectory(self, tag):
        matches = glob.glob(os.path.join(self._get_history_directory(), "*_{0}".format(tag)))
        self.assertTrue(len(matches) == 1, "Expected one history directory for tag {0}. Got: {1}".format(tag, matches))
        return matches[0]

    def _assert_directory_contents(self, directory, expected_files):
        actual_files = os.listdir(directory)

        expected_files.sort()
        actual_files.sort()

        self.assertEqual(expected_files, actual_files, "The expected files were not saved to {0}".format(directory))

    def test_update_should_create_new_history_subdirectories(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            protocol.mock_wire_data.set_incarnation(123)
            protocol.mock_wire_data.set_etag(654)

            goal_state = GoalState(protocol.client, save_to_history=True)
            self._assert_directory_contents(
                self._find_history_subdirectory("123-654"),
                ["GoalState.xml", "ExtensionsConfig.xml", "VmSettings.json",  "Certificates.json", "SharedConfig.xml", "HostingEnvironmentConfig.xml"])

            def http_get_handler(url, *_, **__):
                if HttpRequestPredicates.is_host_plugin_vm_settings_request(url):
                    return MockHttpResponse(status=httpclient.NOT_MODIFIED)
                return None

            protocol.mock_wire_data.set_incarnation(234)
            protocol.set_http_handlers(http_get_handler=http_get_handler)
            goal_state.update()
            self._assert_directory_contents(
                self._find_history_subdirectory("234-654"),
                ["GoalState.xml", "ExtensionsConfig.xml",  "Certificates.json", "SharedConfig.xml", "HostingEnvironmentConfig.xml"])

            protocol.mock_wire_data.set_etag(987)
            protocol.set_http_handlers(http_get_handler=None)
            goal_state.update()
            self._assert_directory_contents(
                self._find_history_subdirectory("234-987"), ["VmSettings.json"])

    def test_it_should_redact_extensions_config(self):
        data_file = wire_protocol_data.DATA_FILE_IN_VM_ARTIFACTS_PROFILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_redact.xml"
        with mock_wire_protocol(data_file, detect_protocol=False) as protocol:
            protocol.mock_wire_data.set_incarnation(888)  # set the incarnation to a known value that we can use to find the history directory

            goal_state = GoalState(protocol.client, save_to_history=True)

            if goal_state.extensions_goal_state.source != GoalStateSource.Fabric:
                raise Exception("The test goal state should be Fabric (it is {0})".format(goal_state.extensions_goal_state.source))

            protected_settings = [s.protectedSettings for s in [e.settings[0] for e in goal_state.extensions_goal_state.extensions]]
            if len(protected_settings) == 0:
                raise Exception("The test goal state does not include any protected settings")

            history_directory = self._find_history_subdirectory("888")
            extensions_config = os.path.join(history_directory, "ExtensionsConfig.xml")
            with open(extensions_config, "r") as f:
                history_contents = f.read()

            vmap_blob = re.sub(r'(?s)(.*<InVMArtifactsProfileBlob.*>)(.*)(</InVMArtifactsProfileBlob>.*)', r'\2', goal_state.extensions_goal_state._text)
            query = urlparse(vmap_blob).query
            redacted = vmap_blob.replace(query, "***REDACTED***")
            self.assertNotIn(query, history_contents, "The VMAP query string was not redacted from the history")
            self.assertNotIn(vmap_blob, history_contents, "The VMAP URL was not redacted in the history")
            self.assertIn(redacted, history_contents, "Could not find the redacted VMAP URL in the history")

            status_blob = re.sub(r'(?s)(.*<StatusUploadBlob.*>)(.*)(</StatusUploadBlob>.*)', r'\2', goal_state.extensions_goal_state._text)
            query = urlparse(status_blob).query
            redacted = status_blob.replace(query, "***REDACTED***")
            self.assertNotIn(query, history_contents, "The Status query string was not redacted from the history")
            self.assertNotIn(status_blob, history_contents, "The Status URL was not redacted in the history")
            self.assertIn(redacted, history_contents, "Could not find the redacted Status URL in the history")

            for s in protected_settings:
                self.assertNotIn(s, history_contents, "The protected settings were not redacted from the history")
            matches = re.findall(r'"protectedSettings"\s*:\s*"\*\*\*REDACTED\*\*\*"', history_contents)
            self.assertEqual(len(matches), len(protected_settings),
                "Could not find the expected number of redacted settings in {0}.\nExpected {1}.\n{2}".format(extensions_config, len(protected_settings), history_contents))

    def test_it_should_redact_vm_settings(self):
        # NOTE: vm_settings-redact_formatted.json is the same as vm_settings-redact.json, but formatted for easier reading
        for test_file in ["hostgaplugin/vm_settings-redact.json", "hostgaplugin/vm_settings-redact_formatted.json"]:
            data_file = wire_protocol_data.DATA_FILE_IN_VM_ARTIFACTS_PROFILE.copy()
            data_file["vm_settings"] = test_file
            data_file["ETag"] = "123"
            with mock_wire_protocol(data_file, detect_protocol=False) as protocol:
                goal_state = GoalState(protocol.client, save_to_history=True)

                if goal_state.extensions_goal_state.source != GoalStateSource.FastTrack:
                    raise Exception("The test goal state should be FastTrack (it is {0}) [test: {1}]".format(goal_state.extensions_goal_state.source, test_file))

                protected_settings = [s.protectedSettings for s in [e.settings[0] for e in goal_state.extensions_goal_state.extensions]]
                if len(protected_settings) == 0:
                    raise Exception("The test goal state does not include any protected settings [test: {0}]".format(test_file))

                history_directory = self._find_history_subdirectory("*-123")
                vm_settings = os.path.join(history_directory, "VmSettings.json")
                with open(vm_settings, "r") as f:
                    history_contents = f.read()

                status_blob = goal_state.extensions_goal_state.status_upload_blob
                query = urlparse(status_blob).query
                redacted = status_blob.replace(query, "***REDACTED***")
                self.assertNotIn(query, history_contents, "The Status query string was not redacted from the history [test: {0}]".format(test_file))
                self.assertNotIn(status_blob, history_contents, "The Status URL was not redacted in the history [test: {0}]".format(test_file))
                self.assertIn(redacted, history_contents, "Could not find the redacted Status URL in the history [test: {0}]".format(test_file))

                for s in protected_settings:
                    self.assertNotIn(s, history_contents, "The protected settings were not redacted from the history [test: {0}]".format(test_file))

                matches = re.findall(r'"protectedSettings"\s*:\s*"\*\*\*REDACTED\*\*\*"', history_contents)
                self.assertEqual(len(matches), len(protected_settings),
                    "Could not find the expected number of redacted settings in {0} [test {1}].\nExpected {2}.\n{3}".format(vm_settings, test_file, len(protected_settings), history_contents))

            shutil.rmtree(history_directory)  # clean up the history directory in-between test cases to avoid stale history files

    def test_it_should_save_vm_settings_on_parse_errors(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            invalid_vm_settings_file = "hostgaplugin/vm_settings-parse_error.json"
            data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
            data_file["vm_settings"] = invalid_vm_settings_file
            protocol.mock_wire_data = wire_protocol_data.WireProtocolData(data_file)

            with self.assertRaises(ProtocolError):  # the parsing error will cause an exception
                _ = GoalState(protocol.client)

            # Do an extra call to update the goal state; this should save the vmsettings to the history directory
            # only once (self._find_history_subdirectory asserts 1 single match)
            time.sleep(0.1)  # add a short delay to ensure that a new timestamp would be saved in the history folder
            protocol.mock_wire_data.set_etag(888)
            with self.assertRaises(ProtocolError):
                _ = GoalState(protocol.client)

            history_directory = self._find_history_subdirectory("888")

            vm_settings_file = os.path.join(history_directory, "VmSettings.json")
            self.assertTrue(os.path.exists(vm_settings_file), "{0} was not saved".format(vm_settings_file))

            expected = load_data(invalid_vm_settings_file)
            actual = fileutil.read_file(vm_settings_file)

            self.assertEqual(expected, actual, "The vmSettings were not saved correctly")

    def test_should_not_save_to_the_history_by_default(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            _ = GoalState(protocol.client)  # omit the save_to_history parameter
            history = self._get_history_directory()
            self.assertFalse(os.path.exists(history), "The history directory not should have been created")

    @staticmethod
    @contextlib.contextmanager
    def _create_protocol_ws_and_hgap_in_sync():
        """
        Creates a mock protocol in which the HostGAPlugin and the WireServer are in sync, both of them returning
        the same Fabric goal state.
        """
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()

        with mock_wire_protocol(data_file) as protocol:
            timestamp = datetime.datetime.now(UTC)
            incarnation = '111'
            etag = '111111'
            protocol.mock_wire_data.set_incarnation(incarnation, timestamp=timestamp)
            protocol.mock_wire_data.set_etag(etag, timestamp=timestamp)
            protocol.mock_wire_data.set_vm_settings_source(GoalStateSource.Fabric)

            # Do a few checks on the mock data to ensure we catch changes in internal implementations
            # that may invalidate this setup.
            vm_settings, _ = protocol.client.get_host_plugin().fetch_vm_settings()
            if vm_settings.etag != etag:
                raise Exception("The HostGAPlugin is not in sync. Expected ETag {0}. Got {1}".format(etag, vm_settings.etag))
            if vm_settings.source != GoalStateSource.Fabric:
                raise Exception("The HostGAPlugin should be returning a Fabric goal state. Got {0}".format(vm_settings.source))

            goal_state = GoalState(protocol.client)
            if goal_state.incarnation != incarnation:
                raise Exception("The WireServer is not in sync. Expected incarnation {0}. Got {1}".format(incarnation, goal_state.incarnation))

            if goal_state.extensions_goal_state.correlation_id != vm_settings.correlation_id:
                raise Exception(
                    "The correlation ID in the WireServer and HostGAPlugin are not in sync. WS: {0} HGAP: {1}".format(
                        goal_state.extensions_goal_state.correlation_id, vm_settings.correlation_id))

            yield protocol

    def _assert_goal_state(self, goal_state, goal_state_id, channel=None, source=None):
        self.assertIn(goal_state_id, goal_state.extensions_goal_state.id, "Incorrect Goal State ID")
        if channel is not None:
            self.assertEqual(channel, goal_state.extensions_goal_state.channel, "Incorrect Goal State channel")
        if source is not None:
            self.assertEqual(source, goal_state.extensions_goal_state.source, "Incorrect Goal State source")


    def test_it_should_ignore_fabric_goal_states_from_the_host_ga_plugin(self):
        with GoalStateTestCase._create_protocol_ws_and_hgap_in_sync() as protocol:
            #
            # Verify __init__()
            #
            expected_incarnation = '111'  # test setup initializes to this value
            timestamp = datetime.datetime.now(UTC) + datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_etag('22222', timestamp)

            goal_state = GoalState(protocol.client)

            self._assert_goal_state(goal_state, expected_incarnation, channel=GoalStateChannel.WireServer)

            #
            # Verify update()
            #
            timestamp += datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_etag('333333', timestamp)

            goal_state.update()

            self._assert_goal_state(goal_state, expected_incarnation, channel=GoalStateChannel.WireServer)

    def test_it_should_use_fast_track_goal_states_from_the_host_ga_plugin(self):
        with GoalStateTestCase._create_protocol_ws_and_hgap_in_sync() as protocol:
            protocol.mock_wire_data.set_vm_settings_source(GoalStateSource.FastTrack)

            #
            # Verify __init__()
            #
            expected_etag = '22222'
            timestamp = datetime.datetime.now(UTC) + datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_etag(expected_etag, timestamp)

            goal_state = GoalState(protocol.client)

            self._assert_goal_state(goal_state, expected_etag, channel=GoalStateChannel.HostGAPlugin)

            #
            # Verify update()
            #
            expected_etag = '333333'
            timestamp += datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_etag(expected_etag, timestamp)

            goal_state.update()

            self._assert_goal_state(goal_state, expected_etag, channel=GoalStateChannel.HostGAPlugin)

    def test_it_should_use_the_most_recent_goal_state(self):
        with GoalStateTestCase._create_protocol_ws_and_hgap_in_sync() as protocol:
            goal_state = GoalState(protocol.client)

            # The most recent goal state is FastTrack
            timestamp = datetime.datetime.now(UTC) + datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_vm_settings_source(GoalStateSource.FastTrack)
            protocol.mock_wire_data.set_etag('222222', timestamp)

            goal_state.update()

            self._assert_goal_state(goal_state, '222222', channel=GoalStateChannel.HostGAPlugin, source=GoalStateSource.FastTrack)

            # The most recent goal state is Fabric
            timestamp += datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_incarnation('222', timestamp)

            goal_state.update()

            self._assert_goal_state(goal_state, '222', channel=GoalStateChannel.WireServer, source=GoalStateSource.Fabric)

            # The most recent goal state is Fabric, but it is coming from the HostGAPlugin (should be ignored)
            timestamp += datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_vm_settings_source(GoalStateSource.Fabric)
            protocol.mock_wire_data.set_etag('333333', timestamp)

            goal_state.update()

            self._assert_goal_state(goal_state, '222', channel=GoalStateChannel.WireServer, source=GoalStateSource.Fabric)

    def test_it_should_mark_outdated_goal_states(self):
        with GoalStateTestCase._create_protocol_ws_and_hgap_in_sync() as protocol:
            goal_state = GoalState(protocol.client)
            initial_incarnation = goal_state.incarnation
            initial_timestamp = goal_state.extensions_goal_state.created_on_timestamp

            # Make the most recent goal state FastTrack
            timestamp = datetime.datetime.now(UTC) + datetime.timedelta(seconds=15)
            protocol.mock_wire_data.set_vm_settings_source(GoalStateSource.FastTrack)
            protocol.mock_wire_data.set_etag('444444', timestamp)

            goal_state.update()

            # Update the goal state after the HGAP plugin stops supporting vmSettings
            def http_get_handler(url, *_, **__):
                if self.is_host_plugin_vm_settings_request(url):
                    return MockHttpResponse(httpclient.NOT_FOUND)
                return None

            protocol.set_http_handlers(http_get_handler=http_get_handler)

            goal_state.update()

            self._assert_goal_state(goal_state, initial_incarnation, channel=GoalStateChannel.WireServer, source=GoalStateSource.Fabric)
            self.assertEqual(initial_timestamp, goal_state.extensions_goal_state.created_on_timestamp, "The timestamp of the updated goal state is incorrect")
            self.assertTrue(goal_state.extensions_goal_state.is_outdated, "The updated goal state should be marked as outdated")

    def test_it_should_download_certs_on_a_new_fast_track_goal_state(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()

        with mock_wire_protocol(data_file) as protocol:
            goal_state = GoalState(protocol.client)

            cert = "F6ABAA61098A301EBB8A571C3C7CF77F355F7FA9"
            crt_path = os.path.join(self.tmp_dir, cert + ".crt")
            prv_path = os.path.join(self.tmp_dir, cert + ".prv")

            # Check that crt and prv files are downloaded after processing goal state
            self.assertTrue(os.path.isfile(crt_path))
            self.assertTrue(os.path.isfile(prv_path))

            # Remove .crt file
            os.remove(crt_path)
            if os.path.isfile(crt_path):
                raise Exception("{0}.crt was not removed.".format(cert))

            # Update goal state and check that .crt was downloaded
            protocol.mock_wire_data.set_etag(888)
            goal_state.update()
            self.assertTrue(os.path.isfile(crt_path))

    def test_it_should_download_certs_on_a_new_fabric_goal_state(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()

        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_vm_settings_source(GoalStateSource.Fabric)
            goal_state = GoalState(protocol.client)

            cert = "F6ABAA61098A301EBB8A571C3C7CF77F355F7FA9"
            crt_path = os.path.join(self.tmp_dir, cert + ".crt")
            prv_path = os.path.join(self.tmp_dir, cert + ".prv")

            # Check that crt and prv files are downloaded after processing goal state
            self.assertTrue(os.path.isfile(crt_path))
            self.assertTrue(os.path.isfile(prv_path))

            # Remove .crt file
            os.remove(crt_path)
            if os.path.isfile(crt_path):
                raise Exception("{0}.crt was not removed.".format(cert))

            # Update goal state and check that .crt was downloaded
            protocol.mock_wire_data.set_incarnation(999)
            goal_state.update()
            self.assertTrue(os.path.isfile(crt_path))

    def test_goal_state_should_contain_empty_certs_when_it_is_fails_to_decrypt_certs(self):
        #  This test simulates that scenario by mocking the goal state request is fabric, and it contains incorrect certs(incorrect-certs.xml)

        data_file = "wire/incorrect-certs.xml"

        def http_get_handler(url, *_, **__):
            if HttpRequestPredicates.is_certificates_request(url):
                http_get_handler.certificate_requests += 1
                data = load_data(data_file)
                return MockHttpResponse(status=200, body=data.encode('utf-8'))
            return None

        http_get_handler.certificate_requests = 0

        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:
            protocol.set_http_handlers(http_get_handler=http_get_handler)
            protocol.mock_wire_data.reset_call_counts()

            goal_state = GoalState(protocol.client)

            expected_file = os.path.join(conf.get_lib_dir(), "Certificates.pem")
            self.assertTrue(os.path.isfile(expected_file), "{0} was not created".format(expected_file))
            self.assertEqual(0, len(goal_state.certs.summary), "Certificates should be empty")
            self.assertEqual(2, http_get_handler.certificate_requests, "There should have been exactly 2 requests for the goal state certificates")  # 1 for the initial request, 1 for the retry with an older cypher

    def test_goal_state_should_try_legacy_cypher_and_then_fail_when_no_cyphers_are_supported_by_the_wireserver(self):
        cyphers = []
        def http_get_handler(url, *_, **kwargs):
            if HttpRequestPredicates.is_certificates_request(url):
                cypher = kwargs["headers"].get("x-ms-cipher-name")
                if cypher is None:
                    raise Exception("x-ms-cipher-name header is missing from the Certificates request")
                cyphers.append(cypher)
                return MockHttpResponse(status=400, body="unsupported cypher: {0}".format(cypher).encode('utf-8'))
            return None

        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:
            with patch("azurelinuxagent.common.event.LogEvent.error") as log_error_patch:
                protocol.set_http_handlers(http_get_handler=http_get_handler)
                goal_state = GoalState(protocol.client)

        log_error_args, _ = log_error_patch.call_args

        self.assertEqual(cyphers, ["AES128_CBC", "DES_EDE3_CBC"], "There should have been 2 requests for the goal state certificates (AES128_CBC and DES_EDE3_CBC)")
        self.assertEqual(log_error_args[0], "GoalStateCertificates", "An error fetching the goal state Certificates should have been reported")
        self.assertEqual(0, len(goal_state.certs.summary), "Certificates should be empty")
        self.assertFalse(os.path.exists(os.path.join(conf.get_lib_dir(), "Certificates.pfx")), "The Certificates.pfx file should not have been created")

    def test_goal_state_should_try_legacy_cypher_and_then_fail_when_no_cyphers_are_supported_by_openssl(self):
        cyphers = []
        def http_get_handler(url, *_, **kwargs):
            if HttpRequestPredicates.is_certificates_request(url):
                cyphers.append(kwargs["headers"].get("x-ms-cipher-name"))
            return None

        original_popen = subprocess.Popen
        openssl = conf.get_openssl_cmd()
        decrypt_calls = []
        def mock_fail_popen(command, *args, **kwargs):
            if len(command) > 3 and command[0:3] == [openssl, "cms", "-decrypt"]:
                decrypt_calls.append(command)
                command[1] = "fake_openssl_command"  # force an error on the openssl to simulate a decryption failure
            return original_popen(command, *args, **kwargs)

        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:
            protocol.set_http_handlers(http_get_handler=http_get_handler)
            with patch("azurelinuxagent.common.event.LogEvent.error") as log_error_patch:
                with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", mock_fail_popen):
                    goal_state = GoalState(protocol.client)

        log_error_args, _ = log_error_patch.call_args

        self.assertEqual(cyphers, ["AES128_CBC", "DES_EDE3_CBC"], "There should have been 2 requests for the goal state certificates (AES128_CBC and DES_EDE3_CBC)")
        self.assertEqual(2, len(decrypt_calls), "There should have been 2 calls to 'openssl cms -decrypt'")
        self.assertEqual(log_error_args[0], "GoalStateCertificates", "An error fetching the goal state Certificates should have been reported")
        self.assertEqual(0, len(goal_state.certs.summary), "Certificates should be empty")
        self.assertFalse(os.path.exists(os.path.join(conf.get_lib_dir(), "Certificates.pfx")), "The Certificates.pfx file should not have been created")

    def test_goal_state_should_try_without_and_with_mac_verification_then_fail_when_the_pfx_cannot_be_converted(self):
        original_popen = subprocess.Popen
        openssl = conf.get_openssl_cmd()
        nomacver = []

        def mock_fail_popen(command, *args, **kwargs):
            if len(command) > 2 and command[0] == openssl and command[1] == "pkcs12":
                nomacver.append("-nomacver" in command)
                # force an error on the openssl to simulate the conversion failure
                command[1] = "fake_openssl_command"
            return original_popen(command, *args, **kwargs)


        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:
            with patch("azurelinuxagent.common.event.LogEvent.error") as log_error_patch:
                with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", mock_fail_popen):
                    goal_state = GoalState(protocol.client)

        log_error_args, _ = log_error_patch.call_args

        self.assertEqual(nomacver, [True, False], "There should have been 2 attempts to parse the PFX (with and without -nomacver)")
        self.assertEqual(log_error_args[0], "GoalStateCertificates", "An error fetching the goal state Certificates should have been reported")
        self.assertEqual(0, len(goal_state.certs.summary), "Certificates should be empty")

    def test_it_should_raise_when_goal_state_properties_not_initialized(self):
        with GoalStateTestCase._create_protocol_ws_and_hgap_in_sync() as protocol:
            goal_state = GoalState(
                protocol.client,
                goal_state_properties=~GoalStateProperties.All)

            goal_state.update()

            with self.assertRaises(ProtocolError) as context:
                _ = goal_state.container_id

            expected_message = "ContainerId is not in goal state properties"
            self.assertIn(expected_message, str(context.exception))

            with self.assertRaises(ProtocolError) as context:
                _ = goal_state.role_config_name

            expected_message = "RoleConfig is not in goal state properties"
            self.assertIn(expected_message, str(context.exception))

            with self.assertRaises(ProtocolError) as context:
                _ = goal_state.role_instance_id

            expected_message = "RoleInstanceId is not in goal state properties"
            self.assertIn(expected_message, str(context.exception))

            with self.assertRaises(ProtocolError) as context:
                _ = goal_state.extensions_goal_state

            expected_message = "ExtensionsGoalState is not in goal state properties"
            self.assertIn(expected_message, str(context.exception))

            with self.assertRaises(ProtocolError) as context:
                _ = goal_state.hosting_env

            expected_message = "HostingEnvironment is not in goal state properties"
            self.assertIn(expected_message, str(context.exception))

            with self.assertRaises(ProtocolError) as context:
                _ = goal_state.certs

            expected_message = "Certificates is not in goal state properties"
            self.assertIn(expected_message, str(context.exception))

            with self.assertRaises(ProtocolError) as context:
                _ = goal_state.shared_conf

            expected_message = "SharedConfig is not in goal state properties"
            self.assertIn(expected_message, str(context.exception))

            with self.assertRaises(ProtocolError) as context:
                _ = goal_state.remote_access

            expected_message = "RemoteAccessInfo is not in goal state properties"
            self.assertIn(expected_message, str(context.exception))

            goal_state = GoalState(
                protocol.client,
                goal_state_properties=GoalStateProperties.All & ~GoalStateProperties.HostingEnv)

            goal_state.update()

            _ = goal_state.container_id, goal_state.role_instance_id, goal_state.role_config_name, \
                goal_state.extensions_goal_state, goal_state.certs, goal_state.shared_conf, goal_state.remote_access

            with self.assertRaises(ProtocolError) as context:
                _ = goal_state.hosting_env

            expected_message = "HostingEnvironment is not in goal state properties"
            self.assertIn(expected_message, str(context.exception))

    def test_it_should_pick_up_most_recent_goal_state_when_the_tenant_certificate_is_rotated(self):
        #
        # During rotation of the tenant certificate a new Fabric goal state is generated; however, neither the vmSettings nor the extensionsConfig change. In that case, the agent should pick up the most recent of
        # vmSettings and extensionsConfig. The test data below comes from an actual incident, in which the tenant certificate was rotated on incarnation 4.
        #
        goal_state_data = wire_protocol_data.DATA_FILE.copy()
        goal_state_data.update({
            "goal_state": "tenant_certificate_rotation/GoalState-incarnation-3.xml",
            "certs": "tenant_certificate_rotation/Certificates-incarnation-3.xml",
            "ext_conf": "tenant_certificate_rotation/ExtensionsConfig-incarnation-3.xml",
            "vm_settings": "tenant_certificate_rotation/VmSettings-etag-10016425637754081485.json",
            "trans_cert": "tenant_certificate_rotation/TransportCert.pem",
            "trans_prv": "tenant_certificate_rotation/TransportPrivate.pem",
            "ETag": "10016425637754081485"
        })

        with mock_wire_protocol(goal_state_data) as protocol:
            # Verify the test setup. Protocol detection should initialize the goal state to incarnation 3
            goal_state = protocol.client.get_goal_state()
            if goal_state.incarnation != '3':
                raise Exception("Incarnation 3 should have been picked up during protocol detection. Got {0}".format(goal_state.incarnation))
            if goal_state.extensions_goal_state.source != "FastTrack":
                raise Exception("The Fast Track goal state should have picked up on initialization, since it is the most recent goal state. Got {0}".format(goal_state.extensions_goal_state.source))
            if all(c["thumbprint"] != "F6ABAA61098A301EBB8A571C3C7CF77F355F7FA9" for c in goal_state.certs.summary):
                raise Exception("The tenant certificate on incarnation 3, 'F6ABAA61098A301EBB8A571C3C7CF77F355F7FA9', is missing from the goal state. Certificates: {0}".format(goal_state.certs.summary))

            # Update the test data to incarnation 4, which has the newly rotated tenant certificate
            goal_state_data.update({
                "goal_state": "tenant_certificate_rotation/GoalState-incarnation-4.xml",
                "certs": "tenant_certificate_rotation/Certificates-incarnation-4.xml",
                "ext_conf": "tenant_certificate_rotation/ExtensionsConfig-incarnation-4.xml",
            })
            protocol.mock_wire_data.reload()

            # The incarnation in the test data changed, but not the ETag; even so, the goal state should pick up the Fast Track extensions, since that is the most recent goal state. This needs to be
            # verified for 3 scenarios: initializing a new goal state, force-updating the goal state, and updating the goal state.
            def assert_fast_track(test_case):
                self.assertEqual('4', goal_state.incarnation, "Incarnation 4 should have been picked up on {0}".format(test_case))
                self.assertEqual("FastTrack", goal_state.extensions_goal_state.source, "The Fast Track goal state should have picked up on {0}, since it is the most recent goal state".format(test_case))
                self.assertTrue(
                    any(c["thumbprint"] == "C0EDFF1B408001B0FD14F8F615E567F7833822D0" for c in goal_state.certs.summary),
                    "The tenant certificate on incarnation 4, 'C0EDFF1B408001B0FD14F8F615E567F7833822D0', is missing from the goal state. Certificates: {0}".format(goal_state.certs.summary))

            goal_state = GoalState(protocol.client)
            assert_fast_track("initialization")

            goal_state.update(force_update=True)
            assert_fast_track("force-update")

            goal_state.update()
            assert_fast_track("update")

    def test_it_should_send_telemetry_for_extension_signed_or_unsigned_if_validation_enabled(self):
        with patch("azurelinuxagent.ga.confidential_vm_info.ConfidentialVMInfo.is_confidential_vm", return_value=True):
            with patch("azurelinuxagent.common.protocol.goal_state.signature_validation_enabled", return_value=True):
                # Should send telemetry for signed extension for extensionsConfig goal state
                with patch("azurelinuxagent.common.protocol.goal_state.add_event") as add_event:
                    with mock_wire_protocol(wire_protocol_data.DATA_FILE):
                        telemetry = [kw for _, kw in add_event.call_args_list if kw['op'] == WALAEventOperation.ExtensionSigned and kw['is_success']]
                        self.assertEqual(1, len(telemetry), "Should send telemetry for signed extension in extensionsConfig goal state")

                # Should send telemetry for unsigned extension in extensionsConfig goal state
                ext_conf_data_file = wire_protocol_data.DATA_FILE.copy()
                ext_conf_data_file["ext_conf"] = "wire/ext_conf-no_encoded_signature.xml"
                with patch("azurelinuxagent.common.protocol.goal_state.add_event") as add_event:
                    with mock_wire_protocol(ext_conf_data_file):
                        telemetry = [kw for _, kw in add_event.call_args_list if kw['op'] == WALAEventOperation.ExtensionSigned and not kw['is_success']]
                        self.assertEqual(1, len(telemetry), "Should send telemetry for unsigned extension in extensionsConfig goal state")

                # Should send telemetry for both signed and unsigned extensions in fast track goal state
                vm_settings_data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
                # This vm settings extensions goal state has 1 extension with encodedSignature (AzureMonitorLinuxAgent), and
                # 1 extension without encodedSignature (AzureSecurityLinuxAgent). The HGAP version supports signature.
                vm_settings_data_file["vm_settings"] = "hostgaplugin/vm_settings-supported_hgap_version_for_signature.json"
                with patch("azurelinuxagent.common.protocol.goal_state.add_event") as add_event:
                    with mock_wire_protocol(vm_settings_data_file):
                        signed_telemetry = [kw for _, kw in add_event.call_args_list if kw['op'] == WALAEventOperation.ExtensionSigned and kw['is_success']]
                        self.assertEqual(1, len(signed_telemetry), "Should send telemetry for signed extension in fast track goal state")
                        unsigned_telemetry = [kw for _, kw in add_event.call_args_list if kw['op'] == WALAEventOperation.ExtensionSigned and not kw['is_success']]
                        self.assertEqual(1, len(unsigned_telemetry), "Should send telemetry for unsigned extensions in fast track goal state")

    def test_it_should_not_send_telemetry_for_extension_signature_for_uninstall(self):
        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf-no_encoded_signature.xml"

        with mock_wire_protocol(data_file) as protocol:
            with patch("azurelinuxagent.common.protocol.goal_state.add_event") as add_event:
                # Generate a new mock goal state to uninstall the extension - increment the incarnation
                protocol.mock_wire_data.set_incarnation(2)
                protocol.mock_wire_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)
                goal_state = GoalState(protocol.client)
                goal_state.update()

            telemetry = [kw for _, kw in add_event.call_args_list if kw['op'] == WALAEventOperation.ExtensionSigned and not kw['is_success']]
            self.assertEqual(0, len(telemetry), "Should not send telemetry for unsigned extension when requested operation is uninstall")

    def test_it_should_not_send_telemetry_for_unsupported_hgap_version(self):
        # This vm settings extensions goal state has a version of HGAP that does not support the 'encodedSignature'
        # property, and it includes an extension with no signature. Telemetry should not be sent, in this case.
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-unsupported_hgap_version_for_signature.json"
        with patch("azurelinuxagent.common.protocol.goal_state.add_event") as add_event:
            with mock_wire_protocol(data_file):
                unsigned_telemetry = [kw for _, kw in add_event.call_args_list if
                                      kw['op'] == WALAEventOperation.ExtensionSigned and not kw['is_success']]
                self.assertEqual(0, len(unsigned_telemetry),
                                 "Should not send telemetry for unsigned extensions in fast track goal state if HGAP version does not support signature")
