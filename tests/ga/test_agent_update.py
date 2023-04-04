import contextlib
import json
import os

from azurelinuxagent.common import conf
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException
from azurelinuxagent.common.future import ustr, httpclient
from azurelinuxagent.common.protocol.restapi import VMAgentUpdateStatuses

from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.version import CURRENT_VERSION
from azurelinuxagent.ga.agent_update import get_agent_update_handler
from azurelinuxagent.ga.guestagent import GAUpdateReportState
from tests.ga.test_update import UpdateTestCase
from tests.protocol.HttpRequestPredicates import HttpRequestPredicates
from tests.protocol.mocks import mock_wire_protocol, MockHttpResponse
from tests.protocol.mockwiredata import DATA_FILE
from tests.tools import clear_singleton_instances, load_bin_data, patch


class TestAgentUpdate(UpdateTestCase):

    def setUp(self):
        UpdateTestCase.setUp(self)
        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)

    @contextlib.contextmanager
    def __get_agent_update_handler(self, test_data=None, autoupdate_frequency=0.001, autoupdate_enabled=True):
        # Default to DATA_FILE of test_data parameter raises the pylint warning
        # W0102: Dangerous default value DATA_FILE (builtins.dict) as argument (dangerous-default-value)
        test_data = DATA_FILE if test_data is None else test_data

        with mock_wire_protocol(test_data) as protocol:

            def get_handler(url, **kwargs):
                if HttpRequestPredicates.is_agent_package_request(url):
                    agent_pkg = load_bin_data(self._get_agent_file_name(), self._agent_zip_dir)
                    protocol.mock_wire_data.call_counts['agentArtifact'] += 1
                    return MockHttpResponse(status=httpclient.OK, body=agent_pkg)
                return protocol.mock_wire_data.mock_http_get(url, **kwargs)

            def put_handler(url, *args, **_):
                if HttpRequestPredicates.is_host_plugin_status_request(url):
                    # Skip reading the HostGA request data as its encoded
                    return MockHttpResponse(status=500)
                protocol.aggregate_status = json.loads(args[0])
                return MockHttpResponse(status=201)

            protocol.set_http_handlers(http_get_handler=get_handler, http_put_handler=put_handler)

            with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=autoupdate_enabled):
                with patch("azurelinuxagent.common.conf.get_autoupdate_frequency", return_value=autoupdate_frequency):
                    with patch("azurelinuxagent.common.conf.get_autoupdate_gafamily", return_value="Prod"):
                        with patch("azurelinuxagent.ga.agent_update.add_event") as mock_telemetry:
                            agent_update_handler = get_agent_update_handler(protocol)
                            agent_update_handler._protocol = protocol
                            yield agent_update_handler, mock_telemetry

    def __assert_agent_directories_available(self, versions):
        for version in versions:
            self.assertTrue(os.path.exists(self.agent_dir(version)), "Agent directory {0} not found".format(version))

    def __assert_agent_directories_exist_and_others_dont_exist(self, versions):
        self.__assert_agent_directories_available(versions=versions)
        other_agents = [agent_dir for agent_dir in self.agent_dirs() if
                        agent_dir not in [self.agent_dir(version) for version in versions]]
        self.assertFalse(any(other_agents),
                         "All other agents should be purged from agent dir: {0}".format(other_agents))

    def __assert_agent_requested_version_in_goal_state(self, mock_telemetry, inc=1, version="9.9.9.10"):
        upgrade_event_msgs = [kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                              'Goal state incarnation_{0} is requesting a new agent version {1}'.format(inc, version) in kwarg['message'] and kwarg[
                                  'op'] == WALAEventOperation.AgentUpgrade]
        self.assertEqual(1, len(upgrade_event_msgs),
                         "Did not find the event indicating that the agent requested version found. Got: {0}".format(
                             mock_telemetry.call_args_list))

    def __assert_no_agent_package_telemetry_emitted(self, mock_telemetry, version="9.9.9.10"):
        upgrade_event_msgs = [kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                              'Unable to update Agent: No matching package found in the agent manifest for requested version: {0}'.format(version) in kwarg['message'] and kwarg[
                                  'op'] == WALAEventOperation.AgentUpgrade]
        self.assertEqual(1, len(upgrade_event_msgs),
                         "Did not find the event indicating that the agent package not found. Got: {0}".format(
                             mock_telemetry.call_args_list))

    def test_it_should_not_update_when_autoupdate_disabled(self):
        self.prepare_agents(count=1)
        with self.__get_agent_update_handler(autoupdate_enabled=False) as (agent_update_handler, mock_telemetry):
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
            self.__assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
            self.assertEqual(0, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "requesting a new agent version" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "should not check for requested version")

    def test_it_should_update_to_largest_version_if_ga_versioning_disabled(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"
        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch.object(conf, "get_enable_ga_versioning", return_value=False):
                with self.assertRaises(AgentUpgradeExitException) as context:
                    agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
                    self.__assert_agent_requested_version_in_goal_state(mock_telemetry, inc=2, version="99999.0.0.0")
                    self.__assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION), "99999.0.0.0"])
                    self.assertIn("Agent update found, Exiting current process", ustr(context.exception.reason))

    def test_it_should_update_to_largest_version_if_time_window_not_elapsed(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file["ga_manifest"] = "wire/ga_manifest_no_uris.xml"
        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, _):
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
            self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                             "New agent directory should not be found")
            agent_update_handler._protocol.mock_wire_data.set_ga_manifest("wire/ga_manifest.xml")
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
            self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                             "New agent directory should not be found")

    def test_it_should_update_to_largest_version_if_time_window_elapsed(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file["ga_manifest"] = "wire/ga_manifest_no_uris.xml"
        with patch("azurelinuxagent.common.conf.get_hotfix_upgrade_frequency", return_value=0.001):
            with patch("azurelinuxagent.common.conf.get_normal_upgrade_frequency", return_value=0.001):
                with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
                    with self.assertRaises(AgentUpgradeExitException) as context:
                        agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
                        self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                                         "New agent directory should not be found")
                        agent_update_handler._protocol.mock_wire_data.set_ga_manifest("wire/ga_manifest.xml")
                        agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
                        agent_update_handler._protocol.client.update_goal_state()
                        agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
                        self.__assert_agent_requested_version_in_goal_state(mock_telemetry, inc=2, version="99999.0.0.0")
                        self.__assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION), "99999.0.0.0"])
                        self.assertIn("Agent update found, Exiting current process", ustr(context.exception.reason))

    def test_it_should_not_agent_update_if_last_attempted_update_time_not_elapsed(self):
        self.prepare_agents(count=1)
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"
        version = "5.2.0.1"
        with self.__get_agent_update_handler(test_data=data_file, autoupdate_frequency=10) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_extension_config_requested_version(version)
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())

            self.__assert_agent_requested_version_in_goal_state(mock_telemetry, inc=2, version=version)
            self.__assert_no_agent_package_telemetry_emitted(mock_telemetry, version=version)
            # Now we shouldn't check for download if update not allowed.This run should not add new logs
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
            self.__assert_agent_requested_version_in_goal_state(mock_telemetry, inc=2, version=version)
            self.__assert_no_agent_package_telemetry_emitted(mock_telemetry, version=version)

    def test_it_should_update_to_largest_version_if_requested_version_not_available(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf.xml"
        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with self.assertRaises(AgentUpgradeExitException) as context:
                agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
                self.__assert_agent_requested_version_in_goal_state(mock_telemetry, inc=2, version="99999.0.0.0")
                self.__assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION), "99999.0.0.0"])
                self.assertIn("Agent update found, Exiting current process", ustr(context.exception.reason))

    def test_it_should_not_agent_update_if_requested_version_is_same_as_current_version(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_extension_config_requested_version(
                str(CURRENT_VERSION))
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
            self.assertEqual(0, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "requesting a new agent version" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "requested version should be same as current version")
            self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                             "New agent directory should not be found")

    def test_it_should_upgrade_agent_if_requested_version_is_available_greater_than_current_version(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with self.assertRaises(AgentUpgradeExitException) as context:
                agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
            self.__assert_agent_requested_version_in_goal_state(mock_telemetry, version="9.9.9.10")
            self.__assert_agent_directories_exist_and_others_dont_exist(versions=["9.9.9.10", str(CURRENT_VERSION)])
            self.assertIn("Agent update found, Exiting current process", ustr(context.exception.reason))

    def test_it_should_downgrade_agent_if_requested_version_is_available_less_than_current_version(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        downgraded_version = "1.2.0"

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_extension_config_requested_version(downgraded_version)
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            with self.assertRaises(AgentUpgradeExitException) as context:
                agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
            self.__assert_agent_requested_version_in_goal_state(mock_telemetry, inc=2, version=downgraded_version)
            self.__assert_agent_directories_exist_and_others_dont_exist(
                versions=[downgraded_version, str(CURRENT_VERSION)])
            self.assertIn("Agent update found, Exiting current process", ustr(context.exception.reason))

    def test_handles_if_requested_version_not_found_in_pkgs_to_download(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        version = "5.2.0.4"

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_extension_config_requested_version(version)
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())

            self.__assert_agent_requested_version_in_goal_state(mock_telemetry, inc=2, version=version)
            self.assertFalse(os.path.exists(self.agent_dir(version)),
                             "New agent directory should not be found")

            self.__assert_no_agent_package_telemetry_emitted(mock_telemetry, version=version)

    def test_handles_missing_agent_family(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_missing_family.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())

            self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                             "New agent directory should not be found")

            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "No manifest links found for agent family" in kwarg[
                                         'message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "Agent manifest should not be in GS")

    def test_it_should_report_update_status_with_success(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, _):
            GAUpdateReportState.report_error_msg = ""
            agent_update_handler._protocol.mock_wire_data.set_extension_config_requested_version(
                str(CURRENT_VERSION))
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(VMAgentUpdateStatuses.Success, vm_agent_update_status.status)
            self.assertEqual(0, vm_agent_update_status.code)
            self.assertEqual(str(CURRENT_VERSION), vm_agent_update_status.expected_version)

    def test_it_should_report_update_status_with_error_on_download_fail(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        @contextlib.contextmanager
        def mock_agent_update_handler(test_data):
            with mock_wire_protocol(test_data) as protocol:

                def get_handler(url, **kwargs):
                    if HttpRequestPredicates.is_agent_package_request(url):
                        return MockHttpResponse(status=httpclient.SERVICE_UNAVAILABLE)
                    return protocol.mock_wire_data.mock_http_get(url, **kwargs)

                protocol.set_http_handlers(http_get_handler=get_handler)

                with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=True):
                    with patch("azurelinuxagent.common.conf.get_autoupdate_frequency", return_value=0.001):
                        with patch("azurelinuxagent.common.conf.get_autoupdate_gafamily", return_value="Prod"):
                            agent_update_handler_local = get_agent_update_handler(protocol)
                            yield agent_update_handler_local

        with mock_agent_update_handler(test_data=data_file) as (agent_update_handler):
            GAUpdateReportState.report_error_msg = ""
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(VMAgentUpdateStatuses.Error, vm_agent_update_status.status)
            self.assertEqual(1, vm_agent_update_status.code)
            self.assertEqual("9.9.9.10", vm_agent_update_status.expected_version)
            self.assertIn("Unable to download Agent", vm_agent_update_status.message)

    def test_it_should_report_update_status_with_missing_requested_version_error(self):
        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf.xml"

        @contextlib.contextmanager
        def mock_agent_update_handler(test_data):
            with mock_wire_protocol(test_data) as protocol:
                def get_handler(url, **kwargs):
                    if HttpRequestPredicates.is_agent_package_request(url):
                        return MockHttpResponse(status=httpclient.SERVICE_UNAVAILABLE)
                    return protocol.mock_wire_data.mock_http_get(url, **kwargs)

                protocol.set_http_handlers(http_get_handler=get_handler)

                with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=True):
                    with patch("azurelinuxagent.common.conf.get_autoupdate_frequency", return_value=0.001):
                        with patch("azurelinuxagent.common.conf.get_autoupdate_gafamily", return_value="Prod"):
                            agent_update_handler_local = get_agent_update_handler(protocol)
                            yield agent_update_handler_local

        with mock_agent_update_handler(test_data=data_file) as (agent_update_handler):
            GAUpdateReportState.report_error_msg = ""
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(VMAgentUpdateStatuses.Error, vm_agent_update_status.status)
            self.assertEqual(1, vm_agent_update_status.code)
            self.assertIn("Missing requested version", vm_agent_update_status.message)

    def test_it_should_not_log_same_error_next_hours(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_missing_family.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler.run(agent_update_handler._protocol.get_goal_state())

            self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                             "New agent directory should not be found")

        self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                 "No manifest links found for agent family" in kwarg[
                                     'message'] and kwarg[
                                     'op'] == WALAEventOperation.AgentUpgrade]), "Agent manifest should not be in GS")

        agent_update_handler.run(agent_update_handler._protocol.get_goal_state())

        self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                 "No manifest links found for agent family" in kwarg[
                                     'message'] and kwarg[
                                     'op'] == WALAEventOperation.AgentUpgrade]), "Agent manifest should not be in GS")