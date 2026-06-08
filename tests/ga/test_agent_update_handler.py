import contextlib
import json
import os
import random
import shutil
import time

from azurelinuxagent.common import conf
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, ExtensionDownloadError
from azurelinuxagent.common.future import ustr, httpclient, datetime_min_utc
from azurelinuxagent.common.protocol.wire import GoalState, GoalStateProperties
from azurelinuxagent.common.protocol.restapi import VMAgentUpdateStatuses
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.version import CURRENT_VERSION, AGENT_NAME
from azurelinuxagent.ga.agent_update_handler import get_agent_update_handler
from azurelinuxagent.ga.guestagent import GuestAgent, INITIAL_UPDATE_STATE_FILE, RSM_UPDATE_STATE_FILE
from azurelinuxagent.ga.signature_validation_util import SignatureValidationError, SignatureValidationTimeoutError, \
    SignatureValidationTimeout

from tests.ga.test_update import UpdateTestCase
from tests.lib.http_request_predicates import HttpRequestPredicates
from tests.lib.mock_wire_protocol import mock_wire_protocol, MockHttpResponse
from tests.lib.wire_protocol_data import DATA_FILE
from tests.lib.tools import clear_singleton_instances, load_bin_data, patch


class TestAgentUpdate(UpdateTestCase):

    def setUp(self):
        UpdateTestCase.setUp(self)
        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)

    @contextlib.contextmanager
    def _get_agent_update_handler(self, test_data=None, autoupdate_frequency=0.001, autoupdate_enabled=True, initial_update_attempted=True, rsm_update_attempted=False, protocol_get_error=False, mock_get_header=None, mock_put_header=None, mock_random_update_time=True):
        # Default to DATA_FILE of test_data parameter raises the pylint warning
        # W0102: Dangerous default value DATA_FILE (builtins.dict) as argument (dangerous-default-value)
        test_data = DATA_FILE if test_data is None else test_data

        with mock_wire_protocol(test_data) as protocol:

            def get_handler(url, **kwargs):
                if HttpRequestPredicates.is_agent_package_request(url):
                    if not protocol_get_error:
                        agent_pkg = load_bin_data(self._get_agent_file_name(), self._agent_zip_dir)
                        return MockHttpResponse(status=httpclient.OK, body=agent_pkg)
                    else:
                        return MockHttpResponse(status=httpclient.SERVICE_UNAVAILABLE)

                return protocol.mock_wire_data.mock_http_get(url, **kwargs)

            def put_handler(url, *args, **_):
                if HttpRequestPredicates.is_host_plugin_status_request(url):
                    # Skip reading the HostGA request data as its encoded
                    return MockHttpResponse(status=500)
                protocol.aggregate_status = json.loads(args[0])
                return MockHttpResponse(status=201)

            http_get_handler = mock_get_header if mock_get_header else get_handler
            http_put_handler = mock_put_header if mock_put_header else put_handler

            protocol.set_http_handlers(http_get_handler=http_get_handler, http_put_handler=http_put_handler)

            if initial_update_attempted:
                open(os.path.join(conf.get_lib_dir(), INITIAL_UPDATE_STATE_FILE), "a").close()

            if rsm_update_attempted:
                open(os.path.join(conf.get_lib_dir(), RSM_UPDATE_STATE_FILE), "a").close()

            original_randint = random.randint

            def _mock_random_update_time(a, b):
                if mock_random_update_time:  # update should occur immediately
                    return 0
                if b == 1:  # handle tests where the normal or hotfix frequency is mocked to be very short (e.g., 1 second). Returning a very small delay (0.001 seconds) ensures the logic is tested without introducing significant waiting time
                    return 0.001
                return original_randint(a, b) + 10  # If none of the above conditions are met, the function returns additional 10-seconds delay. This might represent a normal delay for updates in scenarios where updates are not expected immediately

            with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=autoupdate_enabled):
                with patch("azurelinuxagent.common.conf.get_autoupdate_frequency", return_value=autoupdate_frequency):
                    with patch("azurelinuxagent.ga.self_update_version_updater.random.randint", side_effect=_mock_random_update_time):
                        with patch("azurelinuxagent.common.conf.get_autoupdate_gafamily", return_value="Prod"):
                            with patch("azurelinuxagent.common.conf.get_enable_ga_versioning", return_value=True):
                                # Patch validate_signature so that the function is mocked in these UTs. The actual
                                # signature validation logic is unit tested in test_signature_validation.py and
                                # test_signature_validation_sudo.py
                                with patch("azurelinuxagent.common.protocol.wire.validate_signature"):
                                    with patch("azurelinuxagent.common.event.EventLogger.add_event") as mock_telemetry:
                                        agent_update_handler = get_agent_update_handler(protocol)
                                        agent_update_handler._protocol = protocol
                                        yield agent_update_handler, mock_telemetry

    def _assert_agent_directories_available(self, versions):
        for version in versions:
            self.assertTrue(os.path.exists(self.agent_dir(version)), "Agent directory {0} not found".format(version))

    def _assert_agent_directories_exist_and_others_dont_exist(self, versions):
        self._assert_agent_directories_available(versions=versions)
        other_agents = [agent_dir for agent_dir in self.agent_dirs() if
                        agent_dir not in [self.agent_dir(version) for version in versions]]
        self.assertFalse(any(other_agents),
                         "All other agents should be purged from agent dir: {0}".format(other_agents))

    def _assert_agent_rsm_version_in_goal_state(self, mock_telemetry, inc=1, version="9.9.9.10"):
        upgrade_event_msgs = [kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                              'New agent version:{0} requested by RSM in Goal state incarnation_{1}'.format(version, inc) in kwarg['message'] and kwarg[
                                  'op'] == WALAEventOperation.AgentUpgrade]
        self.assertEqual(1, len(upgrade_event_msgs),
                         "Did not find the event indicating that the agent requested version found. Got: {0}".format(
                             mock_telemetry.call_args_list))

    def _assert_update_discovered_from_agent_manifest(self, mock_telemetry, inc=1, version="9.9.9.10"):
        upgrade_event_msgs = [kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                              'Self-update is ready to upgrade the new agent: {0} now before processing the goal state: incarnation_{1}'.format(version, inc) in kwarg['message'] and kwarg[
                                  'op'] == WALAEventOperation.AgentUpgrade]
        self.assertEqual(1, len(upgrade_event_msgs),
                         "Did not find the event indicating that the new version found. Got: {0}".format(
                             mock_telemetry.call_args_list))

    def _assert_no_agent_package_telemetry_emitted(self, mock_telemetry, version="9.9.9.10"):
        upgrade_event_msgs = [kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                              'No matching package found in the agent manifest for version: {0}'.format(version) in kwarg['message'] and kwarg[
                                  'op'] == WALAEventOperation.AgentUpgrade]
        self.assertEqual(1, len(upgrade_event_msgs),
                         "Did not find the event indicating that the agent package not found. Got: {0}".format(
                             mock_telemetry.call_args_list))

    def _assert_agent_exit_process_telemetry_emitted(self, message):
        self.assertIn("Current Agent {0} completed all update checks, exiting current process".format(CURRENT_VERSION), message)

    def test_it_should_not_update_when_autoupdate_disabled(self):
        self.prepare_agents(count=1)
        with self._get_agent_update_handler(autoupdate_enabled=False) as (agent_update_handler, mock_telemetry):
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
            self.assertEqual(0, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "requested by RSM in Goal state" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "should not check for rsm version")

    def test_it_should_update_to_largest_version_if_ga_versioning_disabled(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"
        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch.object(conf, "get_enable_ga_versioning", return_value=False):
                with self.assertRaises(AgentUpgradeExitException) as context:
                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_update_discovered_from_agent_manifest(mock_telemetry, version="99999.0.0.0")
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION), "99999.0.0.0"])
            self._assert_agent_exit_process_telemetry_emitted(ustr(context.exception.reason))

    def test_it_should_not_self_update_if_manifest_download_time_not_elapsed(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file["ga_manifest"] = "wire/ga_manifest_no_uris.xml"
        with self._get_agent_update_handler(test_data=data_file, autoupdate_frequency=10) as (agent_update_handler, _):
            mock_wire_data = agent_update_handler._protocol.mock_wire_data

            # This run should attempt to download the manifest, but it will fail to download the agent since there are
            # no package URIs in the manifest.
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
            self.assertEqual(1, mock_wire_data.call_counts['manifest_of_ga.xml'], "Agent manifest should have been downloaded once")

            agent_update_handler._protocol.mock_wire_data.set_ga_manifest("wire/ga_manifest.xml")
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            # This run should not attempt to download the manifest, since the required time has not elapsed since last
            # download attempt.
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
            self.assertEqual(1, mock_wire_data.call_counts['manifest_of_ga.xml'], "Agent manifest should not have been downloaded again")

    def test_it_should_not_do_self_update_if_update_time_is_not_elapsed(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file["ga_manifest"] = "wire/ga_manifest_no_uris.xml"
        with self._get_agent_update_handler(test_data=data_file, mock_random_update_time=False) as (agent_update_handler, _):
            # This run should identify the update from the manifest and set a random time within the regular self-update
            # frequency for the update.
            self.assertEqual(datetime_min_utc, agent_update_handler._updater._next_update_time)
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
            next_update_time_after_first_run = agent_update_handler._updater._next_update_time
            self.assertNotEqual(datetime_min_utc, next_update_time_after_first_run)

            agent_update_handler._protocol.mock_wire_data.set_ga_manifest("wire/ga_manifest.xml")
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            # This run should identify the update from the manifest but should not update since the random update time
            # is not elapsed yet. It should not set another random update time since the update is already identified
            # in the last agent_update_handler run
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
            self.assertEqual(agent_update_handler._updater._next_update_time, next_update_time_after_first_run)

    def test_it_should_update_to_largest_version_after_time_window_elapsed(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file["ga_manifest"] = "wire/ga_manifest_no_uris.xml"
        with patch("azurelinuxagent.common.conf.get_self_update_hotfix_frequency", return_value=1):
            with patch("azurelinuxagent.common.conf.get_self_update_regular_frequency", return_value=1):
                with self._get_agent_update_handler(test_data=data_file, mock_random_update_time=False) as (agent_update_handler, mock_telemetry):
                    with self.assertRaises(AgentUpgradeExitException) as context:
                        # This run should identify the update from the manifest and set a random time within the regular
                        # self-update frequency for the update.
                        self.assertEqual(datetime_min_utc, agent_update_handler._updater._next_update_time)
                        agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
                        self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
                        next_update_time_after_first_run = agent_update_handler._updater._next_update_time
                        self.assertNotEqual(datetime_min_utc, next_update_time_after_first_run)

                        agent_update_handler._protocol.mock_wire_data.set_ga_manifest("wire/ga_manifest.xml")
                        agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
                        # sleeping for update window to elapse
                        time.sleep(0.1)
                        # This run should do the update since the required time has elapsed since the update was
                        # identified
                        agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
                    self._assert_update_discovered_from_agent_manifest(mock_telemetry, inc=2, version="99999.0.0.0")
                    self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION), "99999.0.0.0"])
                    self._assert_agent_exit_process_telemetry_emitted(ustr(context.exception.reason))

    def test_it_should_not_allow_update_if_largest_version_below_current_version(self):
        self.prepare_agents(count=1)
        data_file = DATA_FILE.copy()
        data_file["ga_manifest"] = "wire/ga_manifest_no_upgrade.xml"
        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, _):
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])

    def test_it_should_self_update_to_largest_version_if_goal_state_does_not_have_rsm_fields(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf.xml"
        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with self.assertRaises(AgentUpgradeExitException) as context:
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_update_discovered_from_agent_manifest(mock_telemetry, version="99999.0.0.0")
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION), "99999.0.0.0"])
            self._assert_agent_exit_process_telemetry_emitted(ustr(context.exception.reason))

    def test_it_should_not_download_manifest_again_if_last_attempted_download_time_not_elapsed(self):
        self.prepare_agents(count=1)
        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf.xml"
        with self._get_agent_update_handler(test_data=data_file, autoupdate_frequency=10, protocol_get_error=True) as (agent_update_handler, _):
            # making multiple agent update attempts
            goal_state = GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState)
            agent_update_handler.run(goal_state, True)
            agent_update_handler.run(goal_state, True)
            agent_update_handler.run(goal_state, True)

            mock_wire_data = agent_update_handler._protocol.mock_wire_data
            self.assertEqual(1, mock_wire_data.call_counts['manifest_of_ga.xml'], "Agent manifest should not be downloaded again")

    def test_it_should_download_manifest_if_last_attempted_download_time_is_elapsed(self):
        self.prepare_agents(count=1)
        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf.xml"

        with self._get_agent_update_handler(test_data=data_file, autoupdate_frequency=0.00001, protocol_get_error=True) as (agent_update_handler, _):
            # making multiple agent update attempts
            goal_state = GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState)
            agent_update_handler.run(goal_state, True)
            agent_update_handler.run(goal_state, True)
            agent_update_handler.run(goal_state, True)

        mock_wire_data = agent_update_handler._protocol.mock_wire_data
        self.assertEqual(3, mock_wire_data.call_counts['manifest_of_ga.xml'], "Agent manifest should be downloaded in all attempts")

    def test_it_should_not_agent_update_if_rsm_version_is_same_as_current_version(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(
                str(CURRENT_VERSION))
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "VM enabled for RSM updates, switching to RSM update mode" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "rsm mode should be used for update")
            self.assertEqual(0, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "requested by RSM in Goal state" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "rsm version should be same as current version")
            self.assertEqual(20, self.agent_count(), "There should not be any additional agent directories after running update handler")
            self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")), "Agent directories shouldn't have been modified")

    def test_it_should_upgrade_agent_if_rsm_version_is_available_greater_than_current_version(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with self.assertRaises(AgentUpgradeExitException) as context:
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_agent_rsm_version_in_goal_state(mock_telemetry, version="9.9.9.10")
            self._assert_agent_directories_exist_and_others_dont_exist(versions=["9.9.9.10", str(CURRENT_VERSION)])
            self._assert_agent_exit_process_telemetry_emitted(ustr(context.exception.reason))

    def test_it_should_downgrade_agent_if_rsm_version_is_available_less_than_current_version(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_downgrade_rsm_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        downgrade_version = "2.5.0"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(downgrade_version)
            agent_update_handler._protocol.mock_wire_data.set_from_version_in_agent_family(str(CURRENT_VERSION))
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            with self.assertRaises(AgentUpgradeExitException) as context:
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_agent_rsm_version_in_goal_state(mock_telemetry, inc=2, version=downgrade_version)
            self._assert_agent_directories_exist_and_others_dont_exist(
                versions=[downgrade_version, str(CURRENT_VERSION)])
            self._assert_agent_exit_process_telemetry_emitted(ustr(context.exception.reason))

    def test_it_should_not_allow_rsm_downgrade_if_from_version_different_from_current_version(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_downgrade_rsm_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        downgrade_version = "2.5.0"
        from_version = "3.0.0"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(downgrade_version)
            agent_update_handler._protocol.mock_wire_data.set_from_version_in_agent_family(from_version)
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self.assertFalse(os.path.exists(self.agent_dir(downgrade_version)), "New agent directory should not be found")
            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "downgrade {0} is not allowed to update from {1}".format(downgrade_version, from_version) in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "downgrade should not be allowed")
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(1, vm_agent_update_status.code)
            self.assertEqual(VMAgentUpdateStatuses.Error, vm_agent_update_status.status)
            self.assertIn("downgrade {0} is not allowed to update from {1}".format(downgrade_version, from_version), vm_agent_update_status.message)

    def test_it_should_not_allow_rsm_downgrade_if_from_version_missing(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        downgrade_version = "2.5.0"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(downgrade_version)
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self.assertFalse(os.path.exists(self.agent_dir(downgrade_version)), "New agent directory should not be found")
            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "downgrade {0} is not allowed to update from {1}".format(downgrade_version, None) in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "downgrade should not be allowed")
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(1, vm_agent_update_status.code)
            self.assertEqual(VMAgentUpdateStatuses.Error, vm_agent_update_status.status)
            self.assertIn("downgrade {0} is not allowed to update from {1}".format(downgrade_version, None), vm_agent_update_status.message)

    def test_it_should_not_do_rsm_update_if_gs_not_updated_in_next_attempt(self):
        self.prepare_agents(count=1)
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"
        version = "9.9.9.999"
        with self._get_agent_update_handler(test_data=data_file, autoupdate_frequency=10) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(version)
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            goal_state = GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState)
            # This run should fail to update because package for the version is not found in the manifest
            agent_update_handler.run(goal_state, True)
            self._assert_agent_rsm_version_in_goal_state(mock_telemetry, inc=2, version=version)
            self._assert_no_agent_package_telemetry_emitted(mock_telemetry, version=version)

            # Now we shouldn't check for download if update not allowed(GS not updated). This run should not add new
            # logs
            agent_update_handler.run(goal_state, False)
            self._assert_agent_rsm_version_in_goal_state(mock_telemetry, inc=2, version=version)
            self._assert_no_agent_package_telemetry_emitted(mock_telemetry, version=version)    # Checks that this telemetry was only emitted once (i.e., not emitted again in the second run)

    def test_it_should_not_downgrade_below_daemon_version(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        downgrade_version = "1.2.0"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(downgrade_version)
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self.assertFalse(os.path.exists(self.agent_dir(downgrade_version)),
                             "New agent directory should not be found")
            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "new version {0} is below than daemon version".format(downgrade_version) in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "downgrade should not be allowed below daemon version")
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(1, vm_agent_update_status.code)
            self.assertEqual(VMAgentUpdateStatuses.Error, vm_agent_update_status.status)
            self.assertIn("new version {0} is below than daemon version".format(downgrade_version), vm_agent_update_status.message)

    def test_it_should_self_update_to_largest_version_if_vm_not_enabled_for_rsm_upgrades(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf_vm_not_enabled_for_rsm_upgrades.xml"
        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with self.assertRaises(AgentUpgradeExitException) as context:
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_update_discovered_from_agent_manifest(mock_telemetry, version="99999.0.0.0")
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION), "99999.0.0.0"])
            self._assert_agent_exit_process_telemetry_emitted(ustr(context.exception.reason))

    def test_it_should_self_update_to_next_largest_version_if_largest_download_fails(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf_vm_not_enabled_for_rsm_upgrades.xml"
        data_file["ga_manifest"] = "wire/ga_manifest_no_uris_for_largest.xml"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with self.assertRaises(AgentUpgradeExitException) as context:
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_update_discovered_from_agent_manifest(mock_telemetry, version="99999.0.0.0")
            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "Self-update: failed to prepare version 99999.0.0.0 for update, trying next largest version" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]),
                                            "99999.0.0.0 download should have failed")
            self._assert_update_discovered_from_agent_manifest(mock_telemetry, version="9.9.9.10")
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION), "9.9.9.10"])
            self._assert_agent_exit_process_telemetry_emitted(ustr(context.exception.reason))

    def test_it_should_only_attempt_to_download_versions_greater_than_current(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf_vm_not_enabled_for_rsm_upgrades.xml"
        data_file["ga_manifest"] = "wire/ga_manifest_no_uris.xml"

        def download_side_effect(*args, **_):
            package_version = args[0].version
            raise ExtensionDownloadError("Failed to download WALinuxAgent-{0} from all URIs".format(package_version))

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch("azurelinuxagent.ga.ga_version_updater.GAVersionUpdater.download_new_agent_pkg", side_effect=download_side_effect) as mock_download_new_agent:
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
                self._assert_update_discovered_from_agent_manifest(mock_telemetry, version="99999.0.0.0")
                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "Self-update: failed to prepare version 99999.0.0.0 for update, trying next largest version" in kwarg['message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]),
                                                "99999.0.0.0 download should have failed")
                self._assert_update_discovered_from_agent_manifest(mock_telemetry, version="9.9.9.10")
                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "[SelfUpdate] Unable to update Agent: [ExtensionDownloadError] Failed to download WALinuxAgent-9.9.9.10 from all URIs" in kwarg['message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]),
                                                "9.9.9.10 download should have failed and been raised as error")
                self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
                self.assertEqual(2, mock_download_new_agent.call_count)

    def test_it_should_not_update_to_version_if_version_not_from_rsm(self):
        self.prepare_agents(count=1)
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_version_not_from_rsm.xml"
        downgrade_version = "2.5.0"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(downgrade_version)
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_agent_directories_exist_and_others_dont_exist(
                versions=[str(CURRENT_VERSION)])
            self.assertFalse(os.path.exists(self.agent_dir(downgrade_version)),
                             "New agent directory should not be found")
            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "VM enabled for RSM updates, switching to RSM update mode" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]),
                                            "rsm mode should be used for update")

    def test_handles_if_rsm_version_not_found_in_pkgs_to_download(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        version = "9.9.9.999"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(version)
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

            self._assert_agent_rsm_version_in_goal_state(mock_telemetry, inc=2, version=version)
            self.assertFalse(os.path.exists(self.agent_dir(version)),
                             "New agent directory should not be found")

            self._assert_no_agent_package_telemetry_emitted(mock_telemetry, version=version)
            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "VM enabled for RSM updates, switching to RSM update mode" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]),
                                            "rsm mode should be used for update")

    def test_handles_missing_agent_family(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_missing_family.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            goal_state = GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState)
            agent_update_handler.run(goal_state, True)

            self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                             "New agent directory should not be found")

            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "No manifest links found for agent family" in kwarg[
                                         'message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "Agent manifest should not be in GS")

            # making multiple agent update attempts and assert only one time logged (only the first run since it was a new goal state)
            agent_update_handler.run(goal_state, False)
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), False)

            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "No manifest links found for agent family" in kwarg[
                                         'message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]),
                             "Agent manifest error should be logged once if it's same goal state")

    def test_it_should_report_update_status_with_success(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, _):
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(
                str(CURRENT_VERSION))
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(VMAgentUpdateStatuses.Success, vm_agent_update_status.status)
            self.assertEqual(0, vm_agent_update_status.code)
            self.assertEqual(str(CURRENT_VERSION), vm_agent_update_status.expected_version)

    def test_it_should_not_report_update_status_when_self_update_used(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf.xml"
        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, _):
            with self.assertRaises(AgentUpgradeExitException):
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
        vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
        self.assertIsNone(vm_agent_update_status, "VM Agent Update Status should not be set when self-update is used")

    def test_it_should_report_update_with_error_if_auto_update_is_disabled_and_rsm_update_used(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        with self._get_agent_update_handler(test_data=data_file, rsm_update_attempted=True) as (agent_update_handler, _):
            with patch("azurelinuxagent.common.conf.get_auto_update_to_latest_version", return_value=False):
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
                vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
                self.assertEqual(1, vm_agent_update_status.code)
                self.assertEqual(VMAgentUpdateStatuses.Error, vm_agent_update_status.status)
                self.assertIn("Auto update is disabled, skipping agent update", vm_agent_update_status.message)

    def test_it_should_report_update_status_with_error_on_download_fail(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        with self._get_agent_update_handler(test_data=data_file, protocol_get_error=True) as (agent_update_handler, _):
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(VMAgentUpdateStatuses.Error, vm_agent_update_status.status)
            self.assertEqual(1, vm_agent_update_status.code)
            self.assertEqual(str(CURRENT_VERSION), vm_agent_update_status.expected_version)
            self.assertIn("Failed to download WALinuxAgent-9.9.9.10 from all URIs", vm_agent_update_status.message)

    def test_it_should_not_report_error_status_if_new_rsm_version_is_same_as_current_after_last_update_attempt_failed(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        with self._get_agent_update_handler(test_data=data_file, protocol_get_error=True) as (agent_update_handler, _):
            # This run should fail to update because of download error and report error status
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(VMAgentUpdateStatuses.Error, vm_agent_update_status.status)
            self.assertEqual(1, vm_agent_update_status.code)
            # we report current agent version running
            self.assertEqual(str(CURRENT_VERSION), vm_agent_update_status.expected_version)
            self.assertIn("Failed to download WALinuxAgent-9.9.9.10 from all URIs", vm_agent_update_status.message)

            # Send same version GS after last update attempt failed
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(
                str(CURRENT_VERSION))
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            # This run should not produce any error status since the version requested in the GS is the current version
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(VMAgentUpdateStatuses.Success, vm_agent_update_status.status)
            self.assertEqual(0, vm_agent_update_status.code)
            self.assertEqual(str(CURRENT_VERSION), vm_agent_update_status.expected_version)

    def test_it_should_report_update_status_with_missing_rsm_version_error(self):
        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf_version_missing_in_agent_family.xml"

        with self._get_agent_update_handler(test_data=data_file, protocol_get_error=True, rsm_update_attempted=True) as (agent_update_handler, _):
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            vm_agent_update_status = agent_update_handler.get_vmagent_update_status()
            self.assertEqual(VMAgentUpdateStatuses.Error, vm_agent_update_status.status)
            self.assertEqual(1, vm_agent_update_status.code)
            self.assertIn("missing version property. So, skipping agent update", vm_agent_update_status.message)

    def test_it_should_not_log_same_error_if_gs_not_updated(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_missing_family.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            goal_state = GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState)
            # This run should fail to update because there are no manifest uris in the goal state
            agent_update_handler.run(goal_state, True)

            self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                             "New agent directory should not be found")

            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "No manifest links found for agent family" in kwarg[
                                         'message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "Agent manifest should not be in GS")

            # This run should fail to update because there are no manifest uris in the goal state, but it should not
            # emit the event again since the goal state has not been updated
            agent_update_handler.run(goal_state, False)

            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "No manifest links found for agent family" in kwarg[
                                         'message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "Agent manifest should not be in GS")

    def test_it_should_save_rsm_state_of_the_most_recent_goal_state(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, _):
            with self.assertRaises(AgentUpgradeExitException):
                # This run should use rsm update mode and save rsm state file
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

            state_file = os.path.join(conf.get_lib_dir(), RSM_UPDATE_STATE_FILE)
            self.assertTrue(os.path.exists(state_file), "The rsm state file was not saved (can't find {0})".format(state_file))

            # check if state gets updated if most recent goal state has different values
            agent_update_handler._protocol.mock_wire_data.set_extension_config_is_vm_enabled_for_rsm_upgrades("False")
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            with self.assertRaises(AgentUpgradeExitException):
                # This run should use self-update mode and remove rsm state file
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

            self.assertFalse(os.path.exists(state_file), "The rsm file should be removed (file: {0})".format(state_file))

    def test_it_should_not_update_to_latest_if_flag_is_disabled(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf.xml"
        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, _):
            with patch("azurelinuxagent.common.conf.get_auto_update_to_latest_version", return_value=False):
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])

    def test_it_should_continue_with_update_if_number_of_update_attempts_less_than_3(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"

        latest_version = self.prepare_agents(count=2)
        self.expand_agents()
        latest_path = os.path.join(self.tmp_dir, "{0}-{1}".format(AGENT_NAME, latest_version))
        agent = GuestAgent.from_installed_agent(latest_path)
        # marking agent as bad agent on first attempt
        agent.mark_failure(is_fatal=True)
        agent.inc_update_attempt_count()
        self.assertTrue(agent.is_blacklisted, "Agent should be blacklisted")
        self.assertEqual(1, agent.get_update_attempt_count(), "Agent update attempts should be 1")
        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            # Rest 2 attempts it should continue with update even agent is marked as bad agent in first attempt
            for i in range(2):
                with self.assertRaises(AgentUpgradeExitException):
                    agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family(
                        str(latest_version))
                    agent_update_handler._protocol.mock_wire_data.set_version_in_ga_manifest(str(latest_version))
                    agent_update_handler._protocol.mock_wire_data.set_incarnation(i+2)
                    agent_update_handler._protocol.client.update_goal_state()
                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
                self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION), str(latest_version)])
                agent = GuestAgent.from_installed_agent(latest_path)
                self.assertFalse(agent.is_blacklisted, "Agent should not be blacklisted")
                self.assertEqual(i+2, agent.get_update_attempt_count(), "Agent update attempts should be {0}".format(i+2))

            # check if next update is not attempted
            agent.mark_failure(is_fatal=True)
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            agent = GuestAgent.from_installed_agent(latest_path)
            self.assertTrue(agent.is_blacklisted, "Agent should be blacklisted")
            self.assertEqual(3, agent.get_update_attempt_count(), "Agent update attempts should be 3")
            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "Attempted enough update retries for version: {0} but still agent not recovered from bad state".format(latest_version) in kwarg[
                                         'message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]),
                             "Update is not allowed after 3 attempts")

    def test_it_should_fail_the_update_if_agent_pkg_is_missing_manifest(self):
        agent_uri = 'https://foo.blob.core.windows.net/bar/OSTCExtensions.WALinuxAgent__9.9.9.10'

        def http_get_handler(uri, *_, **__):
            if uri in (agent_uri, 'http://168.63.129.16:32526/extensionArtifact'):
                response = load_bin_data("ga/WALinuxAgent-9.9.9.10-no_manifest.zip")
                return MockHttpResponse(status=httpclient.OK, body=response)
            return None
        self.prepare_agents(count=1)
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_rsm_version.xml"
        with self._get_agent_update_handler(test_data=data_file, mock_get_header=http_get_handler) as (agent_update_handler, mock_telemetry):
            agent_update_handler._protocol.mock_wire_data.set_version_in_agent_family("9.9.9.10")
            agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
            agent_update_handler._protocol.client.update_goal_state()
            agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "Downloaded agent package: WALinuxAgent-9.9.9.10 is missing agent handler manifest file" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "Agent update should fail")

    def test_it_should_use_self_update_for_first_update_always(self):
        self.prepare_agents(count=1)

        # mock the goal state as vm enrolled into RSM
        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf_rsm_version.xml"
        with self._get_agent_update_handler(test_data=data_file, initial_update_attempted=False) as (agent_update_handler, mock_telemetry):
            with self.assertRaises(AgentUpgradeExitException) as context:
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)
            # Verifying agent used self-update for initial update
            self._assert_update_discovered_from_agent_manifest(mock_telemetry, version="99999.0.0.0")
            self._assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION), "99999.0.0.0"])
            self._assert_agent_exit_process_telemetry_emitted(ustr(context.exception.reason))

        state_file = os.path.join(conf.get_lib_dir(), INITIAL_UPDATE_STATE_FILE)
        self.assertTrue(os.path.exists(state_file),
                        "The first update state file was not saved (can't find {0})".format(state_file))

    def test_it_should_honor_any_update_type_after_first_update(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf_rsm_version.xml"
        # mocking initial update attempt as true
        with self._get_agent_update_handler(test_data=data_file, initial_update_attempted=True) as (agent_update_handler, mock_telemetry):
            with self.assertRaises(AgentUpgradeExitException) as context:
                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

            # Verifying agent honored RSM update
            self._assert_agent_rsm_version_in_goal_state(mock_telemetry, version="9.9.9.10")
            self._assert_agent_directories_exist_and_others_dont_exist(versions=["9.9.9.10", str(CURRENT_VERSION)])
            self._assert_agent_exit_process_telemetry_emitted(ustr(context.exception.reason))
            self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "VM enabled for RSM updates, switching to RSM update mode" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]),
                                            "rsm mode should be used for update")

    def _get_signature_telemetry_events(self, mock_telemetry):
        """Helper to extract AgentSignature events from the mock telemetry call list."""
        return [kwarg for _, kwarg in mock_telemetry.call_args_list
                if kwarg.get('op') == WALAEventOperation.AgentSignature]

    def test_it_should_not_send_signature_telemetry_when_goal_state_not_updated(self):
        """
        When ext_gs_updated is False (not a new goal state), no signature telemetry should be emitted.
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM but the agent version in the goal state is not from RSM, so it
        # should not result in an agent update. This unit test is only testing the agent logic to send telemetry on
        # agent signatures in the goal state, so an actual agent update is not needed.
        data_file["ext_conf"] = "wire/ext_conf-two_ga_dummy_signatures.xml"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            # Patch agent_signature_goal_state_telemetry_enabled() and supports_agent_signature_mapping() so that the agent takes
            # the signature validation flow
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

                    sig_events = self._get_signature_telemetry_events(mock_telemetry)
                    self.assertEqual(1, len(sig_events), "Expected exactly one AgentSignature event. Got: {0}".format(len(sig_events)))

                    # Run the agent update handler again, but let ext_gs_updated be False. This should not create any new AgentSignature telemetry
                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), False)
                    sig_events = self._get_signature_telemetry_events(mock_telemetry)
                    self.assertEqual(1, len(sig_events), "Expected exactly one AgentSignature event. Got: {0}".format(len(sig_events)))

    def test_it_should_not_send_signature_telemetry_when_agent_signature_goal_state_telemetry_disabled(self):
        """
        When agent signature goal state telemetry is disabled, no telemetry on agent signature should be emitted.
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM but the agent version in the goal state is not from RSM, so it
        # should not result in an agent update. This unit test is only testing the agent logic to send telemetry on
        # agent signatures in the goal state, so an actual agent update is not needed.
        data_file["ext_conf"] = "wire/ext_conf-two_ga_dummy_signatures.xml"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            # Patch agent_signature_goal_state_telemetry_enabled() and supports_agent_signature_mapping() so that the agent takes
            # the signature validation flow
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=False):
                with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

            sig_events = self._get_signature_telemetry_events(mock_telemetry)
            self.assertEqual(0, len(sig_events), "No AgentSignature events should be emitted when signature validation is disabled")

    def test_it_should_not_send_signature_telemetry_when_goal_state_does_not_support_mapping(self):
        """
        When the extensions goal state does not support agent signature mapping, no telemetry should be emitted.
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM but the agent version in the goal state is not from RSM, so it
        # should not result in an agent update. This unit test is only testing the agent logic to send telemetry on
        # agent signatures in the goal state, so an actual agent update is not needed.
        data_file["ext_conf"] = "wire/ext_conf-two_ga_dummy_signatures.xml"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            # Patch agent_signature_goal_state_telemetry_enabled() and supports_agent_signature_mapping() so that the agent takes
            # the signature validation flow
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=False):
                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

            sig_events = self._get_signature_telemetry_events(mock_telemetry)
            self.assertEqual(0, len(sig_events), "No AgentSignature events should be emitted when goal state doesn't support signature mapping")

    def test_it_should_send_signature_telemetry_on_new_goal_state_with_rsm_version(self):
        """
        When signature validation is enabled, goal state supports agent signature mapping, and this is an RSM
        request with signatures, telemetry should include the signed versions in the goal state and the RSM requested
        version.
        """
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM where the agent version in the goal state is from RSM. As a
        # result, the agent should update to the requested version (9.9.9.10)
        data_file["ext_conf"] = "wire/ext_conf-agent_dummy_signatures_and_version_from_rsm.xml"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            # Patch agent_signature_goal_state_telemetry_enabled() and supports_agent_signature_mapping() so that the agent takes
            # the signature validation flow
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                    with self.assertRaises(AgentUpgradeExitException):
                        agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

            sig_events = self._get_signature_telemetry_events(mock_telemetry)
            self.assertEqual(1, len(sig_events), "Expected exactly one AgentSignature event. Got: {0}".format(len(sig_events)))

            telemetry_data = json.loads(sig_events[0]['message'])
            self.assertEqual(["9.9.9.9", "9.9.9.10"], telemetry_data["versions_with_signatures"], "Telemetry should contain the versions with signatures in the goal state")
            self.assertEqual("9.9.9.10", telemetry_data["rsm_requested_version"], "RSM requested version should be included when this is an RSM request")
            self.assertIsNotNone(telemetry_data["created_on_timestamp"], "Goal state created_on_timestamp should be present")
            self.assertIsNotNone(telemetry_data["activity_id"], "Activity id should be present")

    def test_it_should_send_signature_telemetry_with_empty_signatures(self):
        """
        When signature validation is enabled and goal state supports agent signature mapping but no signatures
        are present, telemetry should be sent with an empty versions_with_signatures list.
        """
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        # The default ext_conf.xml has no VersionToSignatureMappings element, so the parsed signature mapping
        # will be empty.
        data_file["ext_conf"] = "wire/ext_conf.xml"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            # Patch agent_signature_goal_state_telemetry_enabled() and supports_agent_signature_mapping() so that the agent takes
            # the signature validation flow
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                    with self.assertRaises(AgentUpgradeExitException):
                        agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

            sig_events = self._get_signature_telemetry_events(mock_telemetry)
            self.assertEqual(1, len(sig_events), "Expected exactly one AgentSignature event. Got: {0}".format(sig_events))

            telemetry_data = json.loads(sig_events[0]['message'])
            self.assertEqual([], telemetry_data["versions_with_signatures"], "versions_with_signatures should be empty when no signatures are present")
            self.assertEqual("", telemetry_data["rsm_requested_version"], "RSM requested version should be empty str if goal state is not an RSM request")
            self.assertIsNotNone(telemetry_data["created_on_timestamp"], "Goal state created_on_timestamp should be present")
            self.assertIsNotNone(telemetry_data["activity_id"], "Activity id should be present")

    def test_it_should_send_signature_telemetry_with_no_rsm_version_for_update(self):
        """
        When the goal state is not an RSM request, rsm_requested_version should be None.
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM but the agent version in the goal state is not from RSM, so it
        # should not result in an agent update. This unit test is only testing the agent logic to send telemetry on
        # agent signatures in the goal state, so an actual agent update is not needed.
        data_file["ext_conf"] = "wire/ext_conf-two_ga_dummy_signatures.xml"

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            # Patch agent_signature_goal_state_telemetry_enabled() and supports_agent_signature_mapping() so that the agent takes
            # the signature validation flow
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

            sig_events = self._get_signature_telemetry_events(mock_telemetry)
            self.assertEqual(1, len(sig_events), "Expected exactly one AgentSignature event. Got: {0}".format(len(sig_events)))

            telemetry_data = json.loads(sig_events[0]['message'])
            self.assertEqual(["9.9.9.10", "99999.0.0.0"], telemetry_data["versions_with_signatures"], "Telemetry should contain the versions with signatures in the goal state")
            self.assertEqual("", telemetry_data["rsm_requested_version"], "RSM requested version should be empty str when this is not an RSM request")
            self.assertIsNotNone(telemetry_data["created_on_timestamp"], "Goal state created_on_timestamp should be present")
            self.assertIsNotNone(telemetry_data["activity_id"], "Activity id should be present")

    def test_it_should_pass_signature_to_download_when_validation_enabled_and_signature_in_goal_state(self):
        """
        When agent signature validation is enabled and the goal state has a signature for the target version,
        the signature should be passed through to download_zip_package.
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM where the agent version in the goal state is from RSM. As a
        # result, the agent should update to the requested version (9.9.9.10)
        data_file["ext_conf"] = "wire/ext_conf-agent_dummy_signatures_and_version_from_rsm.xml"

        self.prepare_agents(count=1)

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, _):
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.ga.ga_version_updater.agent_signature_validation_enabled", return_value=True):
                    with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                        with patch.object(agent_update_handler._protocol.client, "download_zip_package", wraps=agent_update_handler._protocol.client.download_zip_package) as mock_download:
                            with self.assertRaises(AgentUpgradeExitException):
                                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

                            self.assertEqual(1, mock_download.call_count, "download_zip_package should have been called once")
                            call_kwargs = mock_download.call_args[1]
                            self.assertEqual("MIInpwYJKoZIhvcNAQcCProd99910=", call_kwargs['signature'],
                                                "Signature from the goal state should be passed to download_zip_package")
                            self.assertTrue(call_kwargs['ignore_signature_validation_errors'],
                                            "ignore_signature_validation_errors should be True during telemetry release")

    def test_it_should_pass_empty_signature_to_download_when_validation_disabled(self):
        """
        When agent signature validation is disabled, an empty signature should be passed to download_zip_package.
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM where the agent version in the goal state is from RSM. As a
        # result, the agent should update to the requested version (9.9.9.10)
        data_file["ext_conf"] = "wire/ext_conf-agent_dummy_signatures_and_version_from_rsm.xml"

        self.prepare_agents(count=1)

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, _):
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.ga.ga_version_updater.agent_signature_validation_enabled", return_value=False):
                    with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                        with patch.object(agent_update_handler._protocol.client, "download_zip_package", wraps=agent_update_handler._protocol.client.download_zip_package) as mock_download:
                            with self.assertRaises(AgentUpgradeExitException):
                                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

                            self.assertEqual(1, mock_download.call_count, "download_zip_package should have been called once")
                            call_kwargs = mock_download.call_args[1]
                            self.assertEqual("", call_kwargs['signature'],
                                             "Signature should be empty when validation is disabled")

    def test_it_should_pass_empty_signature_when_version_not_in_goal_state_mapping(self):
        """
        When agent signature validation is enabled but the version being downloaded is not in the goal state
        signature mapping, an empty signature should be passed and telemetry should be sent.
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM where the agent version in the goal state is from RSM. As a
        # result, the agent should update to the requested version (9.9.9.10). However, the signature for 9.9.9.10 is
        # not in the goal state. As a result, agent signature validation should be skipped and telemetry should be sent.
        data_file["ext_conf"] = "wire/ext_conf-agent_dummy_signature_missing_from_gs.xml"

        self.prepare_agents(count=1)

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.ga.ga_version_updater.agent_signature_validation_enabled", return_value=True):
                    with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                        with patch.object(agent_update_handler._protocol.client, "download_zip_package", wraps=agent_update_handler._protocol.client.download_zip_package) as mock_download:
                            with self.assertRaises(AgentUpgradeExitException):
                                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

                            self.assertEqual(1, mock_download.call_count, "download_zip_package should have been called once")
                            call_kwargs = mock_download.call_args[1]
                            self.assertEqual("", call_kwargs['signature'],
                                             "Signature should be empty when version is not in the goal state mapping")

                            # Check that telemetry was sent about the missing signature
                            sig_events = [kwarg for _, kwarg in mock_telemetry.call_args_list
                                          if kwarg.get('op') == WALAEventOperation.SignatureValidation and
                                          "No signature found for agent version" in kwarg.get('message', '')]
                            self.assertEqual(1, len(sig_events),
                                             "Expected one AgentSignature event about missing signature. Got: {0}".format(sig_events))

    def test_it_should_pass_empty_signature_when_goal_state_does_not_support_mapping(self):
        """
        When agent signature validation is enabled but the goal state does not support agent signature mapping,
        an empty signature should be passed and telemetry should be sent.
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM where the agent version in the goal state is from RSM. As a
        # result, the agent should update to the requested version (9.9.9.10)
        data_file["ext_conf"] = "wire/ext_conf-agent_dummy_signatures_and_version_from_rsm.xml"

        self.prepare_agents(count=1)

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.ga.ga_version_updater.agent_signature_validation_enabled", return_value=True):
                    with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=False):
                        with patch.object(agent_update_handler._protocol.client, "download_zip_package", wraps=agent_update_handler._protocol.client.download_zip_package) as mock_download:
                            with self.assertRaises(AgentUpgradeExitException):
                                agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

                            self.assertEqual(1, mock_download.call_count, "download_zip_package should have been called once")
                            call_kwargs = mock_download.call_args[1]
                            self.assertEqual("", call_kwargs['signature'],
                                             "Signature should be empty when goal state does not support signature mapping")

                            # Check that telemetry was sent about unsupported mapping
                            sig_events = [kwarg for _, kwarg in mock_telemetry.call_args_list
                                          if kwarg.get('op') == WALAEventOperation.SignatureValidation and
                                          "Goal state does not support agent signature mapping, skipping agent package " \
                                          "signature validation." in kwarg.get('message', '')]
                            self.assertEqual(1, len(sig_events),
                                             "Expected one AgentSignature event about unsupported mapping. Got: {0}".format(sig_events))

    def test_it_should_pass_empty_signature_when_exception_is_raised_getting_package_signature(self):
        """
        When agent signature validation is enabled but the logic to get the agent package signature from the goal state
        results in an unexpected Exception, an empty signature should be passed and telemetry should be sent.
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM where the agent version in the goal state is from RSM. As a
        # result, the agent should update to the requested version (9.9.9.10)
        data_file["ext_conf"] = "wire/ext_conf-agent_dummy_signatures_and_version_from_rsm.xml"

        self.prepare_agents(count=1)

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.ga.ga_version_updater.agent_signature_validation_enabled", return_value=True):
                    with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                        with patch("azurelinuxagent.ga.ga_version_updater.GAVersionUpdater._get_agent_package_signature", side_effect=Exception("test error")):
                            with patch.object(agent_update_handler._protocol.client, "download_zip_package", wraps=agent_update_handler._protocol.client.download_zip_package) as mock_download:
                                with self.assertRaises(AgentUpgradeExitException):
                                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

                                self.assertEqual(1, mock_download.call_count, "download_zip_package should have been called once")
                                call_kwargs = mock_download.call_args[1]
                                self.assertEqual("", call_kwargs['signature'],
                                                 "Signature should be empty when goal state does not support signature mapping")

                                # Check that telemetry was sent about unsupported mapping
                                sig_events = [kwarg for _, kwarg in mock_telemetry.call_args_list
                                              if kwarg.get('op') == WALAEventOperation.SignatureValidation and
                                              "Unexpected error getting the agent package signature, skipping agent " \
                                              "package signature validation:" in kwarg.get('message', '')]
                                self.assertEqual(1, len(sig_events),
                                                 "Expected one AgentSignature event about unexpected error. Got: {0}".format(sig_events))

    def test_it_should_continue_update_on_signature_validation_error(self):
        """
        When agent signature validation is enabled but a SignatureValidationError is raised when downloading the agent
        package, the agent should continue the update but send telemetry on the error
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM where the agent version in the goal state is from RSM. As a
        # result, the agent should update to the requested version (9.9.9.10)
        data_file["ext_conf"] = "wire/ext_conf-agent_dummy_signatures_and_version_from_rsm.xml"

        self.prepare_agents(count=1)

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.ga.ga_version_updater.agent_signature_validation_enabled", return_value=True):
                    with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                        with patch("azurelinuxagent.common.protocol.wire.validate_signature", side_effect=SignatureValidationError(msg="test error", operation=WALAEventOperation.PackageSignatureResult, duration=0)):
                            with patch.object(agent_update_handler._protocol.client, "download_zip_package", wraps=agent_update_handler._protocol.client.download_zip_package) as mock_download:
                                with self.assertRaises(AgentUpgradeExitException):
                                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

                                self.assertEqual(1, mock_download.call_count, "download_zip_package should have been called once")
                                call_kwargs = mock_download.call_args[1]
                                self.assertEqual("MIInpwYJKoZIhvcNAQcCProd99910=", call_kwargs['signature'],
                                                 "Signature from the goal state should be passed to download_zip_package")
                                self.assertTrue(call_kwargs['ignore_signature_validation_errors'],
                                                "ignore_signature_validation_errors should be True during telemetry release")

                                # Check that telemetry was sent about the validation error
                                sig_events = [kwarg for _, kwarg in mock_telemetry.call_args_list
                                              if kwarg.get('op') == WALAEventOperation.PackageSignatureResult and
                                              "test error" in kwarg.get('message', '')]
                                self.assertEqual(1, len(sig_events),
                                                 "Expected one PackageSignatureResult event about validation error. Got: {0}".format(sig_events))

    def test_it_should_continue_update_on_signature_validation_timeout_error_and_disable_feature(self):
        """
        When agent signature validation is enabled but a SignatureValidationTimeoutError is raised when downloading the
        agent package, the agent should continue the update but send telemetry on the error and disable the feature.
        """
        data_file = DATA_FILE.copy()
        # This goal state is for a VM enrolled into RSM where the agent version in the goal state is from RSM. As a
        # result, the agent should update to the requested version (9.9.9.10)
        data_file["ext_conf"] = "wire/ext_conf-agent_dummy_signatures_and_version_from_rsm.xml"

        self.prepare_agents(count=1)

        with self._get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch("azurelinuxagent.ga.agent_update_handler.agent_signature_goal_state_telemetry_enabled", return_value=True):
                with patch("azurelinuxagent.ga.signature_validation_util.conf.get_agent_signature_validation_enabled", return_value=True):
                    with patch("azurelinuxagent.ga.signature_validation_util._should_delay_signature_validation", return_value=False):
                        with patch("azurelinuxagent.ga.signature_validation_util.openssl_version_supported_for_signature_validation", return_value=True):
                            with patch("azurelinuxagent.ga.signature_validation_util.ConfidentialVMInfo.is_confidential_vm", return_value=True):
                                with patch("azurelinuxagent.ga.signature_validation_util._is_signature_validation_telemetry_expired", return_value=False):
                                    with patch("azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config.ExtensionsGoalStateFromExtensionsConfig.supports_agent_signature_mapping", return_value=True):
                                        with patch("azurelinuxagent.common.protocol.wire.validate_signature", side_effect=SignatureValidationTimeoutError(msg="test error", operation=WALAEventOperation.PackageSignatureResult, duration=0)):
                                            with patch.object(agent_update_handler._protocol.client, "download_zip_package", wraps=agent_update_handler._protocol.client.download_zip_package) as mock_download:
                                                # Agent validation should not be disabled due to timeout before the validation attempt
                                                self.assertFalse(SignatureValidationTimeout.is_agent_validation_disabled())
                                                with self.assertRaises(AgentUpgradeExitException):
                                                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

                                                self.assertEqual(1, mock_download.call_count, "download_zip_package should have been called once")
                                                call_kwargs = mock_download.call_args[1]
                                                self.assertEqual("MIInpwYJKoZIhvcNAQcCProd99910=", call_kwargs['signature'],
                                                                 "Signature from the goal state should be passed to download_zip_package")
                                                self.assertTrue(call_kwargs['ignore_signature_validation_errors'],
                                                                "ignore_signature_validation_errors should be True during telemetry release")

                                                # Check that package signature result telemetry was sent about the validation timeout error
                                                sig_events = [kwarg for _, kwarg in mock_telemetry.call_args_list
                                                              if kwarg.get('op') == WALAEventOperation.PackageSignatureResult and
                                                              "test error" in kwarg.get('message', '')]
                                                self.assertEqual(1, len(sig_events), "Expected one PackageSignatureResult event about unexpected error. Got: {0}".format(sig_events))

                                                # Check that agent validation was disabled due to the timeout
                                                self.assertTrue(SignatureValidationTimeout.is_agent_validation_disabled())
                                                sig_events = [kwarg for _, kwarg in mock_telemetry.call_args_list
                                                              if kwarg.get('op') == WALAEventOperation.SignatureValidation and
                                                              "Agent signature validation timeout exceeded. Disabling " \
                                                              "agent signature validation until agent restart" in kwarg.get('message', '')]
                                                self.assertEqual(1, len(sig_events),
                                                                 "Expected one SignatureValidation event about timeout error. Got: {0}".format(
                                                                     sig_events))

                                            with patch.object(agent_update_handler._protocol.client, "download_zip_package", wraps=agent_update_handler._protocol.client.download_zip_package) as mock_download:
                                                # The signature passed to download_zip_package on this invocation of run should be "" since
                                                # agent package validation is disabled now
                                                # Remove the agent directory to trigger the update logic again
                                                agent_dir = self.agent_dir("9.9.9.10")
                                                if os.path.exists(agent_dir):
                                                    shutil.rmtree(agent_dir)
                                                with self.assertRaises(AgentUpgradeExitException):
                                                    agent_update_handler.run(GoalState(agent_update_handler._protocol.client, GoalStateProperties.ExtensionsGoalState), True)

                                                self.assertEqual(1, mock_download.call_count, "download_zip_package should have been called once")
                                                call_kwargs = mock_download.call_args[1]
                                                self.assertEqual("",
                                                                 call_kwargs['signature'],
                                                                 "Signature should be empty string since timeout is exceeded")
                                                self.assertTrue(call_kwargs['ignore_signature_validation_errors'],
                                                                "ignore_signature_validation_errors should be True during telemetry release")

                                            # Reset the timeout flag so it doesn't affect other unit tests
                                            SignatureValidationTimeout._agent_validation_disabled = False
