import contextlib
import json
import os

from azurelinuxagent.common import conf
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, UpdateError
from azurelinuxagent.common.future import ustr, httpclient
from azurelinuxagent.common.protocol.restapi import ExtHandlerPackage, VMAgentUpdateStatuses

from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.version import CURRENT_VERSION, AGENT_NAME
from azurelinuxagent.ga.agent_update import get_agent_update_handler, GuestAgent, AGENT_MANIFEST_FILE, AGENT_ERROR_FILE, \
    MAX_FAILURE, GuestAgentError
from tests.ga.test_update import UpdateTestCase, EMPTY_MANIFEST, WITH_ERROR, NO_ERROR
from tests.protocol import mockwiredata
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

    def test_it_should_not_update_when_autoupdate_disabled(self):
        self.prepare_agents(count=1)
        with self.__get_agent_update_handler(autoupdate_enabled=False) as (agent_update_handler, mock_telemetry):
            agent_update_handler.run()
            self.__assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
            self.assertEqual(0, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "Found requested version" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "Unwanted upgrade")

    def test_it_should_not_agent_update_if_last_attempted_update_time_not_elapsed(self):
        self.prepare_agents(count=1)
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"
        version = "5.2.0.1"
        with self.__get_agent_update_handler(test_data=data_file, autoupdate_frequency=10) as (agent_update_handler, mock_telemetry):
            with patch.object(conf, "get_enable_ga_versioning", return_value=True):
                agent_update_handler._protocol.mock_wire_data.set_extension_config_requested_version(version)
                agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
                agent_update_handler._protocol.update_goal_state()
                agent_update_handler.run()

                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "Found requested version: {0}".format(version) in kwarg[
                                             'message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]), "invalid message")

                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "Unable to update Agent: No matching package found in the agent manifest for requested version: {0}".format(version) in kwarg[
                                             'message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]), "invalid message")
                # Now we shouldn't check for download if update not allowed.This run should not add new logs
                agent_update_handler.run()
                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "Found requested version" in kwarg['message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]), "invalid message")
                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "Unable to update Agent: No matching package found in the agent manifest for requested version: {0}".format(version) in kwarg[
                                             'message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]), "invalid message")

    def test_it_should_not_update_if_requested_version_not_available(self):
        self.prepare_agents(count=1)

        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf.xml"
        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            agent_update_handler.run()

            self.assertEqual(0, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                     "Found requested version:" in kwarg['message'] and kwarg[
                                         'op'] == WALAEventOperation.AgentUpgrade]), "Unwanted upgrade")
            self.__assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])

    def test_it_should_not_agent_update_if_requested_version_is_same_as_current_version(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch.object(conf, "get_enable_ga_versioning", return_value=True):
                agent_update_handler._protocol.mock_wire_data.set_extension_config_requested_version(
                    str(CURRENT_VERSION))
                agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
                agent_update_handler._protocol.update_goal_state()
                agent_update_handler.run()
                self.assertEqual(0, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "Found requested version" in kwarg['message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]), "Unwanted upgrade")
                self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                                 "New agent directory should not be found")

    def test_it_should_upgrade_agent_if_requested_version_is_available_greater_than_current_version(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch.object(conf, "get_enable_ga_versioning", return_value=True):
                with self.assertRaises(AgentUpgradeExitException) as context:
                    agent_update_handler.run()
                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "Found requested version: 9.9.9.10" in kwarg['message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]), "Unwanted upgrade")
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
            with patch.object(conf, "get_enable_ga_versioning", return_value=True):
                agent_update_handler._protocol.mock_wire_data.set_extension_config_requested_version(downgraded_version)
                agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
                agent_update_handler._protocol.update_goal_state()
                with self.assertRaises(AgentUpgradeExitException) as context:
                    agent_update_handler.run()
                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "Found requested version: {0}".format(downgraded_version) in kwarg[
                                             'message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]), "Unwanted upgrade")
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
            with patch.object(conf, "get_enable_ga_versioning", return_value=True):
                agent_update_handler._protocol.mock_wire_data.set_extension_config_requested_version(version)
                agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
                agent_update_handler._protocol.update_goal_state()
                agent_update_handler.run()

                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "Found requested version: {0}".format(version) in kwarg[
                                             'message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]), "Unwanted upgrade")
                self.assertFalse(os.path.exists(self.agent_dir(version)),
                                 "New agent directory should not be found")

                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "Unable to update Agent: No matching package found in the agent manifest for requested version: {0}".format(version) in kwarg[
                                             'message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]), "Unwanted upgrade")

    def test_handles_missing_agent_family(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_missing_family.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, mock_telemetry):
            with patch.object(conf, "get_enable_ga_versioning", return_value=True):
                agent_update_handler.run()

                self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                                 "New agent directory should not be found")

                self.assertEqual(1, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                         "No manifest links found for agent family" in kwarg[
                                             'message'] and kwarg[
                                             'op'] == WALAEventOperation.AgentUpgrade]), "Unwanted upgrade")

    def test_it_should_report_update_status_with_success(self):
        data_file = DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        with self.__get_agent_update_handler(test_data=data_file) as (agent_update_handler, _):
            with patch.object(conf, "get_enable_ga_versioning", return_value=True):
                agent_update_handler._protocol.mock_wire_data.set_extension_config_requested_version(
                    str(CURRENT_VERSION))
                agent_update_handler._protocol.mock_wire_data.set_incarnation(2)
                agent_update_handler._protocol.update_goal_state()
                vm_agent_update_status = agent_update_handler.get_vmagent_update_status(gs_updated=True)
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
                            agent_update_handler = get_agent_update_handler(protocol)
                            yield agent_update_handler

        with mock_agent_update_handler(test_data=data_file) as (agent_update_handler):
            with patch.object(conf, "get_enable_ga_versioning", return_value=True):
                agent_update_handler.run()
                vm_agent_update_status = agent_update_handler.get_vmagent_update_status(gs_updated=True)
                self.assertEqual(VMAgentUpdateStatuses.Error, vm_agent_update_status.status)
                self.assertEqual(1, vm_agent_update_status.code)
                self.assertEqual("9.9.9.10", vm_agent_update_status.expected_version)
                self.assertIn("Unable to download Agent", vm_agent_update_status.message)


class TestGuestAgent(UpdateTestCase):
    def setUp(self):
        UpdateTestCase.setUp(self)
        self.copy_agents(self._get_agent_file_path())
        self.agent_path = os.path.join(self.tmp_dir, self._get_agent_name())

    def test_creation(self):
        with self.assertRaises(UpdateError):
            GuestAgent.from_installed_agent("A very bad file name")

        with self.assertRaises(UpdateError):
            GuestAgent.from_installed_agent("{0}-a.bad.version".format(AGENT_NAME))

        self.expand_agents()

        agent = GuestAgent.from_installed_agent(self.agent_path)
        self.assertNotEqual(None, agent)
        self.assertEqual(self._get_agent_name(), agent.name)
        self.assertEqual(self._get_agent_version(), agent.version)

        self.assertEqual(self.agent_path, agent.get_agent_dir())

        path = os.path.join(self.agent_path, AGENT_MANIFEST_FILE)
        self.assertEqual(path, agent.get_agent_manifest_path())

        self.assertEqual(
            os.path.join(self.agent_path, AGENT_ERROR_FILE),
            agent.get_agent_error_file())

        path = ".".join((os.path.join(conf.get_lib_dir(), self._get_agent_name()), "zip"))
        self.assertEqual(path, agent.get_agent_pkg_path())

        self.assertTrue(agent.is_downloaded)
        self.assertFalse(agent.is_blacklisted)
        self.assertTrue(agent.is_available)

    def test_clear_error(self):
        self.expand_agents()

        agent = GuestAgent.from_installed_agent(self.agent_path)
        agent.mark_failure(is_fatal=True)

        self.assertTrue(agent.error.last_failure > 0.0)
        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)

        agent.clear_error()
        self.assertEqual(0.0, agent.error.last_failure)
        self.assertEqual(0, agent.error.failure_count)
        self.assertFalse(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)

    def test_is_available(self):
        self.expand_agents()

        agent = GuestAgent.from_installed_agent(self.agent_path)

        self.assertTrue(agent.is_available)
        agent.mark_failure(is_fatal=True)
        self.assertFalse(agent.is_available)

    def test_is_blacklisted(self):
        self.expand_agents()

        agent = GuestAgent.from_installed_agent(self.agent_path)
        self.assertFalse(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)

        agent.mark_failure(is_fatal=True)
        self.assertTrue(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)

    def test_is_downloaded(self):
        self.expand_agents()
        agent = GuestAgent.from_installed_agent(self.agent_path)
        self.assertTrue(agent.is_downloaded)

    def test_mark_failure(self):
        agent = GuestAgent.from_installed_agent(self.agent_path)

        agent.mark_failure()
        self.assertEqual(1, agent.error.failure_count)

        agent.mark_failure(is_fatal=True)
        self.assertEqual(2, agent.error.failure_count)
        self.assertTrue(agent.is_blacklisted)

    def test_load_manifest(self):
        self.expand_agents()
        agent = GuestAgent.from_installed_agent(self.agent_path)
        agent._load_manifest()
        self.assertEqual(agent.manifest.get_enable_command(),
                         agent.get_agent_cmd())

    def test_load_manifest_missing(self):
        self.expand_agents()
        agent = GuestAgent.from_installed_agent(self.agent_path)
        os.remove(agent.get_agent_manifest_path())
        self.assertRaises(UpdateError, agent._load_manifest)

    def test_load_manifest_is_empty(self):
        self.expand_agents()
        agent = GuestAgent.from_installed_agent(self.agent_path)
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

        with open(agent.get_agent_manifest_path(), "w") as file:  # pylint: disable=redefined-builtin
            json.dump(EMPTY_MANIFEST, file)
        self.assertRaises(UpdateError, agent._load_manifest)

    def test_load_manifest_is_malformed(self):
        self.expand_agents()
        agent = GuestAgent.from_installed_agent(self.agent_path)
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

        with open(agent.get_agent_manifest_path(), "w") as file:  # pylint: disable=redefined-builtin
            file.write("This is not JSON data")
        self.assertRaises(UpdateError, agent._load_manifest)

    def test_load_error(self):
        agent = GuestAgent.from_installed_agent(self.agent_path)
        agent.error = None

        agent._load_error()
        self.assertTrue(agent.error is not None)

    def test_download(self):
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        agent_uri = 'https://foo.blob.core.windows.net/bar/OSTCExtensions.WALinuxAgent__1.0.0'

        def http_get_handler(uri, *_, **__):
            if uri == agent_uri:
                response = load_bin_data(self._get_agent_file_name(), self._agent_zip_dir)
                return MockHttpResponse(status=httpclient.OK, body=response)
            return None

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(agent_uri)

        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.set_http_handlers(http_get_handler=http_get_handler)
            agent = GuestAgent.from_agent_package(pkg, protocol, False)

        self.assertTrue(os.path.isdir(agent.get_agent_dir()))
        self.assertTrue(agent.is_downloaded)

    def test_download_fail(self):
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        agent_uri = 'https://foo.blob.core.windows.net/bar/OSTCExtensions.WALinuxAgent__1.0.0'

        def http_get_handler(uri, *_, **__):
            if uri in (agent_uri, 'http://168.63.129.16:32526/extensionArtifact'):
                return MockHttpResponse(status=httpclient.SERVICE_UNAVAILABLE)
            return None

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(agent_uri)

        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.set_http_handlers(http_get_handler=http_get_handler)
            with patch("azurelinuxagent.ga.agent_update.add_event") as add_event:
                agent = GuestAgent.from_agent_package(pkg, protocol, False)

        self.assertFalse(os.path.isfile(self.agent_path))

        messages = [kwargs['message'] for _, kwargs in add_event.call_args_list if kwargs['op'] == 'Install' and kwargs['is_success'] == False]
        self.assertEqual(1, len(messages), "Expected exactly 1 install error/ Got: {0}".format(add_event.call_args_list))
        self.assertIn('[UpdateError] Unable to download Agent WALinuxAgent-9.9.9.9', messages[0], "The install error does not include the expected message")

        self.assertFalse(agent.is_blacklisted, "Download failures should not blacklist the Agent")

    def test_invalid_agent_package_does_not_blacklist_the_agent(self):
        agent_uri = 'https://foo.blob.core.windows.net/bar/OSTCExtensions.WALinuxAgent__9.9.9.9'

        def http_get_handler(uri, *_, **__):
            if uri in (agent_uri, 'http://168.63.129.16:32526/extensionArtifact'):
                response = load_bin_data("ga/WALinuxAgent-9.9.9.9-no_manifest.zip")
                return MockHttpResponse(status=httpclient.OK, body=response)
            return None

        pkg = ExtHandlerPackage(version="9.9.9.9")
        pkg.uris.append(agent_uri)

        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.set_http_handlers(http_get_handler=http_get_handler)
            agent = GuestAgent.from_agent_package(pkg, protocol, False)

        self.assertFalse(agent.is_blacklisted, "The agent should not be blacklisted if unable to unpack/download")
        self.assertFalse(os.path.exists(agent.get_agent_dir()), "Agent directory should be cleaned up")

    @patch("azurelinuxagent.ga.update.GuestAgent._download")
    def test_ensure_download_skips_blacklisted(self, mock_download):
        agent = GuestAgent.from_installed_agent(self.agent_path)
        self.assertEqual(0, mock_download.call_count)

        agent.clear_error()
        agent.mark_failure(is_fatal=True)
        self.assertTrue(agent.is_blacklisted)

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(None)
        # _download is mocked so there will be no http request; passing a None protocol
        agent = GuestAgent.from_agent_package(pkg, None, False)

        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.error.was_fatal)
        self.assertTrue(agent.is_blacklisted)
        self.assertEqual(0, mock_download.call_count)


class TestGuestAgentError(UpdateTestCase):
    def test_creation(self):
        self.assertRaises(TypeError, GuestAgentError)
        self.assertRaises(UpdateError, GuestAgentError, None)

        with self.get_error_file(error_data=WITH_ERROR) as path:
            err = GuestAgentError(path.name)
            err.load()
            self.assertEqual(path.name, err.path)
        self.assertNotEqual(None, err)

        self.assertEqual(WITH_ERROR["last_failure"], err.last_failure)
        self.assertEqual(WITH_ERROR["failure_count"], err.failure_count)
        self.assertEqual(WITH_ERROR["was_fatal"], err.was_fatal)
        return

    def test_clear(self):
        with self.get_error_file(error_data=WITH_ERROR) as path:
            err = GuestAgentError(path.name)
            err.load()
            self.assertEqual(path.name, err.path)
        self.assertNotEqual(None, err)

        err.clear()
        self.assertEqual(NO_ERROR["last_failure"], err.last_failure)
        self.assertEqual(NO_ERROR["failure_count"], err.failure_count)
        self.assertEqual(NO_ERROR["was_fatal"], err.was_fatal)
        return

    def test_save(self):
        err1 = self.create_error()
        err1.mark_failure()
        err1.mark_failure(is_fatal=True)

        err2 = self.create_error(err1.to_json())
        self.assertEqual(err1.last_failure, err2.last_failure)
        self.assertEqual(err1.failure_count, err2.failure_count)
        self.assertEqual(err1.was_fatal, err2.was_fatal)

    def test_mark_failure(self):
        err = self.create_error()
        self.assertFalse(err.is_blacklisted)

        for i in range(0, MAX_FAILURE):  # pylint: disable=unused-variable
            err.mark_failure()

        # Agent failed >= MAX_FAILURE, it should be blacklisted
        self.assertTrue(err.is_blacklisted)
        self.assertEqual(MAX_FAILURE, err.failure_count)
        return

    def test_mark_failure_permanent(self):
        err = self.create_error()

        self.assertFalse(err.is_blacklisted)

        # Fatal errors immediately blacklist
        err.mark_failure(is_fatal=True)
        self.assertTrue(err.is_blacklisted)
        self.assertTrue(err.failure_count < MAX_FAILURE)
        return

    def test_str(self):
        err = self.create_error(error_data=NO_ERROR)
        s = "Last Failure: {0}, Total Failures: {1}, Fatal: {2}, Reason: {3}".format(
            NO_ERROR["last_failure"],
            NO_ERROR["failure_count"],
            NO_ERROR["was_fatal"],
            NO_ERROR["reason"])
        self.assertEqual(s, str(err))

        err = self.create_error(error_data=WITH_ERROR)
        s = "Last Failure: {0}, Total Failures: {1}, Fatal: {2}, Reason: {3}".format(
            WITH_ERROR["last_failure"],
            WITH_ERROR["failure_count"],
            WITH_ERROR["was_fatal"],
            WITH_ERROR["reason"])
        self.assertEqual(s, str(err))
        return
