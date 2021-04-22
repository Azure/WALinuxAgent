import os.path

import contextlib

import json
import subprocess

from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import GoalStateAggregateStatusCodes
from azurelinuxagent.common.protocol.restapi import ExtHandlerRequestedState, ExtensionState, ExtensionStatus
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.ga.exthandlers import get_exthandlers_handler, ValidHandlerStatus, ExtCommandEnvVariable, \
    parse_ext_status, GoalStateStatus
from tests.ga.extension_emulator import enable_invocations, extension_emulator, ExtensionCommandNames, Actions, \
    extract_extension_info_from_command
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates, MockHttpResponse
from tests.protocol.mockwiredata import DATA_FILE, WireProtocolData
from tests.tools import AgentTestCase, mock_sleep, patch


class TestMultiConfigExtensionsConfigParsing(AgentTestCase):

    _MULTI_CONFIG_TEST_DATA = os.path.join("wire", "multi-config")

    def setUp(self):
        AgentTestCase.setUp(self)
        self.mock_sleep = patch("time.sleep", lambda *_: mock_sleep(0.0001))
        self.mock_sleep.start()
        self.test_data = DATA_FILE.copy()

    def tearDown(self):
        self.mock_sleep.stop()
        AgentTestCase.tearDown(self)

    class _TestExtHandlerObject:
        def __init__(self, name, version, state="enabled"):
            self.name = name
            self.version = version
            self.state = state
            self.is_invalid_setting = False
            self.extensions = dict()

    class _TestExtensionObject:
        def __init__(self, name, seq_no, dependency_level="0", state="enabled"):
            self.name = name
            self.seq_no = seq_no
            self.dependency_level = int(dependency_level)
            self.state = state

    def _mock_and_assert_ext_handlers(self, expected_handlers):
        with mock_wire_protocol(self.test_data) as protocol:
            ext_handlers, _ = protocol.get_ext_handlers()
            for ext_handler in ext_handlers.extHandlers:
                if ext_handler.name not in expected_handlers:
                    continue
                expected_handler = expected_handlers.pop(ext_handler.name)
                self.assertEqual(expected_handler.state, ext_handler.properties.state)
                self.assertEqual(expected_handler.version, ext_handler.properties.version)
                self.assertEqual(expected_handler.is_invalid_setting, ext_handler.is_invalid_setting)
                self.assertEqual(len(expected_handler.extensions), len(ext_handler.properties.extensions))

                for extension in ext_handler.properties.extensions:
                    self.assertIn(extension.name, expected_handler.extensions)
                    expected_extension = expected_handler.extensions.pop(extension.name)
                    self.assertEqual(expected_extension.seq_no, extension.sequenceNumber)
                    self.assertEqual(expected_extension.state, extension.state)
                    self.assertEqual(expected_extension.dependency_level, extension.dependencyLevel)

                self.assertEqual(0, len(expected_handler.extensions), "All extensions not verified for handler")

            self.assertEqual(0, len(expected_handlers), "All handlers not verified")

    def _get_mock_expected_handler_data(self, rc_extensions, vmaccess_extensions, geneva_extensions):
        # Set expected handler data
        run_command_test_handler = self._TestExtHandlerObject("Microsoft.CPlat.Core.RunCommandHandlerWindows", "2.3.0")
        run_command_test_handler.extensions.update(rc_extensions)

        vm_access_test_handler = self._TestExtHandlerObject("Microsoft.Compute.VMAccessAgent", "2.4.7")
        vm_access_test_handler.extensions.update(vmaccess_extensions)

        geneva_test_handler = self._TestExtHandlerObject("Microsoft.Azure.Geneva.GenevaMonitoring", "2.20.0.1")
        geneva_test_handler.extensions.update(geneva_extensions)

        expected_handlers = {
            run_command_test_handler.name: run_command_test_handler,
            vm_access_test_handler.name: vm_access_test_handler,
            geneva_test_handler.name: geneva_test_handler
        }
        return expected_handlers

    def test_it_should_parse_multi_config_settings_properly(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, "ext_conf_with_multi_config.xml")

        rc_extensions = dict()
        rc_extensions["firstRunCommand"] = self._TestExtensionObject(name="firstRunCommand", seq_no="2")
        rc_extensions["secondRunCommand"] = self._TestExtensionObject(name="secondRunCommand", seq_no="2",
                                                                      dependency_level="3")
        rc_extensions["thirdRunCommand"] = self._TestExtensionObject(name="thirdRunCommand", seq_no="1",
                                                                     dependency_level="4")

        vmaccess_extensions = {
            "Microsoft.Compute.VMAccessAgent": self._TestExtensionObject(name="Microsoft.Compute.VMAccessAgent",
                                                                         seq_no="1", dependency_level="2")}

        geneva_extensions = {"Microsoft.Azure.Geneva.GenevaMonitoring": self._TestExtensionObject(
            name="Microsoft.Azure.Geneva.GenevaMonitoring", seq_no="1")}

        expected_handlers = self._get_mock_expected_handler_data(rc_extensions, vmaccess_extensions, geneva_extensions)
        self._mock_and_assert_ext_handlers(expected_handlers)

    def test_it_should_parse_multi_config_with_disable_state_properly(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_with_disabled_multi_config.xml")

        rc_extensions = dict()
        rc_extensions["firstRunCommand"] = self._TestExtensionObject(name="firstRunCommand", seq_no="3")
        rc_extensions["secondRunCommand"] = self._TestExtensionObject(name="secondRunCommand", seq_no="3",
                                                                      dependency_level="1")
        rc_extensions["thirdRunCommand"] = self._TestExtensionObject(name="thirdRunCommand", seq_no="1",
                                                                     dependency_level="4", state="disabled")

        vmaccess_extensions = {
            "Microsoft.Compute.VMAccessAgent": self._TestExtensionObject(name="Microsoft.Compute.VMAccessAgent",
                                                                         seq_no="2", dependency_level="2")}

        geneva_extensions = {"Microsoft.Azure.Geneva.GenevaMonitoring": self._TestExtensionObject(
            name="Microsoft.Azure.Geneva.GenevaMonitoring", seq_no="2")}

        expected_handlers = self._get_mock_expected_handler_data(rc_extensions, vmaccess_extensions, geneva_extensions)
        self._mock_and_assert_ext_handlers(expected_handlers)


class TestMultiConfigExtensions(AgentTestCase):

    _MULTI_CONFIG_TEST_DATA = os.path.join("wire", "multi-config")

    def setUp(self):
        AgentTestCase.setUp(self)
        self.mock_sleep = patch("time.sleep", lambda *_: mock_sleep(0.01))
        self.mock_sleep.start()
        self.test_data = DATA_FILE.copy()

    def tearDown(self):
        self.mock_sleep.stop()
        AgentTestCase.tearDown(self)

    @contextlib.contextmanager
    def _setup_test_env(self):
        with mock_wire_protocol(self.test_data) as protocol:

            def mock_http_put(url, *args, **_):
                if HttpRequestPredicates.is_host_plugin_status_request(url):
                    # Skip reading the HostGA request data as its encoded
                    return MockHttpResponse(status=500)
                protocol.aggregate_status = json.loads(args[0])
                return MockHttpResponse(status=201)

            with patch("azurelinuxagent.common.agent_supported_feature._MultiConfigFeature.is_supported", True):
                protocol.aggregate_status = None
                protocol.set_http_handlers(http_put_handler=mock_http_put)
                exthandlers_handler = get_exthandlers_handler(protocol)
                no_of_extensions = protocol.mock_wire_data.get_no_of_extensions_in_config()
                yield exthandlers_handler, protocol, no_of_extensions

    def __assert_and_get_handler_status(self, aggregate_status, handler_name="OSTCExtensions.ExampleHandlerLinux",
                                        handler_version="1.0.0", status="Ready", expected_count=1, message=None):
        self.assertIsNotNone(aggregate_status['aggregateStatus'], "No aggregate status found")
        handlers = [handler for handler in aggregate_status['aggregateStatus']['handlerAggregateStatus'] if
                    handler_name == handler['handlerName'] and handler_version == handler['handlerVersion']]
        self.assertEqual(expected_count, len(handlers), "Unexpected extension count")
        self.assertTrue(all(handler['status'] == status for handler in handlers),
                        "Unexpected Status reported for handler {0}".format(handler_name))
        if message is not None:
            self.assertTrue(all(message in handler['formattedMessage']['message'] for handler in handlers),
                            "Status Message mismatch")
        return handlers

    def __assert_extension_status(self, handler_statuses, expected_ext_status, multi_config=False):
        for ext_name, settings_status in expected_ext_status.items():
            ext_status = next(handler for handler in handler_statuses if
                              handler['runtimeSettingsStatus']['settingsStatus']['status']['name'] == ext_name)
            ext_runtime_status = ext_status['runtimeSettingsStatus']
            self.assertIsNotNone(ext_runtime_status, "Extension not found")
            self.assertEqual(settings_status['seq_no'], ext_runtime_status['sequenceNumber'], "Sequence no mismatch")
            self.assertEqual(settings_status['status'], ext_runtime_status['settingsStatus']['status']['status'],
                             "status mismatch")

            if settings_status['message'] is not None:
                self.assertIn(settings_status['message'],
                              ext_runtime_status['settingsStatus']['status']['formattedMessage']['message'],
                              "message mismatch")

            if multi_config:
                self.assertEqual(ext_name, ext_runtime_status['extensionName'], "ext name mismatch")
            else:
                self.assertNotIn('extensionName', ext_runtime_status, "Extension name should not be reported for SC")

            handler_statuses.remove(ext_status)

        self.assertEqual(0, len(handler_statuses), "Unexpected extensions left for handler")

    def __assert_extension_not_present(self, handlers, extensions):
        for ext_name in extensions:
            self.assertFalse(all(
                'runtimeSettingsStatus' in handler and 'extensionName' in handler['runtimeSettingsStatus']
                and handler['runtimeSettingsStatus']['extensionName'] == ext_name for
                handler in handlers), "Extension status found")

    @contextlib.contextmanager
    def __setup_generic_test_env(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")

        first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension")
        second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension")
        third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension")
        fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension")

        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            with enable_invocations(first_ext, second_ext, third_ext, fourth_ext) as invocation_record:
                exthandlers_handler.run()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")
                invocation_record.compare(
                    (first_ext, ExtensionCommandNames.INSTALL),
                    (first_ext, ExtensionCommandNames.ENABLE),
                    (second_ext, ExtensionCommandNames.ENABLE),
                    (third_ext, ExtensionCommandNames.ENABLE),
                    (fourth_ext, ExtensionCommandNames.INSTALL),
                    (fourth_ext, ExtensionCommandNames.ENABLE)
                )

            mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                               handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                               expected_count=3, status="Ready")
            expected_extensions = {
                "firstExtension": {"status": ValidHandlerStatus.success, "seq_no": 1, "message": None},
                "secondExtension": {"status": ValidHandlerStatus.success, "seq_no": 2, "message": None},
                "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 3, "message": None},
            }
            self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)

            sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="Microsoft.Powershell.ExampleExtension")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 9,
                                                          "message": None}
            }
            self.__assert_extension_status(sc_handler, expected_extensions)

            yield exthandlers_handler, protocol, [first_ext, second_ext, third_ext, fourth_ext]

    def test_it_should_execute_and_report_multi_config_extensions_properly(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):

            # Case 1: Install and enable Single and MultiConfig extensions
            exthandlers_handler.run()
            self.assertEqual(no_of_extensions,
                             len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                             "incorrect extensions reported")
            mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                               handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                               status="Ready", expected_count=3)
            expected_extensions = {
                "firstExtension": {"status": ValidHandlerStatus.success, "seq_no": 1, "message": None},
                "secondExtension": {"status": ValidHandlerStatus.success, "seq_no": 2, "message": None},
                "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 3, "message": None},
            }
            self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="Microsoft.Powershell.ExampleExtension",
                                                              status="Ready")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 9,
                                                          "message": None}
            }
            self.__assert_extension_status(sc_handler, expected_extensions)

            # Case 2: Disable 2 multi-config extensions and add another for enable
            self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, 'ext_conf_mc_disabled_extensions.xml')
            protocol.mock_wire_data = WireProtocolData(self.test_data)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.update_goal_state()
            exthandlers_handler.run()

            mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                               handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                               status="Ready", expected_count=2)
            expected_extensions = {
                "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 99, "message": None},
                "fourthExtension": {"status": ValidHandlerStatus.success, "seq_no": 101, "message": None},
            }
            self.__assert_extension_not_present(mc_handlers, ["firstExtension", "secondExtension"])
            self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="Microsoft.Powershell.ExampleExtension",
                                                              status="Ready")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 10,
                                                          "message": None}
            }
            self.__assert_extension_status(sc_handler, expected_extensions)

            # Case 3: Uninstall Multi-config handler (with enabled extensions) and single config extension
            protocol.mock_wire_data.set_incarnation(3)
            protocol.mock_wire_data.set_extensions_config_state(ExtHandlerRequestedState.Uninstall)
            protocol.update_goal_state()
            exthandlers_handler.run()
            self.assertEqual(0, len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                             "No handler/extension status should be reported")

    def test_it_should_report_unregistered_version_error_per_extension(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            # Set a random failing extension
            failing_version = "19.12.1221"
            protocol.mock_wire_data.set_extensions_config_version(failing_version)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.update_goal_state()
            exthandlers_handler.run()
            self.assertEqual(no_of_extensions,
                             len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                             "incorrect extensions reported")
            error_msg_format = '[ExtensionError] Unable to find version {0} in manifest for extension {1}'
            mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                               handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                               handler_version=failing_version, status="NotReady",
                                                               expected_count=3,
                                                               message=error_msg_format.format(failing_version,
                                                                                               "OSTCExtensions.ExampleHandlerLinux"))
            self.assertTrue(all(
                handler['runtimeSettingsStatus']['settingsStatus']['status']['operation'] == WALAEventOperation.Download and
                handler['runtimeSettingsStatus']['settingsStatus']['status']['status'] == ValidHandlerStatus.error for
                handler in mc_handlers), "Incorrect data reported")
            sc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                               handler_name="Microsoft.Powershell.ExampleExtension",
                                                               handler_version=failing_version, status="NotReady",
                                                               message=error_msg_format.format(failing_version,
                                                                                               "Microsoft.Powershell.ExampleExtension"))
            self.assertFalse(all("runtimeSettingsStatus" in handler for handler in sc_handlers), "Incorrect status")

    def test_it_should_not_install_handler_again_if_installed(self):

        with self.__setup_generic_test_env() as (_, _, _):
            # Everything is already asserted in the context manager
            pass

    def test_it_should_retry_handler_installation_per_extension_if_failed(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            fail_code, fail_action = Actions.generate_unique_fail()
            first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                           install_action=fail_action)
            second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension")
            third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension")
            fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension", install_action=fail_action)
            with enable_invocations(first_ext, second_ext, third_ext, fourth_ext) as invocation_record:
                exthandlers_handler.run()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")
                invocation_record.compare(
                    # Should try installation again if first time failed
                    (first_ext, ExtensionCommandNames.INSTALL),
                    (second_ext, ExtensionCommandNames.INSTALL),
                    (second_ext, ExtensionCommandNames.ENABLE),
                    (third_ext, ExtensionCommandNames.ENABLE),
                    (fourth_ext, ExtensionCommandNames.INSTALL)
                )
                mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                   handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                   expected_count=3, status="Ready")
                expected_extensions = {
                    "firstExtension": {"status": ValidHandlerStatus.error, "seq_no": 1, "message": fail_code},
                    "secondExtension": {"status": ValidHandlerStatus.success, "seq_no": 2, "message": None},
                    "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 3, "message": None},
                }
                self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)

                sc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                   handler_name="Microsoft.Powershell.ExampleExtension",
                                                                   status="NotReady", message=fail_code)
                self.assertFalse(all("runtimeSettingsStatus" in handler for handler in sc_handlers), "Incorrect status")

    def test_it_should_only_disable_enabled_extensions_on_update(self):
        with self.__setup_generic_test_env() as (exthandlers_handler, protocol, old_exts):

            # Update extensions
            self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, 'ext_conf_mc_update_extensions.xml')
            protocol.mock_wire_data = WireProtocolData(self.test_data)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.update_goal_state()

            new_version = "1.1.0"
            new_first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension", version=new_version)
            new_second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension", version=new_version)
            new_third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension", version=new_version)
            new_fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension", version=new_version)
            with enable_invocations(new_first_ext, new_second_ext, new_third_ext, new_fourth_ext, *old_exts) as invocation_record:
                exthandlers_handler.run()
                old_first, old_second, old_third, old_fourth = old_exts
                invocation_record.compare(
                    # Disable all enabled commands for MC before updating the Handler
                    (old_first, ExtensionCommandNames.DISABLE),
                    (old_second, ExtensionCommandNames.DISABLE),
                    (old_third, ExtensionCommandNames.DISABLE),
                    (new_first_ext, ExtensionCommandNames.UPDATE),
                    (old_first, ExtensionCommandNames.UNINSTALL),
                    (new_first_ext, ExtensionCommandNames.INSTALL),
                    # No enable for First and Second extension as their state is Disabled in GoalState,
                    # only enabled the ThirdExtension
                    (new_third_ext, ExtensionCommandNames.ENABLE),
                    # Follow the normal update pattern for Single config handlers
                    (old_fourth, ExtensionCommandNames.DISABLE),
                    (new_fourth_ext, ExtensionCommandNames.UPDATE),
                    (old_fourth, ExtensionCommandNames.UNINSTALL),
                    (new_fourth_ext, ExtensionCommandNames.INSTALL),
                    (new_fourth_ext, ExtensionCommandNames.ENABLE)
                )

            mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                 handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                 expected_count=1, handler_version=new_version)
            expected_extensions = {
                "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 99, "message": None}
            }
            self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status, handler_version=new_version,
                                                 handler_name="Microsoft.Powershell.ExampleExtension")

    def test_it_should_retry_update_sequence_per_extension_if_previous_failed(self):
        with self.__setup_generic_test_env() as (exthandlers_handler, protocol, old_exts):
            # Update extensions
            self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, 'ext_conf_mc_update_extensions.xml')
            protocol.mock_wire_data = WireProtocolData(self.test_data)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.update_goal_state()

            new_version = "1.1.0"
            _, fail_action = Actions.generate_unique_fail()
            # Fail Uninstall of the secondExtension
            old_exts[1] = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension",
                                             uninstall_action=fail_action)
            # Fail update of the first extension
            new_first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                               version=new_version, update_action=fail_action)
            new_second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension",
                                                version=new_version)
            new_third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension",
                                               version=new_version)
            new_fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension", version=new_version)

            with enable_invocations(new_first_ext, new_second_ext, new_third_ext, new_fourth_ext,
                                    *old_exts) as invocation_record:
                exthandlers_handler.run()
                old_first, old_second, old_third, old_fourth = old_exts
                invocation_record.compare(
                    # Disable all enabled commands for MC before updating the Handler
                    (old_first, ExtensionCommandNames.DISABLE),
                    (old_second, ExtensionCommandNames.DISABLE),
                    (old_third, ExtensionCommandNames.DISABLE),
                    (new_first_ext, ExtensionCommandNames.UPDATE),
                    # Since the extensions have been disabled before, we won't disable them again for Update scenario
                    (new_second_ext, ExtensionCommandNames.UPDATE),
                    (old_second, ExtensionCommandNames.UNINSTALL),
                    (new_third_ext, ExtensionCommandNames.UPDATE),
                    (old_third, ExtensionCommandNames.UNINSTALL),
                    (new_third_ext, ExtensionCommandNames.INSTALL),
                    # No enable for First and Second extension as their state is Disabled in GoalState,
                    # only enabled the ThirdExtension
                    (new_third_ext, ExtensionCommandNames.ENABLE),
                    # Follow the normal update pattern for Single config handlers
                    (old_fourth, ExtensionCommandNames.DISABLE),
                    (new_fourth_ext, ExtensionCommandNames.UPDATE),
                    (old_fourth, ExtensionCommandNames.UNINSTALL),
                    (new_fourth_ext, ExtensionCommandNames.INSTALL),
                    (new_fourth_ext, ExtensionCommandNames.ENABLE)
                )

            # Since firstExtension and secondExtension are Disabled, we won't report their status
            mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                               handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                               expected_count=1, handler_version=new_version)
            expected_extensions = {
                "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 99, "message": None}
            }
            self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_version=new_version,
                                                              handler_name="Microsoft.Powershell.ExampleExtension")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 10,
                                                          "message": None}
            }
            self.__assert_extension_status(sc_handler, expected_extensions)

    def test_it_should_report_disabled_extension_errors_if_failed(self):
        with self.__setup_generic_test_env() as (exthandlers_handler, protocol, old_exts):
            # Update extensions
            self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, 'ext_conf_mc_update_extensions.xml')
            protocol.mock_wire_data = WireProtocolData(self.test_data)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.update_goal_state()

            new_version = "1.1.0"
            fail_code, fail_action = Actions.generate_unique_fail()
            # Fail Uninstall of the secondExtension
            old_exts[0] = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                             disable_action=fail_action)
            # Fail update of the first extension
            new_first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                               version=new_version)
            new_second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension",
                                                version=new_version)
            new_third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension",
                                               version=new_version)
            new_fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension", version=new_version)

            with enable_invocations(new_first_ext, new_second_ext, new_third_ext, new_fourth_ext,
                                    *old_exts) as invocation_record:
                exthandlers_handler.run()
                old_first, _, _, old_fourth = old_exts
                invocation_record.compare(
                    # Disable for firstExtension should fail 3 times, i.e., once per extension which tries to update the Handler
                    (old_first, ExtensionCommandNames.DISABLE),
                    (old_first, ExtensionCommandNames.DISABLE),
                    (old_first, ExtensionCommandNames.DISABLE),
                    # Since Disable fails for the firstExtension and continueOnUpdate = False, Update should not go through
                    # Follow the normal update pattern for Single config handlers
                    (old_fourth, ExtensionCommandNames.DISABLE),
                    (new_fourth_ext, ExtensionCommandNames.UPDATE),
                    (old_fourth, ExtensionCommandNames.UNINSTALL),
                    (new_fourth_ext, ExtensionCommandNames.INSTALL),
                    (new_fourth_ext, ExtensionCommandNames.ENABLE)
                )

            # Since firstExtension and secondExtension are Disabled, we won't report their status
            mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                               handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                               expected_count=1, handler_version=new_version,
                                                               status="NotReady", message=fail_code)
            expected_extensions = {
                "thirdExtension": {"status": ValidHandlerStatus.error, "seq_no": 99, "message": fail_code}
            }
            self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_version=new_version,
                                                              handler_name="Microsoft.Powershell.ExampleExtension")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 10,
                                                          "message": None}
            }
            self.__assert_extension_status(sc_handler, expected_extensions)

    def test_it_should_report_extension_status_properly(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            exthandlers_handler.run()
            self.assertEqual(no_of_extensions,
                             len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                             "incorrect extensions reported")
            mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                               handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                               expected_count=3)
            expected_extensions = {
                "firstExtension": {"status": ValidHandlerStatus.success, "seq_no": 1, "message": "Enabling firstExtension"},
                "secondExtension": {"status": ValidHandlerStatus.success, "seq_no": 2, "message": "Enabling secondExtension"},
                "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 3, "message": "Enabling thirdExtension"},
            }
            self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="Microsoft.Powershell.ExampleExtension")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 9,
                                                          "message": "Enabling SingleConfig extension"}
            }
            self.__assert_extension_status(sc_handler, expected_extensions)

    def test_it_should_handle_and_report_enable_errors_properly(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            fail_code, fail_action = Actions.generate_unique_fail()
            first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension")
            second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension")
            third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension",
                                           enable_action=fail_action)
            fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension", enable_action=fail_action)
            with enable_invocations(first_ext, second_ext, third_ext, fourth_ext) as invocation_record:
                exthandlers_handler.run()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")
                invocation_record.compare(
                    (first_ext, ExtensionCommandNames.INSTALL),
                    (first_ext, ExtensionCommandNames.ENABLE),
                    (second_ext, ExtensionCommandNames.ENABLE),
                    (third_ext, ExtensionCommandNames.ENABLE),
                    (fourth_ext, ExtensionCommandNames.INSTALL),
                    (fourth_ext, ExtensionCommandNames.ENABLE)
                )
                mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                   handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                   expected_count=3, status="Ready")
                expected_extensions = {
                    "firstExtension": {"status": ValidHandlerStatus.success, "seq_no": 1, "message": None},
                    "secondExtension": {"status": ValidHandlerStatus.success, "seq_no": 2, "message": None},
                    "thirdExtension": {"status": ValidHandlerStatus.error, "seq_no": 3, "message": fail_code},
                }
                self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)

                sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="Microsoft.Powershell.ExampleExtension",
                                                                  status="NotReady", message=fail_code)
                expected_extensions = {
                    "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.error, "seq_no": 9,
                                                              "message": fail_code}
                }
                self.__assert_extension_status(sc_handler, expected_extensions)

    def test_it_should_cleanup_extension_state_on_disable(self):

        def __assert_state_file(handler_name, handler_version, extensions, state, not_present=None):
            config_path = os.path.join(self.tmp_dir, "{0}-{1}".format(handler_name, handler_version), "config")
            config_files = os.listdir(config_path)

            for ext_name in extensions:
                self.assertIn("{0}.settings".format(ext_name), config_files, "settings not found")
                self.assertEqual(
                    fileutil.read_file(os.path.join(config_path, "{0}.HandlerState".format(ext_name.split(".")[0]))),
                    state, "Invalid state")

            if not_present is not None:
                for ext_name in not_present:
                    self.assertNotIn("{0}.HandlerState".format(ext_name), config_files, "Wrongful state found")

        with self.__setup_generic_test_env() as (ext_handler, protocol, _):
            __assert_state_file("OSTCExtensions.ExampleHandlerLinux", "1.0.0",
                                ["firstExtension.1", "secondExtension.2", "thirdExtension.3"], ExtensionState.Enabled)

            self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, 'ext_conf_mc_disabled_extensions.xml')
            protocol.mock_wire_data = WireProtocolData(self.test_data)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.update_goal_state()

            ext_handler.run()
            mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                               handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                               expected_count=2, status="Ready")
            expected_extensions = {
                "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 99, "message": "Enabling thirdExtension"},
                "fourthExtension": {"status": ValidHandlerStatus.success, "seq_no": 101, "message": "Enabling fourthExtension"},
            }
            self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            __assert_state_file("OSTCExtensions.ExampleHandlerLinux", "1.0.0",
                                ["thirdExtension.99", "fourthExtension.101"], ExtensionState.Enabled,
                                not_present=["firstExtension", "secondExtension"])

            sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="Microsoft.Powershell.ExampleExtension")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 10,
                                                          "message": "Enabling SingleConfig Extension"}
            }
            self.__assert_extension_status(sc_handler, expected_extensions)

    def test_it_should_set_relevant_environment_variables_for_mc(self):

        original_popen = subprocess.Popen
        handler_envs = {}

        def __assert_env_variables(handler_name, ext_name=None):
            expected_environment_variables = [ExtCommandEnvVariable.ExtensionPath,
                                              ExtCommandEnvVariable.ExtensionVersion,
                                              ExtCommandEnvVariable.ExtensionSeqNumber,
                                              ExtCommandEnvVariable.WireProtocolAddress,
                                              ExtCommandEnvVariable.ExtensionSupportedFeatures]
            if ext_name is not None:
                expected_environment_variables.append(ExtCommandEnvVariable.ExtensionName)
                handler_name = "{0}.{1}".format(handler_name, ext_name)

            self.assertIn(handler_name, handler_envs, "Handler/ext combo not called")
            self.assertTrue(all(env_var in handler_envs[handler_name] for env_var in expected_environment_variables),
                            "All expected environment variables not found")

        def mock_popen(cmd, *_, **kwargs):
            if 'env' in kwargs:
                handler_name, __, __ = extract_extension_info_from_command(cmd)
                name = handler_name
                if ExtCommandEnvVariable.ExtensionName in kwargs['env']:
                    name = "{0}.{1}".format(handler_name, kwargs['env'][ExtCommandEnvVariable.ExtensionName])
                handler_envs[name] = kwargs['env']
            return original_popen(cmd, *_, **kwargs)

        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            with patch('azurelinuxagent.common.cgroupapi.subprocess.Popen', side_effect=mock_popen):
                exthandlers_handler.run()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")
                mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                   handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                   expected_count=3)
                expected_extensions = {
                    "firstExtension": {"status": ValidHandlerStatus.success, "seq_no": 1, "message": "Enabling firstExtension"},
                    "secondExtension": {"status": ValidHandlerStatus.success, "seq_no": 2, "message": "Enabling secondExtension"},
                    "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 3, "message": "Enabling thirdExtension"},
                }
                self.__assert_extension_status(mc_handlers.copy(), expected_extensions, multi_config=True)

                sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="Microsoft.Powershell.ExampleExtension")
                expected_extensions = {
                    "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 9,
                                                              "message": "Enabling SingleConfig extension"}
                }
                self.__assert_extension_status(sc_handler.copy(), expected_extensions)

                for handler in mc_handlers:
                    __assert_env_variables(handler['handlerName'], ext_name=handler['runtimeSettingsStatus']['extensionName'])
                for handler in sc_handler:
                    __assert_env_variables(handler['handlerName'])

    def test_it_should_always_create_placeholder_for_all_extensions(self):
        original_popen = subprocess.Popen
        handler_statuses = {}

        def __assert_status_file(handler_name, status_file):
            status = handler_statuses["{0}.{1}.enable".format(handler_name, status_file)]
            self.assertIsNotNone(status, "No status found")
            # Assert the format of the placeholder is correct
            ext_status = ExtensionStatus()
            # If the format is wrong or unexpected, this would throw and fail the test
            parse_ext_status(ext_status, status)
            self.assertIn(ext_status.status, [ValidHandlerStatus.success, ValidHandlerStatus.transitioning],
                          "Incorrect status")

        def mock_popen(cmd, *_, **kwargs):
            if 'env' in kwargs:
                handler_name, handler_version, command_name = extract_extension_info_from_command(cmd)
                ext_name = None
                if ExtCommandEnvVariable.ExtensionName in kwargs['env']:
                    ext_name = kwargs['env'][ExtCommandEnvVariable.ExtensionName]
                seq_no = kwargs['env'][ExtCommandEnvVariable.ExtensionSeqNumber]
                status_file_name = "{0}.status".format(seq_no)
                status_file_name = "{0}.{1}".format(ext_name, status_file_name) if ext_name is not None else status_file_name
                status_file = os.path.join(self.tmp_dir, "{0}-{1}".format(handler_name, handler_version), "status", status_file_name)
                contents = None
                if os.path.exists(status_file):
                    contents = json.loads(fileutil.read_file(status_file))
                handler_statuses["{0}.{1}.{2}".format(handler_name, status_file_name, command_name)] = contents

            return original_popen(cmd, *_, **kwargs)

        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            with patch('azurelinuxagent.common.cgroupapi.subprocess.Popen', side_effect=mock_popen):
                exthandlers_handler.run()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")
                mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                   handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                   expected_count=3)
                expected_extensions = {
                    "firstExtension": {"status": ValidHandlerStatus.success, "seq_no": 1, "message": "Enabling firstExtension"},
                    "secondExtension": {"status": ValidHandlerStatus.success, "seq_no": 2, "message": "Enabling secondExtension"},
                    "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 3, "message": "Enabling thirdExtension"},
                }
                self.__assert_extension_status(mc_handlers.copy(), expected_extensions, multi_config=True)

                sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="Microsoft.Powershell.ExampleExtension")
                expected_extensions = {
                    "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 9,
                                                              "message": "Enabling SingleConfig extension"}
                }
                self.__assert_extension_status(sc_handler.copy(), expected_extensions)

                # Ensure we dont create a placeholder for Install command
                self.assertTrue(
                    all(handler_statuses[status] is None for status in handler_statuses if "install" in status),
                    "Incorrect status file found for install")

                # Ensure we create a valid status file for Enable
                # Note: As part of our test, the sample-ext creates a status file after install due to which a placeholder
                # is not created. We will verify a valid status file exists for all extensions instead since that's the
                # main scenario.
                for handler in mc_handlers:
                    file_name = "{0}.{1}.status".format(handler['runtimeSettingsStatus']['extensionName'],
                                                               handler['runtimeSettingsStatus']['sequenceNumber'])
                    __assert_status_file(handler['handlerName'], status_file=file_name)
                for handler in sc_handler:
                    file_name = "{0}.status".format(handler['runtimeSettingsStatus']['sequenceNumber'])
                    __assert_status_file(handler['handlerName'], status_file=file_name)

                # Update GS, remove 2 extensions and add 3
                self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                          'ext_conf_mc_disabled_extensions.xml')
                protocol.mock_wire_data = WireProtocolData(self.test_data)
                protocol.mock_wire_data.set_incarnation(2)
                protocol.update_goal_state()
                exthandlers_handler.run()

                mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                   handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                   status="Ready", expected_count=2)
                expected_extensions = {
                    "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 99, "message": None},
                    "fourthExtension": {"status": ValidHandlerStatus.success, "seq_no": 101, "message": None},
                }
                self.__assert_extension_not_present(mc_handlers, ["firstExtension", "secondExtension"])
                self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
                sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="Microsoft.Powershell.ExampleExtension",
                                                                  status="Ready")
                expected_extensions = {
                    "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 10,
                                                              "message": None}
                }
                self.__assert_extension_status(sc_handler, expected_extensions)

                for handler in mc_handlers:
                    file_name = "{0}.{1}.status".format(handler['runtimeSettingsStatus']['extensionName'],
                                                        handler['runtimeSettingsStatus']['sequenceNumber'])
                    __assert_status_file(handler['handlerName'], status_file=file_name)
                for handler in sc_handler:
                    file_name = "{0}.status".format(handler['runtimeSettingsStatus']['sequenceNumber'])
                    __assert_status_file(handler['handlerName'], status_file=file_name)

    def test_it_should_report_status_correctly_for_unsupported_goal_state(self):
        with self.__setup_generic_test_env() as (exthandlers_handler, protocol, _):

            # Update GS with an ExtensionConfig with 3 Required features to force GA to mark it as unsupported
            self.test_data['ext_conf'] = "wire/ext_conf_required_features.xml"
            protocol.mock_wire_data = WireProtocolData(self.test_data)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.update_goal_state()
            exthandlers_handler.run()

            # Assert the GS was reported as unsupported
            gs_aggregate_status = protocol.aggregate_status['aggregateStatus']['vmArtifactsAggregateStatus'][
                'goalStateAggregateStatus']
            self.assertEqual(gs_aggregate_status['status'], GoalStateStatus.Failed, "Incorrect status")
            self.assertEqual(gs_aggregate_status['code'],
                             GoalStateAggregateStatusCodes.GoalStateUnsupportedRequiredFeatures, "Incorrect code")
            self.assertEqual(gs_aggregate_status['inSvdSeqNo'], '2', "Incorrect incarnation reported")
            self.assertEqual(gs_aggregate_status['formattedMessage']['message'],
                             'Failing GS incarnation: 2 as Unsupported features found: TestRequiredFeature1, TestRequiredFeature2, TestRequiredFeature3',
                             "Incorrect error message reported")

            # Assert the extension status is the same as we reported for Incarnation 1.
            mc_handlers = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                               handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                               expected_count=3, status="Ready")
            expected_extensions = {
                "firstExtension": {"status": ValidHandlerStatus.success, "seq_no": 1, "message": None},
                "secondExtension": {"status": ValidHandlerStatus.success, "seq_no": 2, "message": None},
                "thirdExtension": {"status": ValidHandlerStatus.success, "seq_no": 3, "message": None},
            }
            self.__assert_extension_status(mc_handlers, expected_extensions, multi_config=True)

            sc_handler = self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="Microsoft.Powershell.ExampleExtension")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ValidHandlerStatus.success, "seq_no": 9,
                                                          "message": None}
            }
            self.__assert_extension_status(sc_handler, expected_extensions)
            self.assertTrue(protocol.aggregate_status)
