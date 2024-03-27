import contextlib
import json
import os.path
import re
import subprocess
import uuid

from azurelinuxagent.common import conf
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import GoalStateAggregateStatusCodes
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import ExtensionRequestedState, ExtensionState
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.ga.exthandlers import get_exthandlers_handler, ExtensionStatusValue, ExtCommandEnvVariable, \
    GoalStateStatus, ExtHandlerInstance
from tests.lib.extension_emulator import enable_invocations, extension_emulator, ExtensionCommandNames, Actions, \
    extract_extension_info_from_command
from tests.lib.mock_wire_protocol import mock_wire_protocol, MockHttpResponse
from tests.lib.http_request_predicates import HttpRequestPredicates
from tests.lib.wire_protocol_data import DATA_FILE, WireProtocolData
from tests.lib.tools import AgentTestCase, mock_sleep, patch


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
            self.settings = dict()

    class _TestExtensionObject:
        def __init__(self, name, seq_no, dependency_level="0", state="enabled"):
            self.name = name
            self.seq_no = seq_no
            self.dependency_level = int(dependency_level)
            self.state = state

    def _mock_and_assert_ext_handlers(self, expected_handlers):
        with mock_wire_protocol(self.test_data) as protocol:
            ext_handlers = protocol.get_goal_state().extensions_goal_state.extensions
            for ext_handler in ext_handlers:
                if ext_handler.name not in expected_handlers:
                    continue
                expected_handler = expected_handlers.pop(ext_handler.name)
                self.assertEqual(expected_handler.state, ext_handler.state)
                self.assertEqual(expected_handler.version, ext_handler.version)
                self.assertEqual(expected_handler.is_invalid_setting, ext_handler.is_invalid_setting)
                self.assertEqual(len(expected_handler.settings), len(ext_handler.settings))

                for extension in ext_handler.settings:
                    self.assertIn(extension.name, expected_handler.settings)
                    expected_extension = expected_handler.settings.pop(extension.name)
                    self.assertEqual(expected_extension.seq_no, extension.sequenceNumber)
                    self.assertEqual(expected_extension.state, extension.state)
                    self.assertEqual(expected_extension.dependency_level, extension.dependencyLevel)

                self.assertEqual(0, len(expected_handler.settings), "All extensions not verified for handler")

            self.assertEqual(0, len(expected_handlers), "All handlers not verified")

    def _get_mock_expected_handler_data(self, rc_extensions, vmaccess_extensions, geneva_extensions):
        # Set expected handler data
        run_command_test_handler = self._TestExtHandlerObject("Microsoft.CPlat.Core.RunCommandHandlerWindows", "2.3.0")
        run_command_test_handler.settings.update(rc_extensions)

        vm_access_test_handler = self._TestExtHandlerObject("Microsoft.Compute.VMAccessAgent", "2.4.7")
        vm_access_test_handler.settings.update(vmaccess_extensions)

        geneva_test_handler = self._TestExtHandlerObject("Microsoft.Azure.Geneva.GenevaMonitoring", "2.20.0.1")
        geneva_test_handler.settings.update(geneva_extensions)

        expected_handlers = {
            run_command_test_handler.name: run_command_test_handler,
            vm_access_test_handler.name: vm_access_test_handler,
            geneva_test_handler.name: geneva_test_handler
        }
        return expected_handlers

    def test_it_should_parse_multi_config_settings_properly(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, "ext_conf_with_multi_config.xml")

        rc_extensions = dict()
        rc_extensions["firstRunCommand"] = self._TestExtensionObject(name="firstRunCommand", seq_no=2)
        rc_extensions["secondRunCommand"] = self._TestExtensionObject(name="secondRunCommand", seq_no=2,
                                                                      dependency_level="3")
        rc_extensions["thirdRunCommand"] = self._TestExtensionObject(name="thirdRunCommand", seq_no=1,
                                                                     dependency_level="4")

        vmaccess_extensions = {
            "Microsoft.Compute.VMAccessAgent": self._TestExtensionObject(name="Microsoft.Compute.VMAccessAgent",
                                                                         seq_no=1, dependency_level=2)}

        geneva_extensions = {"Microsoft.Azure.Geneva.GenevaMonitoring": self._TestExtensionObject(
            name="Microsoft.Azure.Geneva.GenevaMonitoring", seq_no=1)}

        expected_handlers = self._get_mock_expected_handler_data(rc_extensions, vmaccess_extensions, geneva_extensions)
        self._mock_and_assert_ext_handlers(expected_handlers)

    def test_it_should_parse_multi_config_with_disable_state_properly(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_with_disabled_multi_config.xml")

        rc_extensions = dict()
        rc_extensions["firstRunCommand"] = self._TestExtensionObject(name="firstRunCommand", seq_no=3)
        rc_extensions["secondRunCommand"] = self._TestExtensionObject(name="secondRunCommand", seq_no=3,
                                                                      dependency_level="1")
        rc_extensions["thirdRunCommand"] = self._TestExtensionObject(name="thirdRunCommand", seq_no=1,
                                                                     dependency_level="4", state="disabled")

        vmaccess_extensions = {
            "Microsoft.Compute.VMAccessAgent": self._TestExtensionObject(name="Microsoft.Compute.VMAccessAgent",
                                                                         seq_no=2, dependency_level="2")}

        geneva_extensions = {"Microsoft.Azure.Geneva.GenevaMonitoring": self._TestExtensionObject(
            name="Microsoft.Azure.Geneva.GenevaMonitoring", seq_no=2)}

        expected_handlers = self._get_mock_expected_handler_data(rc_extensions, vmaccess_extensions, geneva_extensions)
        self._mock_and_assert_ext_handlers(expected_handlers)


class _MultiConfigBaseTestClass(AgentTestCase):
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
    def _setup_test_env(self, mock_manifest=False):

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

                if mock_manifest:
                    with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.supports_multiple_extensions',
                               return_value=True):
                        yield exthandlers_handler, protocol, no_of_extensions
                else:
                    yield exthandlers_handler, protocol, no_of_extensions

    def _assert_and_get_handler_status(self, aggregate_status, handler_name="OSTCExtensions.ExampleHandlerLinux",
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

    def _assert_extension_status(self, handler_statuses, expected_ext_status, multi_config=False):
        for ext_name, settings_status in expected_ext_status.items():
            ext_status = next(handler for handler in handler_statuses if
                              handler['runtimeSettingsStatus']['settingsStatus']['status']['name'] == ext_name)
            ext_runtime_status = ext_status['runtimeSettingsStatus']
            self.assertIsNotNone(ext_runtime_status, "Extension not found")
            self.assertEqual(settings_status['seq_no'], ext_runtime_status['sequenceNumber'], "Sequence no mismatch")
            self.assertEqual(settings_status['status'], ext_runtime_status['settingsStatus']['status']['status'],
                             "status mismatch")

            if 'message' in settings_status and settings_status['message'] is not None:
                self.assertIn(settings_status['message'],
                              ext_runtime_status['settingsStatus']['status']['formattedMessage']['message'],
                              "message mismatch")

            if multi_config:
                self.assertEqual(ext_name, ext_runtime_status['extensionName'], "ext name mismatch")
            else:
                self.assertNotIn('extensionName', ext_runtime_status, "Extension name should not be reported for SC")

            handler_statuses.remove(ext_status)

        self.assertEqual(0, len(handler_statuses), "Unexpected extensions left for handler")


class TestMultiConfigExtensions(_MultiConfigBaseTestClass):

    def __assert_extension_not_present(self, handlers, extensions):
        for ext_name in extensions:
            self.assertFalse(all(
                'runtimeSettingsStatus' in handler and 'extensionName' in handler['runtimeSettingsStatus']
                and handler['runtimeSettingsStatus']['extensionName'] == ext_name for
                handler in handlers), "Extension status found")

    def __run_and_assert_generic_case(self, exthandlers_handler, protocol, no_of_extensions, with_message=True):

        def get_message(msg):
            return msg if with_message else None

        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()
        self.assertEqual(no_of_extensions,
                         len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                         "incorrect extensions reported")
        mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                          handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                          expected_count=3)
        expected_extensions = {
            "firstExtension": {"status": ExtensionStatusValue.success, "seq_no": 1,
                               "message": get_message("Enabling firstExtension")},
            "secondExtension": {"status": ExtensionStatusValue.success, "seq_no": 2,
                                "message": get_message("Enabling secondExtension")},
            "thirdExtension": {"status": ExtensionStatusValue.success, "seq_no": 3,
                               "message": get_message("Enabling thirdExtension")},
        }
        self._assert_extension_status(mc_handlers[:], expected_extensions, multi_config=True)

        sc_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                         handler_name="Microsoft.Powershell.ExampleExtension")
        expected_extensions = {
            "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.success, "seq_no": 9,
                                                      "message": get_message("Enabling SingleConfig extension")}
        }
        self._assert_extension_status(sc_handler[:], expected_extensions)
        return mc_handlers, sc_handler

    def __setup_and_assert_disable_scenario(self, exthandlers_handler, protocol):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, 'ext_conf_mc_disabled_extensions.xml')
        protocol.mock_wire_data = WireProtocolData(self.test_data)
        protocol.mock_wire_data.set_incarnation(2)
        protocol.client.update_goal_state()
        exthandlers_handler.run()
        exthandlers_handler.report_ext_handlers_status()

        mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                          handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                          status="Ready", expected_count=2)
        expected_extensions = {
            "thirdExtension": {"status": ExtensionStatusValue.success, "seq_no": 99, "message": None},
            "fourthExtension": {"status": ExtensionStatusValue.success, "seq_no": 101, "message": None},
        }
        self.__assert_extension_not_present(mc_handlers[:], ["firstExtension", "secondExtension"])
        self._assert_extension_status(mc_handlers[:], expected_extensions, multi_config=True)
        sc_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                         handler_name="Microsoft.Powershell.ExampleExtension",
                                                         status="Ready")
        expected_extensions = {
            "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.success, "seq_no": 10,
                                                      "message": None}
        }
        self._assert_extension_status(sc_handler[:], expected_extensions)
        return mc_handlers, sc_handler

    @contextlib.contextmanager
    def __setup_generic_test_env(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")

        first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension")
        second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension")
        third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension")
        fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension")

        with self._setup_test_env(mock_manifest=True) as (exthandlers_handler, protocol, no_of_extensions):
            with enable_invocations(first_ext, second_ext, third_ext, fourth_ext) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
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

            self.__run_and_assert_generic_case(exthandlers_handler, protocol, no_of_extensions, with_message=False)
            yield exthandlers_handler, protocol, [first_ext, second_ext, third_ext, fourth_ext]

    def test_it_should_execute_and_report_multi_config_extensions_properly(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env(mock_manifest=True) as (exthandlers_handler, protocol, no_of_extensions):

            # Case 1: Install and enable Single and MultiConfig extensions
            self.__run_and_assert_generic_case(exthandlers_handler, protocol, no_of_extensions)

            # Case 2: Disable 2 multi-config extensions and add another for enable
            self.__setup_and_assert_disable_scenario(exthandlers_handler, protocol)

            # Case 3: Uninstall Multi-config handler (with enabled extensions) and single config extension
            protocol.mock_wire_data.set_incarnation(3)
            protocol.mock_wire_data.set_extensions_config_state(ExtensionRequestedState.Uninstall)
            protocol.client.update_goal_state()
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()
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
            protocol.client.update_goal_state()
            exthandlers_handler.run()
            exthandlers_handler.report_ext_handlers_status()
            self.assertEqual(no_of_extensions,
                             len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                             "incorrect extensions reported")
            error_msg_format = '[ExtensionError] Unable to find version {0} in manifest for extension {1}'
            mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                              handler_version=failing_version, status="NotReady",
                                                              expected_count=3,
                                                              message=error_msg_format.format(failing_version,
                                                                                               "OSTCExtensions.ExampleHandlerLinux"))
            self.assertTrue(all(
                handler['runtimeSettingsStatus']['settingsStatus']['status']['operation'] == WALAEventOperation.Download and
                handler['runtimeSettingsStatus']['settingsStatus']['status']['status'] == ExtensionStatusValue.error for
                handler in mc_handlers), "Incorrect data reported")
            sc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
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
                                           install_action=fail_action, supports_multiple_extensions=True)
            second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension",
                                            supports_multiple_extensions=True)
            third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension",
                                           supports_multiple_extensions=True)
            sc_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension", install_action=fail_action)
            with enable_invocations(first_ext, second_ext, third_ext, sc_ext) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")
                invocation_record.compare(
                    (first_ext, ExtensionCommandNames.INSTALL),
                    # Should try installation again if first time failed
                    (second_ext, ExtensionCommandNames.INSTALL),
                    (second_ext, ExtensionCommandNames.ENABLE),
                    (third_ext, ExtensionCommandNames.ENABLE),
                    (sc_ext, ExtensionCommandNames.INSTALL)
                )
                mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                  expected_count=3, status="Ready")
                expected_extensions = {
                    "firstExtension": {"status": ExtensionStatusValue.error, "seq_no": 1, "message": fail_code},
                    "secondExtension": {"status": ExtensionStatusValue.success, "seq_no": 2, "message": None},
                    "thirdExtension": {"status": ExtensionStatusValue.success, "seq_no": 3, "message": None},
                }
                self._assert_extension_status(mc_handlers, expected_extensions, multi_config=True)

                sc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="Microsoft.Powershell.ExampleExtension",
                                                                  status="NotReady", message=fail_code)
                self.assertFalse(all("runtimeSettingsStatus" in handler for handler in sc_handlers), "Incorrect status")

    def test_it_should_only_disable_enabled_extensions_on_update(self):
        with self.__setup_generic_test_env() as (exthandlers_handler, protocol, old_exts):

            # Update extensions
            self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, 'ext_conf_mc_update_extensions.xml')
            protocol.mock_wire_data = WireProtocolData(self.test_data)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.client.update_goal_state()

            new_version = "1.1.0"
            new_first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                               version=new_version, supports_multiple_extensions=True)
            new_second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension",
                                                version=new_version, supports_multiple_extensions=True)
            new_third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension",
                                               version=new_version, supports_multiple_extensions=True)
            new_sc_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension", version=new_version)
            with enable_invocations(new_first_ext, new_second_ext, new_third_ext, new_sc_ext, *old_exts) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
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
                    (new_sc_ext, ExtensionCommandNames.UPDATE),
                    (old_fourth, ExtensionCommandNames.UNINSTALL),
                    (new_sc_ext, ExtensionCommandNames.INSTALL),
                    (new_sc_ext, ExtensionCommandNames.ENABLE)
                )

            mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                              expected_count=1, handler_version=new_version)
            expected_extensions = {
                "thirdExtension": {"status": ExtensionStatusValue.success, "seq_no": 99, "message": None}
            }
            self._assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status, handler_version=new_version,
                                                handler_name="Microsoft.Powershell.ExampleExtension")

    def test_it_should_retry_update_sequence_per_extension_if_previous_failed(self):
        with self.__setup_generic_test_env() as (exthandlers_handler, protocol, old_exts):
            # Update extensions
            self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, 'ext_conf_mc_update_extensions.xml')
            protocol.mock_wire_data = WireProtocolData(self.test_data)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.client.update_goal_state()

            new_version = "1.1.0"
            _, fail_action = Actions.generate_unique_fail()
            # Fail Uninstall of the secondExtension
            old_exts[1] = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension",
                                             uninstall_action=fail_action, supports_multiple_extensions=True)
            # Fail update of the first extension
            new_first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                               version=new_version, update_action=fail_action,
                                               supports_multiple_extensions=True)
            new_second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension",
                                                version=new_version, supports_multiple_extensions=True)
            new_third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension",
                                               version=new_version, supports_multiple_extensions=True)
            new_sc_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension", version=new_version)

            with enable_invocations(new_first_ext, new_second_ext, new_third_ext, new_sc_ext,
                                    *old_exts) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
                old_first, old_second, old_third, old_fourth = old_exts
                invocation_record.compare(
                    # Disable all enabled commands for MC before updating the Handler
                    (old_first, ExtensionCommandNames.DISABLE),
                    (old_second, ExtensionCommandNames.DISABLE),
                    (old_third, ExtensionCommandNames.DISABLE),
                    (new_first_ext, ExtensionCommandNames.UPDATE),
                    # Since the extensions have been disabled before, we won't disable them again for Update scenario
                    (new_second_ext, ExtensionCommandNames.UPDATE),
                    # This will fail too as per the mock above
                    (old_second, ExtensionCommandNames.UNINSTALL),
                    (new_third_ext, ExtensionCommandNames.UPDATE),
                    (old_third, ExtensionCommandNames.UNINSTALL),
                    (new_third_ext, ExtensionCommandNames.INSTALL),
                    # No enable for First and Second extension as their state is Disabled in GoalState,
                    # only enabled the ThirdExtension
                    (new_third_ext, ExtensionCommandNames.ENABLE),
                    # Follow the normal update pattern for Single config handlers
                    (old_fourth, ExtensionCommandNames.DISABLE),
                    (new_sc_ext, ExtensionCommandNames.UPDATE),
                    (old_fourth, ExtensionCommandNames.UNINSTALL),
                    (new_sc_ext, ExtensionCommandNames.INSTALL),
                    (new_sc_ext, ExtensionCommandNames.ENABLE)
                )

            # Since firstExtension and secondExtension are Disabled, we won't report their status
            mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                              expected_count=1, handler_version=new_version)
            expected_extensions = {
                "thirdExtension": {"status": ExtensionStatusValue.success, "seq_no": 99, "message": None}
            }
            self._assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            sc_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                             handler_version=new_version,
                                                             handler_name="Microsoft.Powershell.ExampleExtension")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.success, "seq_no": 10,
                                                          "message": None}
            }
            self._assert_extension_status(sc_handler, expected_extensions)

    def test_it_should_report_disabled_extension_errors_if_update_failed(self):
        with self.__setup_generic_test_env() as (exthandlers_handler, protocol, old_exts):
            # Update extensions
            self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA, 'ext_conf_mc_update_extensions.xml')
            protocol.mock_wire_data = WireProtocolData(self.test_data)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.client.update_goal_state()

            new_version = "1.1.0"
            fail_code, fail_action = Actions.generate_unique_fail()
            # Fail Disable of the firstExtension
            old_exts[0] = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                             disable_action=fail_action, supports_multiple_extensions=True)
            new_first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                               version=new_version, supports_multiple_extensions=True)
            new_second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension",
                                                version=new_version, supports_multiple_extensions=True)
            new_third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension",
                                               version=new_version, supports_multiple_extensions=True)
            new_fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension", version=new_version)

            with enable_invocations(new_first_ext, new_second_ext, new_third_ext, new_fourth_ext,
                                    *old_exts) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
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
            mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                              expected_count=1, handler_version=new_version,
                                                              status="NotReady", message=fail_code)
            expected_extensions = {
                "thirdExtension": {"status": ExtensionStatusValue.error, "seq_no": 99, "message": fail_code}
            }
            self._assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            sc_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                             handler_version=new_version,
                                                             handler_name="Microsoft.Powershell.ExampleExtension")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.success, "seq_no": 10,
                                                          "message": None}
            }
            self._assert_extension_status(sc_handler, expected_extensions)

    def test_it_should_report_extension_status_properly(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env(mock_manifest=True) as (exthandlers_handler, protocol, no_of_extensions):
            self.__run_and_assert_generic_case(exthandlers_handler, protocol, no_of_extensions)

    def test_it_should_handle_and_report_enable_errors_properly(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            fail_code, fail_action = Actions.generate_unique_fail()
            first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                           supports_multiple_extensions=True)
            second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension",
                                            supports_multiple_extensions=True)
            third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension",
                                           enable_action=fail_action, supports_multiple_extensions=True)
            fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension", enable_action=fail_action)
            with enable_invocations(first_ext, second_ext, third_ext, fourth_ext) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
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
                mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                  expected_count=3, status="Ready")
                expected_extensions = {
                    "firstExtension": {"status": ExtensionStatusValue.success, "seq_no": 1, "message": None},
                    "secondExtension": {"status": ExtensionStatusValue.success, "seq_no": 2, "message": None},
                    "thirdExtension": {"status": ExtensionStatusValue.error, "seq_no": 3, "message": fail_code},
                }
                self._assert_extension_status(mc_handlers, expected_extensions, multi_config=True)

                sc_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                 handler_name="Microsoft.Powershell.ExampleExtension",
                                                                 status="NotReady", message=fail_code)
                expected_extensions = {
                    "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.error, "seq_no": 9,
                                                              "message": fail_code}
                }
                self._assert_extension_status(sc_handler, expected_extensions)

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
            protocol.client.update_goal_state()

            ext_handler.run()
            ext_handler.report_ext_handlers_status()
            mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                              handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                              expected_count=2, status="Ready")
            expected_extensions = {
                "thirdExtension": {"status": ExtensionStatusValue.success, "seq_no": 99, "message": "Enabling thirdExtension"},
                "fourthExtension": {"status": ExtensionStatusValue.success, "seq_no": 101, "message": "Enabling fourthExtension"},
            }
            self._assert_extension_status(mc_handlers, expected_extensions, multi_config=True)
            __assert_state_file("OSTCExtensions.ExampleHandlerLinux", "1.0.0",
                                ["thirdExtension.99", "fourthExtension.101"], ExtensionState.Enabled,
                                not_present=["firstExtension", "secondExtension"])

            sc_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                             handler_name="Microsoft.Powershell.ExampleExtension")
            expected_extensions = {
                "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.success, "seq_no": 10,
                                                          "message": "Enabling SingleConfig Extension"}
            }
            self._assert_extension_status(sc_handler, expected_extensions)

    def test_it_should_create_command_execution_log_per_extension(self):
        with self.__setup_generic_test_env() as (_, _, _):
            sc_handler_path = os.path.join(conf.get_ext_log_dir(), "Microsoft.Powershell.ExampleExtension")
            mc_handler_path = os.path.join(conf.get_ext_log_dir(), "OSTCExtensions.ExampleHandlerLinux")
            self.assertIn("CommandExecution_firstExtension.log", os.listdir(mc_handler_path),
                          "Command Execution file not found")
            self.assertGreater(os.path.getsize(os.path.join(mc_handler_path, "CommandExecution_firstExtension.log")), 0,
                               "Log file not being used")
            self.assertIn("CommandExecution_secondExtension.log", os.listdir(mc_handler_path),
                          "Command Execution file not found")
            self.assertGreater(os.path.getsize(os.path.join(mc_handler_path, "CommandExecution_secondExtension.log")), 0,
                               "Log file not being used")
            self.assertIn("CommandExecution_thirdExtension.log", os.listdir(mc_handler_path),
                          "Command Execution file not found")
            self.assertGreater(os.path.getsize(os.path.join(mc_handler_path, "CommandExecution_thirdExtension.log")), 0,
                               "Log file not being used")
            self.assertIn("CommandExecution.log", os.listdir(sc_handler_path), "Command Execution file not found")
            self.assertGreater(os.path.getsize(os.path.join(sc_handler_path, "CommandExecution.log")), 0,
                               "Log file not being used")

    def test_it_should_set_relevant_environment_variables_for_mc(self):
        original_popen = subprocess.Popen
        handler_envs = {}

        def __assert_env_variables(handler_name, handler_version="1.0.0", seq_no="1", ext_name=None, expected_vars=None,
                                   not_expected=None):
            original_env_vars = {
                ExtCommandEnvVariable.ExtensionPath: os.path.join(self.tmp_dir, "{0}-{1}".format(handler_name, handler_version)),
                ExtCommandEnvVariable.ExtensionVersion: handler_version,
                ExtCommandEnvVariable.ExtensionSeqNumber: ustr(seq_no),
                ExtCommandEnvVariable.WireProtocolAddress: '168.63.129.16',
                ExtCommandEnvVariable.ExtensionSupportedFeatures: json.dumps([{"Key": "ExtensionTelemetryPipeline",
                                                                               "Value": "1.0"}])

            }

            full_name = handler_name
            if ext_name is not None:
                original_env_vars[ExtCommandEnvVariable.ExtensionName] = ext_name
                full_name = "{0}.{1}".format(handler_name, ext_name)

            self.assertIn(full_name, handler_envs, "Handler/ext combo not called")
            for commands in handler_envs[full_name]:
                expected_environment_variables = original_env_vars.copy()
                if expected_vars is not None and commands['command'] in expected_vars:
                    for name, val in expected_vars[commands['command']].items():
                        expected_environment_variables[name] = val

                self.assertTrue(all(
                    env_var in commands['data'] and env_val == commands['data'][env_var] for env_var, env_val in
                    expected_environment_variables.items()),
                    "Incorrect data for environment variable for {0}-{1}, incorrect: {2}".format(
                        full_name, commands['command'],
                        [(env_var, env_val) for env_var, env_val in expected_environment_variables.items() if
                         env_var not in commands['data'] or env_val != commands['data'][env_var]]))

                if not_expected is not None and commands['command'] in not_expected:
                    self.assertFalse(any(env_var in commands['data'] for env_var in not_expected), "Unwanted env variable found")

        def mock_popen(cmd, *_, **kwargs):
            # This cgroupsapi Popen mocking all other popen calls which breaking the extension emulator logic.
            # The emulator should be used only on extension commands and not on other commands even env flag set.
            # So, added ExtensionVersion check to avoid using extension emulator on non extension operations.
            if 'env' in kwargs and ExtCommandEnvVariable.ExtensionVersion in kwargs['env']:
                handler_name, __, command = extract_extension_info_from_command(cmd)
                name = handler_name
                if ExtCommandEnvVariable.ExtensionName in kwargs['env']:
                    name = "{0}.{1}".format(handler_name, kwargs['env'][ExtCommandEnvVariable.ExtensionName])

                data = {
                    "command": command,
                    "data": kwargs['env']
                }
                if name in handler_envs:
                    handler_envs[name].append(data)
                else:
                    handler_envs[name] = [data]
            return original_popen(cmd, *_, **kwargs)

        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env(mock_manifest=True) as (exthandlers_handler, protocol, no_of_extensions):
            with patch('azurelinuxagent.ga.cgroupapi.subprocess.Popen', side_effect=mock_popen):
                # Case 1: Check normal scenario - Install/Enable
                mc_handlers, sc_handler = self.__run_and_assert_generic_case(exthandlers_handler, protocol,
                                                                             no_of_extensions)

                for handler in mc_handlers:
                    __assert_env_variables(handler['handlerName'],
                                           ext_name=handler['runtimeSettingsStatus']['extensionName'],
                                           seq_no=handler['runtimeSettingsStatus']['sequenceNumber'])
                for handler in sc_handler:
                    __assert_env_variables(handler['handlerName'],
                                           seq_no=handler['runtimeSettingsStatus']['sequenceNumber'])

                # Case 2: Check Update Scenario
                # Clear old test case state
                handler_envs = {}
                self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                          'ext_conf_mc_update_extensions.xml')
                protocol.mock_wire_data = WireProtocolData(self.test_data)
                protocol.mock_wire_data.set_incarnation(2)
                protocol.client.update_goal_state()
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                  expected_count=1, handler_version="1.1.0")
                expected_extensions = {
                    "thirdExtension": {"status": ExtensionStatusValue.success, "seq_no": 99,
                                       "message": "Enabling thirdExtension"},
                }
                self._assert_extension_status(mc_handlers[:], expected_extensions, multi_config=True)

                sc_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                 handler_name="Microsoft.Powershell.ExampleExtension",
                                                                 handler_version="1.1.0")
                expected_extensions = {
                    "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.success, "seq_no": 10,
                                                              "message": "Enabling SingleConfig extension"}
                }
                self._assert_extension_status(sc_handler[:], expected_extensions)

                for handler in mc_handlers:
                    __assert_env_variables(handler['handlerName'],
                                           handler_version="1.1.0",
                                           ext_name=handler['runtimeSettingsStatus']['extensionName'],
                                           seq_no=handler['runtimeSettingsStatus']['sequenceNumber'],
                                           expected_vars={
                                                "disable": {
                                                    ExtCommandEnvVariable.ExtensionPath: os.path.join(self.tmp_dir, "{0}-{1}".format(handler['handlerName'], "1.0.0")),
                                                    ExtCommandEnvVariable.ExtensionVersion: '1.0.0'
                                                }})

                # Assert the environment variables were present even for disabled/uninstalled commands
                first_ext_expected_vars = {
                    "disable": {
                        ExtCommandEnvVariable.ExtensionPath: os.path.join(self.tmp_dir, "{0}-{1}".format(handler['handlerName'], "1.0.0")),
                        ExtCommandEnvVariable.ExtensionVersion: '1.0.0'
                    },
                    "uninstall": {
                        ExtCommandEnvVariable.ExtensionPath: os.path.join(self.tmp_dir, "{0}-{1}".format(handler['handlerName'], "1.0.0")),
                        ExtCommandEnvVariable.ExtensionVersion: '1.0.0'
                    },
                    "update": {
                        ExtCommandEnvVariable.UpdatingFromVersion: "1.0.0",
                        ExtCommandEnvVariable.DisableReturnCodeMultipleExtensions:
                            json.dumps([
                                {"extensionName": "firstExtension", "exitCode": "0"},
                                {"extensionName": "secondExtension", "exitCode": "0"},
                                {"extensionName": "thirdExtension", "exitCode": "0"}
                            ])
                    }
                }
                __assert_env_variables(handler['handlerName'], ext_name="firstExtension",
                                       expected_vars=first_ext_expected_vars, handler_version="1.1.0", seq_no="1",
                                       not_expected={
                                           "update": [ExtCommandEnvVariable.DisableReturnCode]
                                       })
                __assert_env_variables(handler['handlerName'], ext_name="secondExtension", seq_no="2")

                for handler in sc_handler:
                    sc_expected_vars = {
                        "disable": {
                            ExtCommandEnvVariable.ExtensionPath: os.path.join(self.tmp_dir, "{0}-{1}".format(handler['handlerName'], "1.0.0")),
                            ExtCommandEnvVariable.ExtensionVersion: '1.0.0'
                        },
                        "uninstall": {
                            ExtCommandEnvVariable.ExtensionPath: os.path.join(self.tmp_dir, "{0}-{1}".format(handler['handlerName'], "1.0.0")),
                            ExtCommandEnvVariable.ExtensionVersion: '1.0.0'
                        },
                        "update": {
                            ExtCommandEnvVariable.UpdatingFromVersion: "1.0.0",
                            ExtCommandEnvVariable.DisableReturnCode: "0"
                        }
                    }
                    __assert_env_variables(handler['handlerName'], handler_version="1.1.0",
                                           seq_no=handler['runtimeSettingsStatus']['sequenceNumber'],
                                           expected_vars=sc_expected_vars, not_expected={
                                           "update": [ExtCommandEnvVariable.DisableReturnCodeMultipleExtensions]
                                       })

    def test_it_should_ignore_disable_errors_for_multi_config_extensions(self):
        fail_code, fail_action = Actions.generate_unique_fail()

        with self.__setup_generic_test_env() as (exthandlers_handler, protocol, exts):

            # Fail disable of 1st and 2nd extension
            exts[0] = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                         disable_action=fail_action)
            exts[1] = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension",
                                         disable_action=fail_action)
            fourth_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.fourthExtension")

            with patch.object(ExtHandlerInstance, "report_event", autospec=True) as patch_report_event:
                with enable_invocations(fourth_ext, *exts) as invocation_record:
                    # Assert even though 2 extensions are failing, we clean their state up properly and enable the
                    # remaining extensions
                    self.__setup_and_assert_disable_scenario(exthandlers_handler, protocol)
                    first_ext, second_ext, third_ext, sc_ext = exts
                    invocation_record.compare(
                        (first_ext, ExtensionCommandNames.DISABLE),
                        (second_ext, ExtensionCommandNames.DISABLE),
                        (third_ext, ExtensionCommandNames.ENABLE),
                        (fourth_ext, ExtensionCommandNames.ENABLE),
                        (sc_ext, ExtensionCommandNames.ENABLE)
                    )

                    reported_events = [kwargs for _, kwargs in patch_report_event.call_args_list if
                                       re.search("Executing command: (.+) with environment variables: ",
                                                 kwargs['message']) is None]

                    self.assertTrue(all(
                        fail_code in kwargs['message'] for kwargs in reported_events if
                        kwargs['name'] == first_ext.name), "Error not reported")
                    self.assertTrue(all(
                        fail_code in kwargs['message'] for kwargs in reported_events if
                        kwargs['name'] == second_ext.name), "Error not reported")
                    # Make sure fail code is not reported for any other extension
                    self.assertFalse(all(
                        fail_code in kwargs['message'] for kwargs in reported_events if
                        kwargs['name'] == third_ext.name), "Error not reported")

    def test_it_should_report_transitioning_if_status_file_not_found(self):
        original_popen = subprocess.Popen

        def mock_popen(cmd, *_, **kwargs):
            if 'env' in kwargs:
                handler_name, handler_version, __ = extract_extension_info_from_command(cmd)
                ext_name = None
                if ExtCommandEnvVariable.ExtensionName in kwargs['env']:
                    ext_name = kwargs['env'][ExtCommandEnvVariable.ExtensionName]
                seq_no = kwargs['env'][ExtCommandEnvVariable.ExtensionSeqNumber]
                status_file_name = "{0}.status".format(seq_no)
                status_file_name = "{0}.{1}".format(ext_name, status_file_name) if ext_name is not None else status_file_name
                status_file = os.path.join(self.tmp_dir, "{0}-{1}".format(handler_name, handler_version), "status", status_file_name)
                if os.path.exists(status_file):
                    os.remove(status_file)

            return original_popen("echo " + cmd, *_, **kwargs)

        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env(mock_manifest=True) as (exthandlers_handler, protocol, no_of_extensions):
            with patch('azurelinuxagent.ga.cgroupapi.subprocess.Popen', side_effect=mock_popen):
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")
                mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                  expected_count=3)
                agent_status_message = "This status is being reported by the Guest Agent since no status file was " \
                                       "reported by extension {0}: " \
                                       "[ExtensionStatusError] Status file"
                expected_extensions = {
                    "firstExtension": {"status": ExtensionStatusValue.transitioning, "seq_no": 1,
                                       "message": agent_status_message.format("OSTCExtensions.ExampleHandlerLinux.firstExtension")},
                    "secondExtension": {"status": ExtensionStatusValue.transitioning, "seq_no": 2,
                                        "message": agent_status_message.format("OSTCExtensions.ExampleHandlerLinux.secondExtension")},
                    "thirdExtension": {"status": ExtensionStatusValue.transitioning, "seq_no": 3,
                                       "message": agent_status_message.format("OSTCExtensions.ExampleHandlerLinux.thirdExtension")},
                }
                self._assert_extension_status(mc_handlers[:], expected_extensions, multi_config=True)

                sc_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                 handler_name="Microsoft.Powershell.ExampleExtension")
                expected_extensions = {
                    "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.transitioning, "seq_no": 9,
                                                              "message": agent_status_message.format("Microsoft.Powershell.ExampleExtension")}
                }
                self._assert_extension_status(sc_handler[:], expected_extensions)

    def test_it_should_report_status_correctly_for_unsupported_goal_state(self):
        with self.__setup_generic_test_env() as (exthandlers_handler, protocol, _):

            # Update GS with an ExtensionConfig with 3 Required features to force GA to mark it as unsupported
            self.test_data['ext_conf'] = "wire/ext_conf_required_features.xml"
            protocol.mock_wire_data = WireProtocolData(self.test_data)
            protocol.mock_wire_data.set_incarnation(2)
            protocol.client.update_goal_state()
            # Assert the extension status is the same as we reported for Incarnation 1.
            self.__run_and_assert_generic_case(exthandlers_handler, protocol, no_of_extensions=4, with_message=False)

            # Assert the GS was reported as unsupported
            gs_aggregate_status = protocol.aggregate_status['aggregateStatus']['vmArtifactsAggregateStatus'][
                'goalStateAggregateStatus']
            self.assertEqual(gs_aggregate_status['status'], GoalStateStatus.Failed, "Incorrect status")
            self.assertEqual(gs_aggregate_status['code'],
                             GoalStateAggregateStatusCodes.GoalStateUnsupportedRequiredFeatures, "Incorrect code")
            self.assertEqual(gs_aggregate_status['inSvdSeqNo'], '2', "Incorrect incarnation reported")
            self.assertEqual(gs_aggregate_status['formattedMessage']['message'],
                             'Failing GS incarnation_2 as Unsupported features found: TestRequiredFeature1, TestRequiredFeature2, TestRequiredFeature3',
                             "Incorrect error message reported")

    def test_it_should_fail_handler_if_handler_does_not_support_mc(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")

        first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension")
        second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension")
        third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension")
        fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension")

        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            with enable_invocations(first_ext, second_ext, third_ext, fourth_ext) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")

                invocation_record.compare(
                    # Since we raise a ConfigError, we shouldn't process any of the MC extensions at all
                    (fourth_ext, ExtensionCommandNames.INSTALL),
                    (fourth_ext, ExtensionCommandNames.ENABLE)
                )

                err_msg = 'Handler OSTCExtensions.ExampleHandlerLinux does not support MultiConfig but CRP expects it, failing due to inconsistent data'
                mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                  expected_count=3, status="NotReady", message=err_msg)
                expected_extensions = {
                    "firstExtension": {"status": ExtensionStatusValue.error, "seq_no": 1, "message": err_msg},
                    "secondExtension": {"status": ExtensionStatusValue.error, "seq_no": 2, "message": err_msg},
                    "thirdExtension": {"status": ExtensionStatusValue.error, "seq_no": 3, "message": err_msg},
                }
                self._assert_extension_status(mc_handlers[:], expected_extensions, multi_config=True)

                sc_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                 handler_name="Microsoft.Powershell.ExampleExtension")
                expected_extensions = {
                    "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.success, "seq_no": 9}
                }
                self._assert_extension_status(sc_handler[:], expected_extensions)

    def test_it_should_check_every_time_if_handler_supports_mc(self):
        with self.__setup_generic_test_env() as (exthandlers_handler, protocol, old_exts):

            protocol.mock_wire_data.set_incarnation(2)
            protocol.client.update_goal_state()

            # Mock manifest to not support multiple extensions
            with patch('azurelinuxagent.ga.exthandlers.HandlerManifest.supports_multiple_extensions', return_value=False):
                with enable_invocations(*old_exts) as invocation_record:
                    (_, _, _, fourth_ext) = old_exts
                    exthandlers_handler.run()
                    exthandlers_handler.report_ext_handlers_status()
                    self.assertEqual(4, len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                     "incorrect extensions reported")

                    invocation_record.compare(
                        # Since we raise a ConfigError, we shouldn't process any of the MC extensions at all
                        (fourth_ext, ExtensionCommandNames.ENABLE)
                    )

                    err_msg = 'Handler OSTCExtensions.ExampleHandlerLinux does not support MultiConfig but CRP expects it, failing due to inconsistent data'
                    mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                      handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                      expected_count=3, status="NotReady", message=err_msg)

                    # Since the extensions were not even executed, their status file should reflect the last status
                    # (Handler status above should always report the error though)
                    expected_extensions = {
                        "firstExtension": {"status": ExtensionStatusValue.success, "seq_no": 1},
                        "secondExtension": {"status": ExtensionStatusValue.success, "seq_no": 2},
                        "thirdExtension": {"status": ExtensionStatusValue.success, "seq_no": 3},
                    }
                    self._assert_extension_status(mc_handlers[:], expected_extensions, multi_config=True)

                    sc_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                     handler_name="Microsoft.Powershell.ExampleExtension")
                    expected_extensions = {
                        "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.success, "seq_no": 9}
                    }
                    self._assert_extension_status(sc_handler[:], expected_extensions)


class TestMultiConfigExtensionSequencing(_MultiConfigBaseTestClass):

    @contextlib.contextmanager
    def __setup_test_and_get_exts(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_with_multi_config_dependencies.xml")

        first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension", supports_multiple_extensions=True)
        second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension", supports_multiple_extensions=True)
        third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension", supports_multiple_extensions=True)
        dependent_sc_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension")
        independent_sc_ext = extension_emulator(name="Microsoft.Azure.Geneva.GenevaMonitoring", version="1.1.0")

        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            yield exthandlers_handler, protocol, no_of_extensions, first_ext, second_ext, third_ext, dependent_sc_ext, independent_sc_ext

    def test_it_should_process_dependency_chain_extensions_properly(self):
        with self.__setup_test_and_get_exts() as (
            exthandlers_handler, protocol, no_of_extensions, first_ext, second_ext, third_ext, dependent_sc_ext,
                independent_sc_ext):
            with enable_invocations(first_ext, second_ext, third_ext, dependent_sc_ext, independent_sc_ext) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")
                invocation_record.compare(
                    (first_ext, ExtensionCommandNames.INSTALL),
                    (first_ext, ExtensionCommandNames.ENABLE),
                    (independent_sc_ext, ExtensionCommandNames.INSTALL),
                    (independent_sc_ext, ExtensionCommandNames.ENABLE),
                    (dependent_sc_ext, ExtensionCommandNames.INSTALL),
                    (dependent_sc_ext, ExtensionCommandNames.ENABLE),
                    (second_ext, ExtensionCommandNames.ENABLE),
                    (third_ext, ExtensionCommandNames.ENABLE)
                )

                mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                  handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                                  expected_count=3)
                expected_extensions = {
                    "firstExtension": {"status": ExtensionStatusValue.success, "seq_no": 2},
                    "secondExtension": {"status": ExtensionStatusValue.success, "seq_no": 2},
                    "thirdExtension": {"status": ExtensionStatusValue.success, "seq_no": 1},
                }
                self._assert_extension_status(mc_handlers[:], expected_extensions, multi_config=True)

                sc_dependent_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                           handler_name="Microsoft.Powershell.ExampleExtension")
                expected_extensions = {
                    "Microsoft.Powershell.ExampleExtension": {"status": ExtensionStatusValue.success, "seq_no": 2}
                }
                self._assert_extension_status(sc_dependent_handler[:], expected_extensions)
                sc_independent_handler = self._assert_and_get_handler_status(
                    aggregate_status=protocol.aggregate_status, handler_name="Microsoft.Azure.Geneva.GenevaMonitoring",
                    handler_version="1.1.0")
                expected_extensions = {
                    "Microsoft.Azure.Geneva.GenevaMonitoring": {"status": ExtensionStatusValue.success, "seq_no": 1}
                }
                self._assert_extension_status(sc_independent_handler[:], expected_extensions)

    def __assert_invalid_status_scenario(self, protocol, fail_code, mc_status="NotReady",
                                         mc_message="Plugin installed but not enabled", err_msg=None):
        mc_handlers = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                          handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                          expected_count=3, status=mc_status,
                                                          message=mc_message)

        expected_extensions = {
            "firstExtension": {"status": ExtensionStatusValue.error, "seq_no": 2, "message": fail_code},
            "secondExtension": {"status": ExtensionStatusValue.error, "seq_no": 2, "message": err_msg},
            "thirdExtension": {"status": ExtensionStatusValue.error, "seq_no": 1, "message": err_msg},
        }
        self._assert_extension_status(mc_handlers[:], expected_extensions, multi_config=True)

        sc_dependent_handler = self._assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                                   handler_name="Microsoft.Powershell.ExampleExtension",
                                                                   status="NotReady", message=err_msg)
        self.assertTrue(all('runtimeSettingsStatus' not in handler for handler in sc_dependent_handler))

        sc_independent_handler = self._assert_and_get_handler_status(
            aggregate_status=protocol.aggregate_status, handler_name="Microsoft.Azure.Geneva.GenevaMonitoring",
            handler_version="1.1.0", status="NotReady", message=err_msg)
        self.assertTrue(all('runtimeSettingsStatus' not in handler for handler in sc_independent_handler))

    def test_it_should_report_extension_status_failures_for_all_dependent_extensions(self):
        with self.__setup_test_and_get_exts() as (
            exthandlers_handler, protocol, no_of_extensions, first_ext, second_ext, third_ext, dependent_sc_ext,
                independent_sc_ext):

            # Fail the enable for firstExtension.
            fail_code, fail_action = Actions.generate_unique_fail()
            first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension",
                                           enable_action=fail_action, supports_multiple_extensions=True)

            with enable_invocations(first_ext, second_ext, third_ext, dependent_sc_ext,
                                    independent_sc_ext) as invocation_record:
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")

                # Since firstExtension is high up on the dependency chain, no other extensions should be executed
                invocation_record.compare(
                    (first_ext, ExtensionCommandNames.INSTALL),
                    (first_ext, ExtensionCommandNames.ENABLE)
                )

                err_msg = 'Skipping processing of extensions since execution of dependent extension OSTCExtensions.ExampleHandlerLinux.firstExtension failed'
                self.__assert_invalid_status_scenario(protocol, fail_code, err_msg=err_msg)

    def test_it_should_stop_execution_if_status_file_contains_errors(self):
        # This test tests the scenario where the extensions exit with a success exit code but fail subsequently with an
        # error in the status file
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_with_multi_config_dependencies.xml")

        original_popen = subprocess.Popen
        invocation_records = []
        fail_code = str(uuid.uuid4())

        def mock_popen(cmd, *_, **kwargs):

            try:
                handler_name, handler_version, command_name = extract_extension_info_from_command(cmd)
            except ValueError:
                return original_popen(cmd, *_, **kwargs)

            if 'env' in kwargs:
                env = kwargs['env']
                if ExtCommandEnvVariable.ExtensionName in env:
                    full_name = "{0}.{1}".format(handler_name, env[ExtCommandEnvVariable.ExtensionName])
                    status_file = "{0}.{1}.status".format(env[ExtCommandEnvVariable.ExtensionName],
                                                          env[ExtCommandEnvVariable.ExtensionSeqNumber])

                    status_contents = [{"status": {"status": ExtensionStatusValue.error, "code": fail_code,
                                                   "formattedMessage": {"message": fail_code, "lang": "en-US"}}}]
                    fileutil.write_file(os.path.join(env[ExtCommandEnvVariable.ExtensionPath], "status", status_file),
                                        json.dumps(status_contents))

                    invocation_records.append((full_name, handler_version, command_name))
                    # The return code is 0 but the status file should have the error, this it to test the scenario
                    # where the extensions return a success code but fail later.
                    return original_popen(['echo', "works"], *_, **kwargs)

            invocation_records.append((handler_name, handler_version, command_name))
            return original_popen(cmd, *_, **kwargs)

        with self._setup_test_env(mock_manifest=True) as (exthandlers_handler, protocol, no_of_extensions):
            with patch('azurelinuxagent.ga.cgroupapi.subprocess.Popen', side_effect=mock_popen):
                exthandlers_handler.run()
                exthandlers_handler.report_ext_handlers_status()

                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")

                # Since we're writing error status for firstExtension, only the firstExtension should be invoked and
                # everything else should be skipped
                expected_invocations = [
                    ('OSTCExtensions.ExampleHandlerLinux.firstExtension', '1.0.0', ExtensionCommandNames.INSTALL),
                    ('OSTCExtensions.ExampleHandlerLinux.firstExtension', '1.0.0', ExtensionCommandNames.ENABLE)]
                self.assertEqual(invocation_records, expected_invocations, "Invalid invocations found")

                err_msg = 'Dependent Extension OSTCExtensions.ExampleHandlerLinux.firstExtension did not succeed. Status was error'
                self.__assert_invalid_status_scenario(protocol, fail_code, mc_status="Ready",
                                                      mc_message="Plugin enabled", err_msg=err_msg)
