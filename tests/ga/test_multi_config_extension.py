import os.path

import contextlib

import json

from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.protocol.restapi import ExtHandlerRequestedState
from azurelinuxagent.ga.exthandlers import get_exthandlers_handler, ValidHandlerStatus
from tests.ga.extension_emulator import enable_invocations, extension_emulator, ExtensionCommandNames, Actions
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
        run_command_test_handler = self._TestExtHandlerObject("Microsoft.CPlat.Core.RunCommandHandlerWindows", "2.0.2")
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
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env() as (exthandlers_handler, protocol, no_of_extensions):
            first_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.firstExtension")
            second_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.secondExtension")
            third_ext = extension_emulator(name="OSTCExtensions.ExampleHandlerLinux.thirdExtension")
            fourth_ext = extension_emulator(name="Microsoft.Powershell.ExampleExtension")
            with enable_invocations(first_ext, second_ext, third_ext, fourth_ext) as invocation_record:
                exthandlers_handler.run()
                self.assertEqual(no_of_extensions,
                                 len(protocol.aggregate_status['aggregateStatus']['handlerAggregateStatus']),
                                 "incorrect extensions reported")
                invocation_record.compare(
                    # Should only install once
                    (first_ext, ExtensionCommandNames.INSTALL),
                    (first_ext, ExtensionCommandNames.ENABLE),
                    (second_ext, ExtensionCommandNames.ENABLE),
                    (third_ext, ExtensionCommandNames.ENABLE),
                    (fourth_ext, ExtensionCommandNames.INSTALL),
                    (fourth_ext, ExtensionCommandNames.ENABLE)
                )
                self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                     handler_name="OSTCExtensions.ExampleHandlerLinux",
                                                     expected_count=3)
                self.__assert_and_get_handler_status(aggregate_status=protocol.aggregate_status,
                                                     handler_name="Microsoft.Powershell.ExampleExtension")

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
        raise NotImplementedError

    def test_it_should_report_disabled_extension_errors_if_failed(self):
        raise NotImplementedError

    def test_it_should_report_extension_status_properly(self):
        raise NotImplementedError

    def test_it_should_handle_install_failures_properly(self):
        raise NotImplementedError

    def test_it_should_handle_enable_errors_properly(self):
        raise NotImplementedError

    def test_it_should_cleanup_extension_state_on_disable(self):
        raise NotImplementedError

    def test_it_should_handle_disable_errors_properly(self):
        raise NotImplementedError

    def test_it_should_handle_update_errors_properly(self):
        raise NotImplementedError

    def test_it_should_not_block_on_uninstall_failures(self):
        raise NotImplementedError

    def test_it_should_set_relevant_environment_variables_for_mc(self):
        raise NotImplementedError

    def test_placeholder_always_created(self):
        raise NotImplementedError

    def test_reporting_for_unsupported_gs(self):
        raise NotImplementedError
