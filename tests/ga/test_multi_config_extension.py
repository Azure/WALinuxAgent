import os.path

import contextlib

import json

from azurelinuxagent.ga.exthandlers import get_exthandlers_handler
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates, MockHttpResponse
from tests.protocol.mockwiredata import DATA_FILE
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
                yield exthandlers_handler, protocol

    def test_mc_end_to_end(self):
        self.test_data['ext_conf'] = os.path.join(self._MULTI_CONFIG_TEST_DATA,
                                                  "ext_conf_multi_config_no_dependencies.xml")
        with self._setup_test_env() as (exthandlers_handler, protocol):
            exthandlers_handler.run()
        raise NotImplementedError

    def test_it_should_not_install_handler_again_if_installed(self):
        raise NotImplementedError

    def test_placeholder_always_created(self):
        raise NotImplementedError

    def test_reporting_for_unsupported_gs(self):
        raise NotImplementedError
