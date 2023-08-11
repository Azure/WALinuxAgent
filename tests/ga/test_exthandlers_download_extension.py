# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

import contextlib
import os
import time
import zipfile

from azurelinuxagent.common.exception import ExtensionDownloadError, ExtensionErrorCodes
from azurelinuxagent.common.protocol.restapi import Extension, ExtHandlerPackage
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.ga.exthandlers import ExtHandlerInstance, ExtHandlerState
from tests.lib import wire_protocol_data
from tests.lib.mock_wire_protocol import mock_wire_protocol
from tests.lib.tools import AgentTestCase, patch, Mock


class DownloadExtensionTestCase(AgentTestCase):
    """
    Test cases for launch_command
    """
    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()
        cls.mock_cgroups = patch("azurelinuxagent.ga.exthandlers.CGroupConfigurator")
        cls.mock_cgroups.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock_cgroups.stop()

        AgentTestCase.tearDownClass()

    def setUp(self):
        AgentTestCase.setUp(self)

        ext_handler = Extension(name='Microsoft.CPlat.Core.RunCommandLinux')
        ext_handler.version = "1.0.0"

        protocol = WireProtocol("http://Microsoft.CPlat.Core.RunCommandLinux/foo-bar")
        protocol.client.get_host_plugin = Mock()
        protocol.client.get_artifact_request = Mock(return_value=(None, None))

        # create a dummy goal state, since downloads are done via the GoalState class
        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as p:
            goal_state = p.get_goal_state()
            goal_state._wire_client = protocol.client
            protocol.client._goal_state = goal_state

        self.pkg = ExtHandlerPackage()
        self.pkg.uris = [
            'https://zrdfepirv2cy4prdstr00a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712-foobar/Microsoft.CPlat.Core__RunCommandLinux__1.0.0',
            'https://zrdfepirv2cy4prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712-foobar/Microsoft.CPlat.Core__RunCommandLinux__1.0.0',
            'https://zrdfepirv2cy4prdstr02a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712-foobar/Microsoft.CPlat.Core__RunCommandLinux__1.0.0',
            'https://zrdfepirv2cy4prdstr03a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712-foobar/Microsoft.CPlat.Core__RunCommandLinux__1.0.0',
            'https://zrdfepirv2cy4prdstr04a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712-foobar/Microsoft.CPlat.Core__RunCommandLinux__1.0.0'
        ]
        self.ext_handler_instance = ExtHandlerInstance(ext_handler=ext_handler, protocol=protocol)
        self.ext_handler_instance.pkg = self.pkg

        self.extension_dir = os.path.join(self.tmp_dir, "Microsoft.CPlat.Core.RunCommandLinux-1.0.0")
        self.mock_get_base_dir = patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_base_dir", return_value=self.extension_dir)
        self.mock_get_base_dir.start()

        self.mock_get_log_dir = patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_log_dir", return_value=self.tmp_dir)
        self.mock_get_log_dir.start()

        self.agent_dir = self.tmp_dir
        self.mock_get_lib_dir = patch("azurelinuxagent.ga.exthandlers.conf.get_lib_dir", return_value=self.agent_dir)
        self.mock_get_lib_dir.start()

    def tearDown(self):
        self.mock_get_lib_dir.stop()
        self.mock_get_log_dir.stop()
        self.mock_get_base_dir.stop()

        AgentTestCase.tearDown(self)

    _extension_command = "RunCommandLinux.sh"

    @staticmethod
    def _create_zip_file(filename):
        file = None  # pylint: disable=redefined-builtin
        try:
            file = zipfile.ZipFile(filename, "w")
            info = zipfile.ZipInfo(DownloadExtensionTestCase._extension_command)
            info.date_time = time.localtime(time.time())[:6]
            info.compress_type = zipfile.ZIP_DEFLATED
            file.writestr(info, "#!/bin/sh\necho 'RunCommandLinux executed successfully'\n")
        finally:
            if file is not None:
                file.close()

    @staticmethod
    def _create_invalid_zip_file(filename):
        with open(filename, "w") as file:  # pylint: disable=redefined-builtin
            file.write("An invalid ZIP file\n")

    def _get_extension_base_dir(self):
        return self.extension_dir

    def _get_extension_package_file(self):
        return os.path.join(self.agent_dir, self.ext_handler_instance.get_extension_package_zipfile_name())

    def _get_extension_command_file(self):
        return os.path.join(self.extension_dir, DownloadExtensionTestCase._extension_command)

    def _assert_download_and_expand_succeeded(self):
        self.assertTrue(os.path.exists(self._get_extension_base_dir()), "The extension package was not downloaded to the expected location")
        self.assertTrue(os.path.exists(self._get_extension_command_file()), "The extension package was not expanded to the expected location")

    @staticmethod
    @contextlib.contextmanager
    def create_mock_stream(stream_function):
        with patch("azurelinuxagent.common.protocol.wire.WireClient.stream", side_effect=stream_function) as mock_stream:
            mock_stream.download_failures = 0
            with patch('time.sleep'):  # don't sleep in-between retries
                yield mock_stream

    def test_it_should_download_and_expand_extension_package(self):
        def stream(_, destination, **__):
            DownloadExtensionTestCase._create_zip_file(destination)
            return True

        with DownloadExtensionTestCase.create_mock_stream(stream) as mock_stream:
            with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.report_event") as mock_report_event:
                self.ext_handler_instance.download()

        # first download attempt should succeed
        mock_stream.assert_called_once()
        mock_report_event.assert_called_once()

        self._assert_download_and_expand_succeeded()

    def test_it_should_use_existing_extension_package_when_already_downloaded(self):
        DownloadExtensionTestCase._create_zip_file(self._get_extension_package_file())

        with DownloadExtensionTestCase.create_mock_stream(lambda: None) as mock_stream:
            with patch("azurelinuxagent.ga.exthandlers.ExtHandlerInstance.report_event") as mock_report_event:
                self.ext_handler_instance.download()

        mock_stream.assert_not_called()
        mock_report_event.assert_not_called()

        self.assertTrue(os.path.exists(self._get_extension_command_file()), "The extension package was not expanded to the expected location")

    def test_it_should_ignore_existing_extension_package_when_it_is_invalid(self):
        def stream(_, destination, **__):
            DownloadExtensionTestCase._create_zip_file(destination)
            return True

        DownloadExtensionTestCase._create_invalid_zip_file(self._get_extension_package_file())

        with DownloadExtensionTestCase.create_mock_stream(stream) as mock_stream:
            self.ext_handler_instance.download()

        mock_stream.assert_called_once()

        self._assert_download_and_expand_succeeded()

    def test_it_should_maintain_extension_handler_state_when_good_zip_exists(self):
        DownloadExtensionTestCase._create_zip_file(self._get_extension_package_file())
        self.ext_handler_instance.set_handler_state(ExtHandlerState.NotInstalled)
        self.ext_handler_instance.download()
        self._assert_download_and_expand_succeeded()
        self.assertTrue(os.path.exists(os.path.join(self.ext_handler_instance.get_conf_dir(), "HandlerState")),
                        "Ensure that the HandlerState file exists on disk")
        self.assertEqual(self.ext_handler_instance.get_handler_state(), ExtHandlerState.NotInstalled,
                         "Ensure that the state is maintained for extension HandlerState")

    def test_it_should_maintain_extension_handler_state_when_bad_zip_exists_and_recovers_with_good_zip(self):
        def stream(_, destination, **__):
            DownloadExtensionTestCase._create_zip_file(destination)
            return True

        DownloadExtensionTestCase._create_invalid_zip_file(self._get_extension_package_file())
        self.ext_handler_instance.set_handler_state(ExtHandlerState.NotInstalled)

        with DownloadExtensionTestCase.create_mock_stream(stream) as mock_stream:
            self.ext_handler_instance.download()

        mock_stream.assert_called_once()
        self._assert_download_and_expand_succeeded()
        self.assertEqual(self.ext_handler_instance.get_handler_state(), ExtHandlerState.NotInstalled,
                         "Ensure that the state is maintained for extension HandlerState")

    def test_it_should_maintain_extension_handler_state_when_it_downloads_bad_zips(self):
        def stream(_, destination, **__):
            DownloadExtensionTestCase._create_invalid_zip_file(destination)
            return True

        self.ext_handler_instance.set_handler_state(ExtHandlerState.NotInstalled)

        with DownloadExtensionTestCase.create_mock_stream(stream):
            with self.assertRaises(ExtensionDownloadError):
                self.ext_handler_instance.download()

        self.assertFalse(os.path.exists(self._get_extension_package_file()), "The bad zip extension package should not be downloaded to the expected location")
        self.assertFalse(os.path.exists(self._get_extension_command_file()), "The extension package should not expanded be to the expected location due to bad zip")
        self.assertEqual(self.ext_handler_instance.get_handler_state(), ExtHandlerState.NotInstalled, "Ensure that the state is maintained for extension HandlerState")

    def test_it_should_use_alternate_uris_when_download_fails(self):
        def stream(_, destination, **__):
            # fail a few times, then succeed
            if mock_stream.download_failures < 3:
                mock_stream.download_failures += 1
                return None
            DownloadExtensionTestCase._create_zip_file(destination)
            return True

        with DownloadExtensionTestCase.create_mock_stream(stream) as mock_stream:
            self.ext_handler_instance.download()

        self.assertEqual(mock_stream.call_count, mock_stream.download_failures + 1)

        self._assert_download_and_expand_succeeded()

    def test_it_should_use_alternate_uris_when_download_raises_an_exception(self):
        def stream(_, destination, **__):
            # fail a few times, then succeed
            if mock_stream.download_failures < 3:
                mock_stream.download_failures += 1
                raise Exception("Download failed")
            DownloadExtensionTestCase._create_zip_file(destination)
            return True

        with DownloadExtensionTestCase.create_mock_stream(stream) as mock_stream:
            self.ext_handler_instance.download()

        self.assertEqual(mock_stream.call_count, mock_stream.download_failures + 1)

        self._assert_download_and_expand_succeeded()

    def test_it_should_use_alternate_uris_when_it_downloads_an_invalid_package(self):
        def stream(_, destination, **__):
            # fail a few times, then succeed
            if mock_stream.download_failures < 3:
                mock_stream.download_failures += 1
                DownloadExtensionTestCase._create_invalid_zip_file(destination)
            else:
                DownloadExtensionTestCase._create_zip_file(destination)
            return True

        with DownloadExtensionTestCase.create_mock_stream(stream) as mock_stream:
            self.ext_handler_instance.download()

        self.assertEqual(mock_stream.call_count, mock_stream.download_failures + 1)

        self._assert_download_and_expand_succeeded()

    def test_it_should_raise_an_exception_when_all_downloads_fail(self):
        def stream(_, target_file, **___):
            stream.target_file = target_file
            DownloadExtensionTestCase._create_invalid_zip_file(target_file)
            return True
        stream.target_file = None

        with DownloadExtensionTestCase.create_mock_stream(stream) as mock_stream:
            with self.assertRaises(ExtensionDownloadError) as context_manager:
                self.ext_handler_instance.download()

        self.assertEqual(mock_stream.call_count, len(self.pkg.uris))

        self.assertRegex(str(context_manager.exception), "Failed to download extension")
        self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginManifestDownloadError)

        self.assertFalse(os.path.exists(self.extension_dir), "The extension directory was not removed")
        self.assertFalse(os.path.exists(stream.target_file), "The extension package was not removed")

