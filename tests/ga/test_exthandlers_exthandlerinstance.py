# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

from azurelinuxagent.ga.exthandlers import ExtHandlerInstance
from azurelinuxagent.common.protocol.restapi import ExtHandler, ExtHandlerProperties, ExtHandlerPackage, \
    ExtHandlerVersionUri
import os # pylint: disable=wrong-import-order
import shutil # pylint: disable=wrong-import-order
import sys # pylint: disable=wrong-import-order
from tests.tools import AgentTestCase, patch


class ExtHandlerInstanceTestCase(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        ext_handler_properties = ExtHandlerProperties()
        ext_handler_properties.version = "1.2.3"
        ext_handler = ExtHandler(name='foo')
        ext_handler.properties = ext_handler_properties
        self.ext_handler_instance = ExtHandlerInstance(ext_handler=ext_handler, protocol=None)

        pkg_uri = ExtHandlerVersionUri()
        pkg_uri.uri = "http://bar/foo__1.2.3"
        self.ext_handler_instance.pkg = ExtHandlerPackage(ext_handler_properties.version)
        self.ext_handler_instance.pkg.uris.append(pkg_uri)

        self.base_dir = self.tmp_dir
        self.extension_directory = os.path.join(self.tmp_dir, "extension_directory")
        self.mock_get_base_dir = patch.object(self.ext_handler_instance, "get_base_dir", return_value=self.extension_directory)
        self.mock_get_base_dir.start()

    def tearDown(self):
        self.mock_get_base_dir.stop()

    def test_rm_ext_handler_dir_should_remove_the_extension_packages(self):
        os.mkdir(self.extension_directory)
        open(os.path.join(self.extension_directory, "extension_file1"), 'w').close()
        open(os.path.join(self.extension_directory, "extension_file2"), 'w').close()
        open(os.path.join(self.extension_directory, "extension_file3"), 'w').close()
        open(os.path.join(self.base_dir, "foo__1.2.3.zip"), 'w').close()

        self.ext_handler_instance.remove_ext_handler()

        self.assertFalse(os.path.exists(self.extension_directory))
        self.assertFalse(os.path.exists(os.path.join(self.base_dir, "foo__1.2.3.zip")))

    def test_rm_ext_handler_dir_should_remove_the_extension_directory(self):
        os.mkdir(self.extension_directory)
        os.mknod(os.path.join(self.extension_directory, "extension_file1"))
        os.mknod(os.path.join(self.extension_directory, "extension_file2"))
        os.mknod(os.path.join(self.extension_directory, "extension_file3"))

        self.ext_handler_instance.remove_ext_handler()

        self.assertFalse(os.path.exists(self.extension_directory))

    def test_rm_ext_handler_dir_should_not_report_an_event_if_the_extension_directory_does_not_exist(self):
        if os.path.exists(self.extension_directory):
            os.rmdir(self.extension_directory)

        with patch.object(self.ext_handler_instance, "report_event") as mock_report_event:
            self.ext_handler_instance.remove_ext_handler()

        mock_report_event.assert_not_called()

    def test_rm_ext_handler_dir_should_not_report_an_event_if_a_child_is_removed_asynchronously_while_deleting_the_extension_directory(self):
        os.mkdir(self.extension_directory)
        os.mknod(os.path.join(self.extension_directory, "extension_file1"))
        os.mknod(os.path.join(self.extension_directory, "extension_file2"))
        os.mknod(os.path.join(self.extension_directory, "extension_file3"))

        #
        # Some extensions uninstall asynchronously and the files we are trying to remove may be removed
        # while shutil.rmtree is traversing the extension's directory. Mock this by deleting a file
        # twice (the second call will produce "[Errno 2] No such file or directory", which should not be
        # reported as a telemetry event.
        # In order to mock this, we need to know that remove_ext_handler invokes Pyhon's shutil.rmtree,
        # which in turn invokes os.unlink (Python 3) or os.remove (Python 2)
        #
        remove_api_name = "unlink" if sys.version_info >= (3, 0) else "remove"

        original_remove_api = getattr(shutil.os, remove_api_name)

        extension_directory = self.extension_directory

        def mock_remove(path, dir_fd=None):
            if dir_fd is not None:  # path is relative, make it absolute
                path = os.path.join(extension_directory, path)

            if path.endswith("extension_file2"):
                original_remove_api(path)
                mock_remove.file_deleted_asynchronously = True
            original_remove_api(path)

        mock_remove.file_deleted_asynchronously = False

        with patch.object(shutil.os, remove_api_name, mock_remove):
            with patch.object(self.ext_handler_instance, "report_event") as mock_report_event:
                self.ext_handler_instance.remove_ext_handler()

        mock_report_event.assert_not_called()

        # The next 2 asserts are checks on the mock itself, in case the implementation of remove_ext_handler changes (mocks may need to be updated then)
        self.assertTrue(mock_remove.file_deleted_asynchronously)  # verify the mock was actually called
        self.assertFalse(os.path.exists(self.extension_directory))  # verify the error produced by the mock did not prevent the deletion

    def test_rm_ext_handler_dir_should_report_an_event_if_an_error_occurs_while_deleting_the_extension_directory(self):
        os.mkdir(self.extension_directory)
        os.mknod(os.path.join(self.extension_directory, "extension_file1"))
        os.mknod(os.path.join(self.extension_directory, "extension_file2"))
        os.mknod(os.path.join(self.extension_directory, "extension_file3"))

        # The mock below relies on the knowledge that remove_ext_handler invokes Pyhon's shutil.rmtree,
        # which in turn invokes os.unlink (Python 3) or os.remove (Python 2)
        remove_api_name = "unlink" if sys.version_info >= (3, 0) else "remove"

        original_remove_api = getattr(shutil.os, remove_api_name)

        def mock_remove(path, dir_fd=None): # pylint: disable=unused-argument
            if path.endswith("extension_file2"):
                raise IOError("A mocked error")
            original_remove_api(path)

        with patch.object(shutil.os, remove_api_name, mock_remove):
            with patch.object(self.ext_handler_instance, "report_event") as mock_report_event:
                self.ext_handler_instance.remove_ext_handler()

        args, kwargs = mock_report_event.call_args # pylint: disable=unused-variable
        self.assertTrue("A mocked error" in kwargs["message"])

