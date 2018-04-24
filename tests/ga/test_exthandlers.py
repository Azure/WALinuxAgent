# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
import json

from azurelinuxagent.common.protocol.restapi import ExtensionStatus
from azurelinuxagent.ga.exthandlers import parse_ext_status
from azurelinuxagent.common.protocol.restapi import ExtHandler
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.ga.exthandlers import ExtHandlerInstance
from tests.tools import *

debug = False
if os.environ.get('DEBUG') == '1':
    debug = True

# Enable verbose logger to stdout
if debug:
    logger.add_logger_appender(logger.AppenderType.STDOUT,
                               logger.LogLevel.VERBOSE)


class TestExtHandlers(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        prefix = "{0}_".format(self.__class__.__name__)
        self.lib_dir = tempfile.mkdtemp(prefix=prefix)

    def tearDown(self):
        if not debug and self.lib_dir is not None:
            shutil.rmtree(self.lib_dir)

    def touch_in_lib_dir(self, fn):
        fileutil.write_file(os.path.join(self.lib_dir, fn), '<empty>')

    def test_parse_extension_status00(self):
        """
        Parse a status report for a successful execution of an extension.
        """

        s = '''[{
    "status": {
      "status": "success",
      "formattedMessage": {
        "lang": "en-US",
        "message": "Command is finished."
      },
      "operation": "Daemon",
      "code": "0",
      "name": "Microsoft.OSTCExtensions.CustomScriptForLinux"
    },
    "version": "1.0",
    "timestampUTC": "2018-04-20T21:20:24Z"
  }
]'''
        ext_status = ExtensionStatus(seq_no=0)
        parse_ext_status(ext_status, json.loads(s))

        self.assertEqual('0', ext_status.code)
        self.assertEqual(None, ext_status.configurationAppliedTime)
        self.assertEqual('Command is finished.', ext_status.message)
        self.assertEqual('Daemon', ext_status.operation)
        self.assertEqual('success', ext_status.status)
        self.assertEqual(0, ext_status.sequenceNumber)
        self.assertEqual(0, len(ext_status.substatusList))

    def test_parse_extension_status01(self):
        """
        Parse a status report for a failed execution of an extension.

        The extension returned a bad status/status of failed.
        The agent should handle this gracefully, and convert all unknown
        status/status values into an error.
        """

        s = '''[{
    "status": {
      "status": "failed",
      "formattedMessage": {
        "lang": "en-US",
        "message": "Enable failed: Failed with error: commandToExecute is empty or invalid ..."
      },
      "operation": "Enable",
      "code": "0",
      "name": "Microsoft.OSTCExtensions.CustomScriptForLinux"
    },
    "version": "1.0",
    "timestampUTC": "2018-04-20T20:50:22Z"
}]'''
        ext_status = ExtensionStatus(seq_no=0)
        parse_ext_status(ext_status, json.loads(s))

        self.assertEqual('0', ext_status.code)
        self.assertEqual(None, ext_status.configurationAppliedTime)
        self.assertEqual('Enable failed: Failed with error: commandToExecute is empty or invalid ...', ext_status.message)
        self.assertEqual('Enable', ext_status.operation)
        self.assertEqual('error', ext_status.status)
        self.assertEqual(0, ext_status.sequenceNumber)
        self.assertEqual(0, len(ext_status.substatusList))

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_try_get_pkg_file00(self, mock_conf):
        """
        Given zero packages (*.zip) in /var/lib/waagent
        And an extension handler name Microsoft.OSTCExtensions.CustomScriptForLinux with version 1.5.2.2
        When you call try_get_pkg_file()
        Then None is returned.
        """
        mock_conf.return_value = self.lib_dir

        ext_handler = ExtHandler()
        ext_handler.name = "Microsoft.OSTCExtensions.CustomScriptForLinux"
        ext_handler.properties.version = str(FlexibleVersion("1.5.2.2"))

        test_subject = ExtHandlerInstance(ext_handler, "ignored")
        self.assertEqual(None, test_subject.try_get_pkg_file())

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_try_get_pkg_file01(self, mock_conf):
        """
        Ensure the correct package file is returned if it exists.

        Given the package files:
          /var/lib/waagent/Microsoft.OSTCExtensions__CustomScriptForLinux__1.5.2.2.zip
        And an extension handler named Microsoft.OSTCExtensions.CustomScriptForLinux with version 1.5.2.2
        When you call try_get_pkg_file()
        Then /var/lib/waagent/Microsoft.OSTCExtensions__CustomScriptForLinux__1.5.2.2.zip is returned.
        """
        mock_conf.return_value = self.lib_dir

        self.touch_in_lib_dir('Microsoft.OSTCExtensions__CustomScriptForLinux__1.5.2.2.zip')

        ext_handler = ExtHandler()
        ext_handler.name = "Microsoft.OSTCExtensions.CustomScriptForLinux"
        ext_handler.properties.version = str(FlexibleVersion("1.5.2.2"))

        test_subject = ExtHandlerInstance(ext_handler, "ignored")
        expected_fn = os.path.join(self.lib_dir, 'Microsoft.OSTCExtensions__CustomScriptForLinux__1.5.2.2.zip')
        self.assertEqual(expected_fn, test_subject.try_get_pkg_file())

    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_try_get_pkg_file02(self, mock_conf):
        """
        Ensure the correct package file is returned even if other packages exist
        with the same namespace, type, or version.

        Given the packages files:
          /var/lib/waagent/Microsoft.OSTCExtensions__CustomScriptForLinux__1.0.zip
          /var/lib/waagent/Microsoft.OSTCExtensions__CustomScriptForLinux__1.1.zip
          /var/lib/waagent/Microsoft.OSTCExtensions__VMAccessForLinux__1.5.2.2.zip
        And an extension handler named Microsoft.OSTCExtensions.CustomScriptForLinux with version 1.5.2.2
        When you call try_get_pkg_file()
        Then None is returned.
        """
        mock_conf.return_value = self.lib_dir

        self.touch_in_lib_dir('Microsoft.OSTCExtensions__CustomScriptForLinux__1.0.zip')
        self.touch_in_lib_dir('Microsoft.OSTCExtensions__CustomScriptForLinux__1.1.zip')
        self.touch_in_lib_dir('Microsoft.OSTCExtensions__VMAccessForLinux__1.5.2.2.zip')

        ext_handler = ExtHandler()
        ext_handler.name = "Microsoft.OSTCExtensions.CustomScriptForLinux"
        ext_handler.properties.version = str(FlexibleVersion("1.5.2.2"))

        test_subject = ExtHandlerInstance(ext_handler, "ignored")
        self.assertEqual(None, test_subject.try_get_pkg_file())
