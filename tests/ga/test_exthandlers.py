# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import json

from azurelinuxagent.common.protocol.restapi import ExtensionStatus, Extension, ExtHandler, ExtHandlerProperties
from azurelinuxagent.ga.exthandlers import parse_ext_status, ExtHandlerInstance
from tests.tools import *


class TestExtHandlers(AgentTestCase):
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

    @patch('azurelinuxagent.common.event.EventLogger.add_event')
    @patch('azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_largest_seq_no')
    def assert_extension_sequence_number(self,
                                         patch_get_largest_seq,
                                         patch_add_event,
                                         goal_state_sequence_number,
                                         disk_sequence_number,
                                         expected_sequence_number):
        ext = Extension()
        ext.sequenceNumber = goal_state_sequence_number
        patch_get_largest_seq.return_value = disk_sequence_number

        ext_handler_props = ExtHandlerProperties()
        ext_handler_props.version = "1.2.3"
        ext_handler = ExtHandler(name='foo')
        ext_handler.properties = ext_handler_props

        instance = ExtHandlerInstance(ext_handler=ext_handler, protocol=None)
        seq, path = instance.get_status_file_path(ext)

        try:
            gs_seq_int = int(goal_state_sequence_number)
            gs_int = True
        except ValueError:
            gs_int = False

        if gs_int and gs_seq_int != disk_sequence_number:
            self.assertEqual(1, patch_add_event.call_count)
            args, kw_args = patch_add_event.call_args
            self.assertEqual('SequenceNumberMismatch', kw_args['op'])
            self.assertEqual(False, kw_args['is_success'])
            self.assertEqual('Goal state: {0}, disk: {1}'
                             .format(gs_seq_int, disk_sequence_number),
                             kw_args['message'])
        else:
            self.assertEqual(0, patch_add_event.call_count)

        self.assertEqual(expected_sequence_number, seq)
        if seq > -1:
            self.assertTrue(path.endswith('/foo-1.2.3/status/{0}.status'.format(expected_sequence_number)))
        else:
            self.assertIsNone(path)

    def test_extension_sequence_number(self):
        self.assert_extension_sequence_number(goal_state_sequence_number="12",
                                              disk_sequence_number=366,
                                              expected_sequence_number=12)

        self.assert_extension_sequence_number(goal_state_sequence_number=" 12 ",
                                              disk_sequence_number=366,
                                              expected_sequence_number=12)

        self.assert_extension_sequence_number(goal_state_sequence_number=" foo",
                                              disk_sequence_number=3,
                                              expected_sequence_number=3)

        self.assert_extension_sequence_number(goal_state_sequence_number="-1",
                                              disk_sequence_number=3,
                                              expected_sequence_number=-1)
