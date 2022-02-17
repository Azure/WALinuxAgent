# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateChannel
from tests.protocol.mocks import mockwiredata, mock_wire_protocol
from tests.tools import AgentTestCase


class ExtensionsGoalStateFromExtensionsConfigTestCase(AgentTestCase):
    def test_it_should_parse_in_vm_metadata(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_IN_VM_META_DATA) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state
            self.assertEqual("555e551c-600e-4fb4-90ba-8ab8ec28eccc", extensions_goal_state.activity_id, "Incorrect activity Id")
            self.assertEqual("400de90b-522e-491f-9d89-ec944661f531", extensions_goal_state.correlation_id, "Incorrect correlation Id")
            self.assertEqual('2020-11-09T17:48:50.412125Z', extensions_goal_state.created_on_timestamp, "Incorrect GS Creation time")

    def test_it_should_use_default_values_when_in_vm_metadata_is_missing(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state
            self.assertEqual(AgentGlobals.GUID_ZERO, extensions_goal_state.activity_id, "Incorrect activity Id")
            self.assertEqual(AgentGlobals.GUID_ZERO, extensions_goal_state.correlation_id, "Incorrect correlation Id")
            self.assertEqual('1900-01-01T00:00:00.000000Z', extensions_goal_state.created_on_timestamp, "Incorrect GS Creation time")

    def test_it_should_use_default_values_when_in_vm_metadata_is_invalid(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_INVALID_VM_META_DATA) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state
            self.assertEqual(AgentGlobals.GUID_ZERO, extensions_goal_state.activity_id, "Incorrect activity Id")
            self.assertEqual(AgentGlobals.GUID_ZERO, extensions_goal_state.correlation_id, "Incorrect correlation Id")
            self.assertEqual('1900-01-01T00:00:00.000000Z', extensions_goal_state.created_on_timestamp, "Incorrect GS Creation time")

    def test_it_should_parse_missing_status_upload_blob_as_none(self):
        data_file = mockwiredata.DATA_FILE.copy()
        data_file["ext_conf"] = "hostgaplugin/ext_conf-no_status_upload_blob.xml"
        with mock_wire_protocol(data_file) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state

            self.assertIsNone(extensions_goal_state.status_upload_blob, "Expected status upload blob to be None")
            self.assertEqual("BlockBlob", extensions_goal_state.status_upload_blob_type, "Expected status upload blob to be Block")

    def test_it_should_default_to_block_blob_when_the_status_blob_type_is_not_valid(self):
        data_file = mockwiredata.DATA_FILE.copy()
        data_file["ext_conf"] = "hostgaplugin/ext_conf-invalid_blob_type.xml"
        with mock_wire_protocol(data_file) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state
            self.assertEqual("BlockBlob", extensions_goal_state.status_upload_blob_type, 'Expected BlockBob for an invalid statusBlobType')

    def test_it_should_parse_empty_depends_on_as_dependency_level_0(self):
        data_file = mockwiredata.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-empty_depends_on.json"
        data_file["ext_conf"] = "hostgaplugin/ext_conf-empty_depends_on.xml"
        with mock_wire_protocol(data_file) as protocol:
            extensions = protocol.get_goal_state().extensions_goal_state.extensions

            self.assertEqual(0, extensions[0].settings[0].dependencyLevel, "Incorrect dependencyLevel}")

    def test_its_source_channel_should_be_wire_server(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state

            self.assertEqual(GoalStateChannel.WireServer, extensions_goal_state.source_channel, "The source_channel is incorrect")
