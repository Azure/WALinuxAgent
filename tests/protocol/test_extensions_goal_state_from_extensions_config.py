# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
from azurelinuxagent.common.AgentGlobals import AgentGlobals
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

    def test_extension_goal_state_should_parse_requested_version_properly(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            manifests, _ = protocol.get_vmagent_manifests()
            for manifest in manifests:
                self.assertEqual(manifest.requested_version_string, "0.0.0.0", "Version should be None")

        data_file = mockwiredata.DATA_FILE.copy()
        data_file["ext_conf"] = "hostgaplugin/ext_conf-requested_version.xml"
        with mock_wire_protocol(data_file) as protocol:
            manifests, _ = protocol.get_vmagent_manifests()
            for manifest in manifests:
                self.assertEqual(manifest.requested_version_string, "9.9.9.10", "Version should be 9.9.9.10")
