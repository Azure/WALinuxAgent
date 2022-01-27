# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import copy
import re
import sys

from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from tests.protocol.mocks import mockwiredata, mock_wire_protocol
from tests.tools import AgentTestCase, load_data

# Python < 3.7 can't copy regular expressions, this is the recommended patch
if sys.version_info[0] < 3 or sys.version_info[0] == 3 and sys.version_info[1] < 7:
    copy._deepcopy_dispatch[type(re.compile(''))] = lambda r, _: r


class ExtensionsGoalStateTestCase(AgentTestCase):
    def test_create_from_extensions_config_should_assume_block_when_blob_type_is_not_valid(self):
        data_file = mockwiredata.DATA_FILE.copy()
        data_file["ext_conf"] = "hostgaplugin/ext_conf-invalid_blob_type.xml"
        with mock_wire_protocol(data_file) as protocol:
            extensions_goal_state = ExtensionsGoalStateFactory.create_from_extensions_config(123, load_data("hostgaplugin/ext_conf-invalid_blob_type.xml"), protocol)
            self.assertEqual("BlockBlob", extensions_goal_state.status_upload_blob_type, 'Expected BlockBob for an invalid statusBlobType')

    def test_create_from_vm_settings_should_assume_block_when_blob_type_is_not_valid(self):
        extensions_goal_state = ExtensionsGoalStateFactory.create_from_vm_settings(1234567890, load_data("hostgaplugin/vm_settings-invalid_blob_type.json"))
        self.assertEqual("BlockBlob", extensions_goal_state.status_upload_blob_type, 'Expected BlockBob for an invalid statusBlobType')

    def test_extension_goal_state_should_parse_requested_version_properly(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            fabric_manifests, _ = protocol.get_vmagent_manifests()
            for manifest in fabric_manifests:
                self.assertEqual(manifest.requested_version_string, "0.0.0.0", "Version should be None")

            vm_settings_ga_manifests = protocol.client._host_plugin._cached_vm_settings.agent_manifests
            for manifest in vm_settings_ga_manifests:
                self.assertEqual(manifest.requested_version_string, "0.0.0.0", "Version should be None")

        data_file = mockwiredata.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-requested_version.json"
        data_file["ext_conf"] = "hostgaplugin/ext_conf-requested_version.xml"
        with mock_wire_protocol(data_file) as protocol:
            fabric_manifests = protocol.client.get_goal_state()._extensions_config.agent_manifests
            for manifest in fabric_manifests:
                self.assertEqual(manifest.requested_version_string, "9.9.9.10", "Version should be 9.9.9.10")

            vm_settings_ga_manifests = protocol.client._host_plugin._cached_vm_settings.agent_manifests
            for manifest in vm_settings_ga_manifests:
                self.assertEqual(manifest.requested_version_string, "9.9.9.9", "Version should be 9.9.9.9")
