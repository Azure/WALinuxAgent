# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import re

from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState, GoalStateMismatchError
from tests.protocol.mocks import mockwiredata, mock_wire_protocol
from tests.tools import AgentTestCase, PropertyMock, patch


class ExtensionsGoalStateTestCase(AgentTestCase):
    def test_compare_should_report_mismatches_between_extensions_config_and_vm_settings(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            from_extensions_config = protocol.client.get_extensions_goal_state()
            from_vm_settings = protocol.client._extensions_goal_state_from_vm_settings

            def test_property(name, value):
                full_name = "azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings.ExtensionsGoalStateFromVmSettings.{0}".format(name)
                with patch(full_name, new_callable=PropertyMock) as property_mock:
                    property_mock.return_value = value
                    with self.assertRaisesRegexCM(GoalStateMismatchError, r"Attribute: {0}.*{1}".format(name, value), re.DOTALL):
                        ExtensionsGoalState.compare(from_extensions_config, from_vm_settings)

            test_property("activity_id",             'MOCK_ACTIVITY_ID')
            test_property("correlation_id",          'MOCK_CORRELATION_ID')
            test_property("created_on_timestamp",    'MOCK_TIMESTAMP')
            test_property("status_upload_blob",      'MOCK_UPLOAD_BLOB')
            test_property("status_upload_blob_type", 'MOCK_UPLOAD_BLOB_TYPE')
            test_property("required_features",       ['MOCK_REQUIRED_FEATURE'])
            test_property("on_hold",                 True)

    def test_create_from_extensions_config_should_assume_block_when_blob_type_is_not_valid(self):
        data_file = mockwiredata.DATA_FILE.copy()
        data_file["ext_conf"] = "hostgaplugin/ext_conf-invalid_blob_type.xml"
        with mock_wire_protocol(data_file) as protocol:
            actual = protocol.client.get_extensions_goal_state().status_upload_blob_type
            self.assertEqual("BlockBlob", actual, 'Expected BlockBob for an invalid statusBlobType')

    def test_create_from_vm_settings_should_assume_block_when_blob_type_is_not_valid(self):
        data_file = mockwiredata.DATA_FILE.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-invalid_blob_type.json"
        with mock_wire_protocol(data_file) as protocol:
            actual = protocol.client._extensions_goal_state_from_vm_settings.status_upload_blob_type
            self.assertEqual("BlockBlob", actual, 'Expected BlockBob for an invalid statusBlobType')
