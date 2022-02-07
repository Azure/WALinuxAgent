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

