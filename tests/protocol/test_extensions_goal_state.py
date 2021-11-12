# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import json
import os.path
import re

from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState, GoalStateMismatchError
from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import _CaseFoldedDict
from azurelinuxagent.common.utils import fileutil
from tests.protocol.mocks import HttpRequestPredicates, mockwiredata, mock_wire_protocol
from tests.tools import AgentTestCase, data_dir, PropertyMock, patch


class ExtensionsGoalStateTestCase(HttpRequestPredicates, AgentTestCase):
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

    def test_create_from_vm_settings_should_parse_vm_settings(self):
        vm_settings_text = fileutil.read_file(os.path.join(data_dir, "hostgaplugin/vm_settings.json"))
        vm_settings = ExtensionsGoalStateFactory.create_from_vm_settings("123", vm_settings_text)

        self.assertEqual("https://dcrcqabsr1.blob.core.windows.net/$system/edpxmal5j1.058b176d-445b-4e75-bd97-4911511b7d96.status?sv=2018-03-28&sr=b&sk=system-1&sig=U4KaLxlyYfgQ%2fie8RCwgMBSXa3E4vlW0ozPYOEHikoc%3d&se=9999-01-01T00%3a00%3a00Z&sp=w", vm_settings.status_upload_blob, 'statusUploadBlob.value was not parsed correctly')
        self.assertEqual("BlockBlob", vm_settings.status_upload_blob_type, 'statusBlobType was not parsed correctly')
        self.assertEqual(["MultipleExtensionsPerHandler"], vm_settings.required_features, 'requiredFeatures was not parsed correctly')


class CaseFoldedDictionaryTestCase(AgentTestCase):
    def test_it_should_retrieve_items_ignoring_case(self):
        dictionary = json.loads('''{
            "activityId": "2e7f8b5d-f637-4721-b757-cb190d49b4e9",
            "StatusUploadBlob": {
                "statusBlobType": "BlockBlob",
                "value": "https://dcrcqabsr1.blob.core.windows.net/$system/edpxmal5j1.058b176d-445b-4e75-bd97-4911511b7d96.status"
            },
            "gaFamilies": [
                {
                    "Name": "Prod",
                    "Version": "2.5.0.2",
                    "Uris": [
                        "https://zrdfepirv2cdm03prdstr01a.blob.core.windows.net/7d89d439b79f4452950452399add2c90/Microsoft.OSTCLinuxAgent_Prod_uscentraleuap_manifest.xml",
                        "https://ardfepirv2cdm03prdstr01a.blob.core.windows.net/7d89d439b79f4452950452399add2c90/Microsoft.OSTCLinuxAgent_Prod_uscentraleuap_manifest.xml"
                    ]
                }
            ]
         }''')

        case_folded = _CaseFoldedDict.from_dict(dictionary)

        def test_retrieve_item(key, expected_value):
            """
            Test for operators [] and in, and methods get() and has_key()
            """
            try:
                self.assertEqual(expected_value, case_folded[key], "Operator [] retrieved incorrect value for '{0}'".format(key))
            except KeyError:
                self.fail("Operator [] failed to retrieve '{0}'".format(key))

            self.assertTrue(case_folded.has_key(key), "Method has_key() did not find '{0}'".format(key))

            self.assertEqual(expected_value, case_folded.get(key), "Method get() retrieved incorrect value for '{0}'".format(key))
            self.assertTrue(key in case_folded, "Operator in did not find key '{0}'".format(key))

        test_retrieve_item("activityId", "2e7f8b5d-f637-4721-b757-cb190d49b4e9")
        test_retrieve_item("activityid", "2e7f8b5d-f637-4721-b757-cb190d49b4e9")
        test_retrieve_item("ACTIVITYID", "2e7f8b5d-f637-4721-b757-cb190d49b4e9")

        self.assertEqual("BlockBlob", case_folded["statusuploadblob"]["statusblobtype"], "Failed to retrieve item in nested dictionary")
        self.assertEqual("Prod", case_folded["gafamilies"][0]["name"], "Failed to retrieve item in nested array")
