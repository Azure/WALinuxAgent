# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import json
import os.path
import re

from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState, GoalStateMismatchError, _CaseFoldedDict
from azurelinuxagent.common.utils import fileutil
from tests.protocol.HttpRequestPredicates import HttpRequestPredicates
from tests.tools import AgentTestCase, data_dir


class ExtensionsGoalStateTestCase(HttpRequestPredicates, AgentTestCase):
    def test_compare_should_report_mismatches_between_extensions_config_and_vm_settings(self):
        from_vm_settings = ExtensionsGoalState.create_from_vm_settings("123", fileutil.read_file(os.path.join(data_dir, "hostgaplugin/vm_settings.json")))
        from_extensions_config = ExtensionsGoalState.create_from_extensions_config("123", fileutil.read_file(os.path.join(data_dir, "hostgaplugin/ext_conf.xml")))

        from_vm_settings._required_features = ['FORCE_A_MISMATCH_FEATURE']
        with self.assertRaisesRegexCM(GoalStateMismatchError, "MultipleExtensionsPerHandler.*!=.*FORCE_A_MISMATCH_FEATURE"):
            ExtensionsGoalState.compare(from_extensions_config, from_vm_settings)

    def test_create_from_extensions_config_should_assume_block_when_blob_type_is_not_valid(self):
        extensions_config_text = fileutil.read_file(os.path.join(data_dir, "hostgaplugin/ext_conf.xml"))
        extensions_config_text = re.sub(r'statusBlobType.*=.*"BlockBlob"', 'statusBlobType="INVALID_BLOB_TYPE"', extensions_config_text)
        if "INVALID_BLOB_TYPE" not in extensions_config_text:
            raise Exception("Failed to inject an invalid blob type in the test data")
        extensions_config = ExtensionsGoalState.create_from_extensions_config("123", extensions_config_text)

        actual = extensions_config.get_status_upload_blob_type()
        self.assertEqual("BlockBlob", actual, 'Expected BlockBob for an invalid statusBlobType')

    def test_create_from_vm_settings_should_assume_block_when_blob_type_is_not_valid(self):
        vm_settings_text = fileutil.read_file(os.path.join(data_dir, "hostgaplugin/vm_settings.json"))
        vm_settings_text =  re.sub(r'"statusBlobType".*:.*"BlockBlob"', '"statusBlobType": "INVALID_BLOB_TYPE"', vm_settings_text)
        if "INVALID_BLOB_TYPE" not in vm_settings_text:
            raise Exception("Failed to inject an invalid blob type in the test data")
        vm_settings = ExtensionsGoalState.create_from_vm_settings("123", vm_settings_text)

        actual = vm_settings.get_status_upload_blob_type()
        self.assertEqual("BlockBlob", actual, 'Expected BlockBob for an invalid statusBlobType')

    def test_create_from_vm_settings_should_parse_vm_settiings(self):
        vm_settings_text = fileutil.read_file(os.path.join(data_dir, "hostgaplugin/vm_settings.json"))
        vm_settings = ExtensionsGoalState.create_from_vm_settings("123", vm_settings_text)

        # TODO: HostGAPlugin 112 does not include the status blob; see TODO in ExtensionsGoalState
        # self.assertEqual("https://dcrcqabsr1.blob.core.windows.net/$system/edpxmal5j1.058b176d-445b-4e75-bd97-4911511b7d96.status?sv=2018-03-28&sr=b&sk=system-1&sig=U4KaLxlyYfgQ%2fie8RCwgMBSXa3E4vlW0ozPYOEHikoc%3d&se=9999-01-01T00%3a00%3a00Z&sp=w", vm_settings.get_status_upload_blob(), 'statusUploadBlob.value was not parsed correctly')
        # self.assertEqual("BlockBlob", vm_settings.get_status_upload_blob_type(), 'statusBlobType was not parsed correctly')
        self.assertEqual(["MultipleExtensionsPerHandler"], vm_settings.get_required_features(), 'requiredFeatures was not parsed correctly')


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
