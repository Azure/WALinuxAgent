# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import json
import os.path

from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import _CaseFoldedDict
from azurelinuxagent.common.utils import fileutil
from tests.tools import AgentTestCase, data_dir


class ExtensionsGoalStateFromVmSettingsTestCase(AgentTestCase):
    def test_create_from_vm_settings_should_parse_vm_settings(self):
        vm_settings_text = fileutil.read_file(os.path.join(data_dir, "hostgaplugin/vm_settings.json"))
        vm_settings = ExtensionsGoalStateFactory.create_from_vm_settings("123", vm_settings_text)

        def assert_property(name, value):
            self.assertEqual(value, getattr(vm_settings, name), '{0} was not parsed correctly'.format(name))

        assert_property("activity_id", "2e7f8b5d-f637-4721-b757-cb190d49b4e9")
        assert_property("correlation_id", "1bef4c48-044e-4225-8f42-1d1eac1eb158")
        assert_property("created_on_timestamp", "2021-10-08T21:52:23.161652Z")
        assert_property("status_upload_blob", "https://dcrcqabsr1.blob.core.windows.net/$system/edpxmal5j1.058b176d-445b-4e75-bd97-4911511b7d96.status?sv=2018-03-28&sr=b&sk=system-1&sig=U4KaLxlyYfgQ%2fie8RCwgMBSXa3E4vlW0ozPYOEHikoc%3d&se=9999-01-01T00%3a00%3a00Z&sp=w")
        assert_property("status_upload_blob_type", "BlockBlob")
        assert_property("required_features", ["MultipleExtensionsPerHandler"])
        assert_property("on_hold", True)


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
