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

        assert_property("activity_id", "a33f6f53-43d6-4625-b322-1a39651a00c9")
        assert_property("correlation_id", "9a47a2a2-e740-4bfc-b11b-4f2f7cfe7d2e")
        assert_property("created_on_timestamp", "2021-11-16T13:22:50.620522Z")
        assert_property("status_upload_blob", "https://dcrcl3a0xs.blob.core.windows.net/$system/edp0plkw2b.86f4ae0a-61f8-48ae-9199-40f402d56864.status?sv=2018-03-28&sr=b&sk=system-1&sig=KNWgC2%3d&se=9999-01-01T00%3a00%3a00Z&sp=w")
        assert_property("status_upload_blob_type", "BlockBlob")
        assert_property("required_features", ["MultipleExtensionsPerHandler"])
        assert_property("on_hold", True)

        #
        # for the rest of the attributes, we check only 1 item in each container (but check the length of the container)
        #

        # agent manifests
        self.assertEqual(2, len(vm_settings.agent_manifests), "Incorrect number of agent manifests. Got: {0}".format(vm_settings.agent_manifests))
        self.assertEqual("Prod", vm_settings.agent_manifests[0].family, "Incorrect agent family.")
        self.assertEqual(2, len(vm_settings.agent_manifests[0].uris), "Incorrect number of uris. Got: {0}".format(vm_settings.agent_manifests[0].uris))
        self.assertEqual("https://zrdfepirv2cdm03prdstr01a.blob.core.windows.net/7d89d439b79f4452950452399add2c90/Microsoft.OSTCLinuxAgent_Prod_uscentraleuap_manifest.xml", vm_settings.agent_manifests[0].uris[0], "Incorrect number of uris.")

        # extensions
        self.assertEqual(5, len(vm_settings.extensions), "Incorrect number of extensions. Got: {0}".format(vm_settings.extensions))
        self.assertEqual('Microsoft.Azure.Monitor.AzureMonitorLinuxAgent', vm_settings.extensions[0].name, "Incorrect extension name")
        self.assertEqual(1, len(vm_settings.extensions[0].settings[0].publicSettings), "Incorrect number of public settings")
        self.assertEqual(True, vm_settings.extensions[0].settings[0].publicSettings["GCS_AUTO_CONFIG"], "Incorrect public settings")

        # dependency level (single-config)
        self.assertEqual(1, vm_settings.extensions[2].settings[0].dependencyLevel, "Incorrect dependency level (single-config)")

        # dependency level (multi-config)
        self.assertEqual(1, vm_settings.extensions[3].settings[1].dependencyLevel, "Incorrect dependency level (multi-config)")

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
