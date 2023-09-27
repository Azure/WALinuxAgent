# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import json

from azurelinuxagent.common.protocol.goal_state import GoalState
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateChannel
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import _CaseFoldedDict
from tests.lib.mock_wire_protocol import wire_protocol_data, mock_wire_protocol
from tests.lib.tools import AgentTestCase


class ExtensionsGoalStateFromVmSettingsTestCase(AgentTestCase):
    def test_it_should_parse_vm_settings(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state

            def assert_property(name, value):
                self.assertEqual(value, getattr(extensions_goal_state, name), '{0} was not parsed correctly'.format(name))

            assert_property("activity_id", "a33f6f53-43d6-4625-b322-1a39651a00c9")
            assert_property("correlation_id", "9a47a2a2-e740-4bfc-b11b-4f2f7cfe7d2e")
            assert_property("created_on_timestamp", "2021-11-16T13:22:50.620529Z")
            assert_property("status_upload_blob", "https://dcrcl3a0xs.blob.core.windows.net/$system/edp0plkw2b.86f4ae0a-61f8-48ae-9199-40f402d56864.status?sv=2018-03-28&sr=b&sk=system-1&sig=KNWgC2%3d&se=9999-01-01T00%3a00%3a00Z&sp=w")
            assert_property("status_upload_blob_type", "BlockBlob")
            assert_property("required_features", ["MultipleExtensionsPerHandler"])
            assert_property("on_hold", True)

            #
            # for the rest of the attributes, we check only 1 item in each container (but check the length of the container)
            #

            # agent families
            self.assertEqual(2, len(extensions_goal_state.agent_families), "Incorrect number of agent families. Got: {0}".format(extensions_goal_state.agent_families))
            self.assertEqual("Prod", extensions_goal_state.agent_families[0].name, "Incorrect agent family.")
            self.assertEqual(2, len(extensions_goal_state.agent_families[0].uris), "Incorrect number of uris. Got: {0}".format(extensions_goal_state.agent_families[0].uris))
            expected = "https://zrdfepirv2cdm03prdstr01a.blob.core.windows.net/7d89d439b79f4452950452399add2c90/Microsoft.OSTCLinuxAgent_Prod_uscentraleuap_manifest.xml"
            self.assertEqual(expected, extensions_goal_state.agent_families[0].uris[0], "Unexpected URI for the agent manifest.")

            # extensions
            self.assertEqual(5, len(extensions_goal_state.extensions), "Incorrect number of extensions. Got: {0}".format(extensions_goal_state.extensions))
            self.assertEqual('Microsoft.Azure.Monitor.AzureMonitorLinuxAgent', extensions_goal_state.extensions[0].name, "Incorrect extension name")
            self.assertEqual(1, len(extensions_goal_state.extensions[0].settings[0].publicSettings), "Incorrect number of public settings")
            self.assertEqual(True, extensions_goal_state.extensions[0].settings[0].publicSettings["GCS_AUTO_CONFIG"], "Incorrect public settings")

            # dependency level (single-config)
            self.assertEqual(1, extensions_goal_state.extensions[2].settings[0].dependencyLevel, "Incorrect dependency level (single-config)")

            # dependency level (multi-config)
            self.assertEqual(1, extensions_goal_state.extensions[3].settings[1].dependencyLevel, "Incorrect dependency level (multi-config)")

    def test_it_should_parse_requested_version_properly(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertEqual(family.requested_version_string, "0.0.0.0", "Version should be None")

        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-requested_version.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertEqual(family.requested_version_string, "9.9.9.9", "Version should be 9.9.9.9")

    def test_it_should_parse_is_version_from_rsm_properly(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertEqual(family.is_version_from_rsm, False, "is_version_from_rsm should be False")

        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-requested_version.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertEqual(family.is_version_from_rsm, True, "is_version_from_rsm should be True")

    def test_it_should_parse_missing_status_upload_blob_as_none(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-no_status_upload_blob.json"
        with mock_wire_protocol(data_file) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state

            self.assertIsNone(extensions_goal_state.status_upload_blob, "Expected status upload blob to be None")
            self.assertEqual("BlockBlob", extensions_goal_state.status_upload_blob_type, "Expected status upload blob to be Block")

    def test_it_should_parse_missing_agent_manifests_as_empty(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-no_manifests.json"
        with mock_wire_protocol(data_file) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state
            self.assertEqual(1, len(extensions_goal_state.agent_families), "Expected exactly one agent manifest. Got: {0}".format(extensions_goal_state.agent_families))
            self.assertListEqual([], extensions_goal_state.agent_families[0].uris, "Expected an empty list of agent manifests")

    def test_it_should_parse_missing_extension_manifests_as_empty(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-no_manifests.json"
        with mock_wire_protocol(data_file) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state

            self.assertEqual(3, len(extensions_goal_state.extensions), "Incorrect number of extensions. Got: {0}".format(extensions_goal_state.extensions))
            self.assertEqual([], extensions_goal_state.extensions[0].manifest_uris, "Expected an empty list of manifests for {0}".format(extensions_goal_state.extensions[0]))
            self.assertEqual([], extensions_goal_state.extensions[1].manifest_uris, "Expected an empty list of manifests for {0}".format(extensions_goal_state.extensions[1]))
            self.assertEqual(
                [
                    "https://umsakzkwhng2ft0jjptl.blob.core.windows.net/deeb2df6-c025-e6fb-b015-449ed6a676bc/deeb2df6-c025-e6fb-b015-449ed6a676bc_manifest.xml",
                    "https://umsafmqfbv4hgrd1hqff.blob.core.windows.net/deeb2df6-c025-e6fb-b015-449ed6a676bc/deeb2df6-c025-e6fb-b015-449ed6a676bc_manifest.xml",
                ],
                extensions_goal_state.extensions[2].manifest_uris, "Incorrect list of manifests for {0}".format(extensions_goal_state.extensions[2]))

    def test_it_should_default_to_block_blob_when_the_status_blob_type_is_not_valid(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-invalid_blob_type.json"
        with mock_wire_protocol(data_file) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state

            self.assertEqual("BlockBlob", extensions_goal_state.status_upload_blob_type, 'Expected BlockBlob for an invalid statusBlobType')

    def test_its_source_channel_should_be_host_ga_plugin(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            extensions_goal_state = protocol.get_goal_state().extensions_goal_state

            self.assertEqual(GoalStateChannel.HostGAPlugin, extensions_goal_state.channel, "The channel is incorrect")


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
