# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import json

from azurelinuxagent.common.protocol.goal_state import GoalState, GoalStateProperties
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateChannel
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import _CaseFoldedDict
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from tests.lib.mock_wire_protocol import wire_protocol_data, mock_wire_protocol
from tests.lib.tools import AgentTestCase, patch


class ExtensionsGoalStateFromVmSettingsTestCase(AgentTestCase):
    def test_it_should_parse_vm_settings(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            extensions_goal_state = GoalState(protocol.client, GoalStateProperties.ExtensionsGoalState).extensions_goal_state

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
                self.assertIsNone(family.version, "Version should be None")

        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-agent_family_version.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertEqual(family.version, "9.9.9.9", "Version should be 9.9.9.9")

    def test_it_should_parse_from_version_properly(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertIsNone(family.from_version, "fromVersion should be None")

        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-agent_family_version.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertEqual(family.from_version, "9.9.9.9", "fromVersion should be 9.9.9.9")

    def test_it_should_parse_is_version_from_rsm_properly(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertIsNone(family.is_version_from_rsm, "is_version_from_rsm should be None")

        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-agent_family_version.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertTrue(family.is_version_from_rsm, "is_version_from_rsm should be True")

        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-requested_version_properties_false.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertFalse(family.is_version_from_rsm, "is_version_from_rsm should be False")

    def test_it_should_parse_is_vm_enabled_for_rsm_upgrades_properly(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertIsNone(family.is_vm_enabled_for_rsm_upgrades, "is_vm_enabled_for_rsm_upgrades should be None")

        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-agent_family_version.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertTrue(family.is_vm_enabled_for_rsm_upgrades, "is_vm_enabled_for_rsm_upgrades should be True")

        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-requested_version_properties_false.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertFalse(family.is_vm_enabled_for_rsm_upgrades, "is_vm_enabled_for_rsm_upgrades should be False")

    def test_it_should_parse_is_agent_family_version_to_signature_mappings_properly(self):
        # VMAgentFamily.ga_version_to_signature_mapping should be an empty dict when the goal state
        # VersionToSignatureMappings element is not in goal state (no versions published with signature in that region)
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertEqual(len(family.ga_version_to_signature_mapping), 0)

        # VMAgentFamily.ga_version_to_signature_mapping should be a dict with one element when the goal state
        # VersionToSignatureMappings element has one GASignature element
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-one_ga_signature.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertEqual(len(family.ga_version_to_signature_mapping), 1)
                # Prod and Test types have different signatures
                if family.name == "Prod":
                    expected_dict = {
                        "9.9.9.10": "MIInpwYJKoZIhvcNAQcCProd99910="
                    }
                else:
                    expected_dict = {
                        "9.9.9.10": "MIInpwYJKoZIhvcNAQcCTest99910="
                    }
                self.assertDictEqual(family.ga_version_to_signature_mapping, expected_dict)

        # VMAgentFamily.ga_version_to_signature_mapping should be a dict with two elements when the goal state
        # VersionToSignatureMappings element has two GASignature elements
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-two_ga_signatures.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                self.assertEqual(len(family.ga_version_to_signature_mapping), 2)
                # Prod and Test types have different signatures
                if family.name == "Prod":
                    expected_dict = {
                        "9.9.9.10": "MIInpwYJKoZIhvcNAQcCProd99910=",
                        "99999.0.0.0": "MIInpwYJKoZIhvcNAQcCProd999900="
                    }
                else:
                    expected_dict = {
                        "99999.0.0.0": "MIInpwYJKoZIhvcNAQcCTest999900=",
                        "9.9.9.10": "MIInpwYJKoZIhvcNAQcCTest99910="
                    }
                self.assertDictEqual(family.ga_version_to_signature_mapping, expected_dict)

    def test_it_should_handle_invalid_agent_family_version_to_signature_mappings(self):
        # The following test uses a vm_settings with invalid VersionToSignatureMappings to test that the agent handles
        # the invalid fields gracefully

        # The Prod family has an empty versionToSignatureMappings element
        #      {
        #        "name": "Prod",
        #        ...
        #        "versionToSignatureMappings": []
        #      }

        # The Test family has three GASignature elements, one missing the EncodedSignature element, one missing the
        # Version element, and one missing both elements
        #     {
        #       "name": "Test",
        #       ...
        #       "versionToSignatureMappings": [
        #         {
        #           "version": "2.15.0.5"
        #         },
        #         {
        #           "encodedSignature": "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"
        #         },
        #         {}
        #        ]
        #      }
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-invalid_ga_signature_mappings.json"
        with mock_wire_protocol(data_file) as protocol:
            protocol.mock_wire_data.set_etag(888)
            goal_state = GoalState(protocol.client)
            families = goal_state.extensions_goal_state.agent_families
            for family in families:
                # GA version to signature mapping should be an empty dict if there are no valid mappings in the GS
                self.assertDictEqual(family.ga_version_to_signature_mapping, {})

    def test_it_should_parse_missing_status_upload_blob_as_none(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-no_status_upload_blob.json"
        with mock_wire_protocol(data_file) as protocol:
            extensions_goal_state = GoalState(protocol.client, GoalStateProperties.ExtensionsGoalState).extensions_goal_state

            self.assertIsNone(extensions_goal_state.status_upload_blob, "Expected status upload blob to be None")
            self.assertEqual("BlockBlob", extensions_goal_state.status_upload_blob_type, "Expected status upload blob to be Block")

    def test_it_should_parse_missing_agent_manifests_as_empty(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-no_manifests.json"
        with mock_wire_protocol(data_file) as protocol:
            extensions_goal_state = GoalState(protocol.client, GoalStateProperties.ExtensionsGoalState).extensions_goal_state
            self.assertEqual(1, len(extensions_goal_state.agent_families), "Expected exactly one agent manifest. Got: {0}".format(extensions_goal_state.agent_families))
            self.assertListEqual([], extensions_goal_state.agent_families[0].uris, "Expected an empty list of agent manifests")

    def test_it_should_parse_missing_extension_manifests_as_empty(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-no_manifests.json"
        with mock_wire_protocol(data_file) as protocol:
            extensions_goal_state = GoalState(protocol.client, GoalStateProperties.ExtensionsGoalState).extensions_goal_state

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
            extensions_goal_state = GoalState(protocol.client, GoalStateProperties.ExtensionsGoalState).extensions_goal_state

            self.assertEqual("BlockBlob", extensions_goal_state.status_upload_blob_type, 'Expected BlockBlob for an invalid statusBlobType')

    def test_its_source_channel_should_be_host_ga_plugin(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            extensions_goal_state = GoalState(protocol.client, GoalStateProperties.ExtensionsGoalState).extensions_goal_state

            self.assertEqual(GoalStateChannel.HostGAPlugin, extensions_goal_state.channel, "The channel is incorrect")

    def test_it_should_parse_encoded_signature_plugin_property(self):
        data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        # This vm settings extensions goal state has 1 extension with encodedSignature (AzureMonitorLinuxAgent). The
        # remaining extensions do not have encodedSignature
        expected_signature = "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"
        with mock_wire_protocol(data_file) as protocol:
            extensions = GoalState(protocol.client, GoalStateProperties.ExtensionsGoalState).extensions_goal_state.extensions
            self.assertEqual(expected_signature, extensions[0].encoded_signature)

            # extension.encoded_signature should be an empty string if the property does not exist for the extension
            for i in range(1, 5):
                self.assertEqual(extensions[i].encoded_signature, "")

    def test_supports_agent_signature_mapping_should_check_hgap_version_and_cvm(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE_VM_SETTINGS) as protocol:
            extensions_goal_state = GoalState(protocol.client, GoalStateProperties.ExtensionsGoalState).extensions_goal_state

            # When HGAP version is sufficient and VM is a CVM, it should return True
            extensions_goal_state._host_ga_plugin_version = FlexibleVersion("1.0.8.177")
            with patch("azurelinuxagent.ga.confidential_vm_info.ConfidentialVMInfo.is_confidential_vm", return_value=True):
                self.assertTrue(extensions_goal_state.supports_agent_signature_mapping(), "supports_agent_signature_mapping should be True when HGAP version >= 1.0.8.177 and VM is a CVM")

            # When HGAP version is sufficient but VM is not a CVM, it should return False
            extensions_goal_state._host_ga_plugin_version = FlexibleVersion("1.0.8.177")
            with patch("azurelinuxagent.ga.confidential_vm_info.ConfidentialVMInfo.is_confidential_vm", return_value=False):
                self.assertFalse(extensions_goal_state.supports_agent_signature_mapping(), "supports_agent_signature_mapping should be False when VM is not a CVM")

            # When HGAP version is below the minimum but VM is a CVM, it should return False
            extensions_goal_state._host_ga_plugin_version = FlexibleVersion("1.0.8.176")
            with patch("azurelinuxagent.ga.confidential_vm_info.ConfidentialVMInfo.is_confidential_vm", return_value=True):
                self.assertFalse(extensions_goal_state.supports_agent_signature_mapping(), "supports_agent_signature_mapping should be False when HGAP version < 1.0.8.177")


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
