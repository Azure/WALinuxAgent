# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import copy
import re
import sys

from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState, GoalStateMismatchError
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils import textutil
from tests.protocol.mocks import mockwiredata, mock_wire_protocol
from tests.tools import AgentTestCase

# Python < 3.7 can't copy regular expressions, this is the recommended patch
if sys.version_info[0] < 3 or sys.version_info[0] == 3 and sys.version_info[1] < 7:
    copy._deepcopy_dispatch[type(re.compile(''))] = lambda r, _: r


class ExtensionsGoalStateTestCase(AgentTestCase):
    def test_compare_should_succeed_when_extensions_config_and_vm_settings_are_equal(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            from_extensions_config = protocol.client.get_extensions_goal_state()
            from_vm_settings = protocol.client._extensions_goal_state_from_vm_settings

            try:
                ExtensionsGoalState.compare(from_extensions_config, from_vm_settings)
            except Exception as exception:
                self.fail("Compare goal state failed: {0}".format(textutil.format_exception(exception)))

    def test_compare_should_report_mismatches_between_extensions_config_and_vm_settings(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            from_extensions_config = protocol.client.get_extensions_goal_state()
            from_vm_settings = protocol.client._extensions_goal_state_from_vm_settings

            def assert_compare_raises(setup_copy, failing_attribute):
                from_vm_settings_copy = copy.deepcopy(from_vm_settings)
                setup_copy(from_vm_settings_copy)

                with self.assertRaisesRegexCM(GoalStateMismatchError, re.escape("(Attribute: {0})".format(failing_attribute)), re.DOTALL):
                    ExtensionsGoalState.compare(from_extensions_config, from_vm_settings_copy)

            assert_compare_raises(lambda c: setattr(c, "_activity_id",              'MOCK_ACTIVITY_ID'),        "activity_id")
            assert_compare_raises(lambda c: setattr(c, "_correlation_id",           'MOCK_CORRELATION_ID'),     "correlation_id")
            assert_compare_raises(lambda c: setattr(c, "_created_on_timestamp",     'MOCK_TIMESTAMP'),          "created_on_timestamp")
            assert_compare_raises(lambda c: setattr(c, "_status_upload_blob",       'MOCK_UPLOAD_BLOB'),        "status_upload_blob")
            assert_compare_raises(lambda c: setattr(c, "_status_upload_blob_type",  'MOCK_UPLOAD_BLOB_TYPE'),   "status_upload_blob_type")
            assert_compare_raises(lambda c: setattr(c, "_required_features",        ['MOCK_REQUIRED_FEATURE']), "required_features")
            assert_compare_raises(lambda c: setattr(c, "_on_hold",                  False),                     "on_hold")

            assert_compare_raises(lambda c: setattr(c.agent_manifests[0], "family",  'MOCK_FAMILY'),  r"agent_manifests[0].family")
            assert_compare_raises(lambda c: setattr(c.agent_manifests[0], "version", 'MOCK_VERSION'), r"agent_manifests[0].version")
            assert_compare_raises(lambda c: setattr(c.agent_manifests[0], "uris",    ['MOCK_URI']),   r"agent_manifests[0].uris")

            assert_compare_raises(lambda c: setattr(c.extensions[0], "version",  'MOCK_NAME'),         r"extensions[0].version")
            assert_compare_raises(lambda c: setattr(c.extensions[0], "state",  'MOCK_STATE'),          r"extensions[0].state")
            assert_compare_raises(lambda c: setattr(c.extensions[0], "manifest_uris",  ['MOCK_URI']),  r"extensions[0].manifest_uris")
            assert_compare_raises(lambda c: setattr(c.extensions[0], "supports_multi_config",  True),  r"extensions[0].supports_multi_config")

            assert_compare_raises(lambda c: setattr(c.extensions[0].settings[0], "name",                  'MOCK_NAME'),                 r"extensions[0].settings[0].name")
            assert_compare_raises(lambda c: setattr(c.extensions[0].settings[0], "sequenceNumber",        98765),                       r"extensions[0].settings[0].sequenceNumber")
            assert_compare_raises(lambda c: setattr(c.extensions[0].settings[0], "publicSettings",        {'MOCK_NAME': 'MOCK_VALUE'}), r"extensions[0].settings[0].publicSettings")
            assert_compare_raises(lambda c: setattr(c.extensions[0].settings[0], "protectedSettings",     'MOCK_SETTINGS'),             r"extensions[0].settings[0].protectedSettings")
            assert_compare_raises(lambda c: setattr(c.extensions[0].settings[0], "certificateThumbprint", 'MOCK_CERT'),                 r"extensions[0].settings[0].certificateThumbprint")
            assert_compare_raises(lambda c: setattr(c.extensions[0].settings[0], "dependencyLevel",       56789),                       r"extensions[0].settings[0].dependencyLevel")
            assert_compare_raises(lambda c: setattr(c.extensions[0].settings[0], "state",                 'MOCK_STATE'),                r"extensions[0].settings[0].state")

    def test_compare_should_check_the_status_upload_blob_only_when_the_host_ga_plugin_version_is_greater_then_112(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            from_extensions_config = protocol.client.get_extensions_goal_state()
            from_vm_settings = protocol.client._extensions_goal_state_from_vm_settings

            # we set the status upload value to a dummy value to verify whether the compare() method is checking it or not
            from_vm_settings._status_upload_blob = "A DUMMY VALUE FOR THE STATUS UPLOAD BLOB"

            #
            # 112 and below should not check the status blob
            #
            from_vm_settings._host_ga_plugin_version = FlexibleVersion("1.0.8.112")

            try:
                ExtensionsGoalState.compare(from_extensions_config, from_vm_settings)
            except GoalStateMismatchError as error:
                self.fail("The status upload blob should not have been checked when the Host GA Plugin version is 112 or below (Got error: {0})".format(error))

            #
            # 113 and above should check the status blob
            #
            from_vm_settings._host_ga_plugin_version = FlexibleVersion("1.0.8.113")

            with self.assertRaisesRegexCM(GoalStateMismatchError, r"\(Attribute: status_upload_blob\)"):
                ExtensionsGoalState.compare(from_extensions_config, from_vm_settings)

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

    def test_extension_goal_state_should_parse_requested_version_properly(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            fabric_manifests, _ = protocol.get_vmagent_manifests()
            for manifest in fabric_manifests:
                self.assertEqual(manifest.version, "0.0.0.0", "Version should be None")

            vm_settings_ga_manifests = protocol.client._extensions_goal_state_from_vm_settings.agent_manifests
            for manifest in vm_settings_ga_manifests:
                self.assertEqual(manifest.version, "0.0.0.0", "Version should be None")

        data_file = mockwiredata.DATA_FILE.copy()
        data_file["vm_settings"] = "hostgaplugin/vm_settings-requested_version.json"
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"
        with mock_wire_protocol(data_file) as protocol:
            fabric_manifests, _ = protocol.get_vmagent_manifests()
            for manifest in fabric_manifests:
                self.assertEqual(manifest.version, "9.9.9.10", "Version should be 9.9.9.10")

            vm_settings_ga_manifests = protocol.client._extensions_goal_state_from_vm_settings.agent_manifests
            for manifest in vm_settings_ga_manifests:
                self.assertEqual(manifest.version, "9.9.9.9", "Version should be 9.9.9.9")
