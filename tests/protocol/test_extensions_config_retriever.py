from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.protocol.wire import InVMArtifactsProfile
from azurelinuxagent.common.protocol.extensions_config_retriever import ExtensionsConfigRetriever, \
    FastTrackChangeDetail, GOAL_STATE_SOURCE_FABRIC, GOAL_STATE_SOURCE_FAST_TRACK
from tests.protocol.mockwiredata import WireProtocolData, DATA_FILE
from tests.tools import AgentTestCase, patch, clear_singleton_instances


class TestExtensionsConfigRetriever(AgentTestCase):
    DEFAULT_IN_SVD_SEQ_NO = 1
    DEFAULT_INCARNATION = 1
    DEFAULT_SEQ_NO = 1
    SAMPLE_URL = "http://this/doesnt/matter"

    def setUp(self):
        super(TestExtensionsConfigRetriever, self).setUp()
        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not
        # reuse a previous state
        clear_singleton_instances(ProtocolUtil)

    def test_get_on_hold(self):
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(retriever.get_is_on_hold())

        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertFalse(retriever.get_is_on_hold())

    def test_ext_config_empty_arguments(self):
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(DATA_FILE)
        ext_conf = retriever.get_ext_config(5, None)
        self.assertFalse(ext_conf.changed)
        self.assertEqual(0, len(ext_conf.ext_handlers.extHandlers))

        ext_conf = retriever.get_ext_config(None, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertFalse(ext_conf.changed)
        self.assertEqual(0, len(ext_conf.ext_handlers.extHandlers))

    def test_ext_config_startup_no_profile(self):
        test_data = WireProtocolData(DATA_FILE)
        wire_client = MockWireClient(test_data.ext_conf, artifacts_profile=None)
        retriever = ExtensionsConfigRetriever(wire_client=wire_client)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.NO_PROFILE in ext_conf.get_description())

    def test_ext_config_startup_no_profile_uri(self):
        # The default ext_conf for WireProtocolData is missing the uri
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(DATA_FILE)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.NO_PROFILE_URI in ext_conf.get_description())

    def test_ext_config_startup_no_created_on_ticks(self):
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_no_ticks.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.DISABLED in ext_conf.get_description())

    def test_ext_config_startup_no_created_on_schema_version(self):
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_no_schema_version.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.DISABLED in ext_conf.get_description())

    def test_ext_config_startup_fabric_no_extensions(self):
        test_data_file = TestExtensionsConfigRetriever.get_test_data(ext_conf="wire/ext_conf_no_extensions.xml")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(0, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))

    def test_ext_config_startup_fast_track_no_extensions(self):
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_no_extensions.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.NO_EXTENSIONS in ext_conf.get_description())

    def test_ext_config_startup_fast_track_no_extension_data(self):
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile= "wire/in_vm_artifacts_profile_no_ext_config.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.NO_EXTENSIONS in ext_conf.get_description())

    @patch("azurelinuxagent.common.conf.get_extensions_fast_track_enabled", return_value=False)
    def test_ext_config_startup_fast_track_disabled(self, conf_get_fast_track_enabled):
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.TURNED_OFF_IN_CONFIG in ext_conf.get_description())

    def test_ext_config_startup_fabric_newer(self):
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())

    def test_ext_config_startup_fast_track_newer(self):
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertFalse(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FAST_TRACK))
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())

    def test_ext_config_startup_fast_track_no_settings(self):
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_no_settings.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertFalse(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FAST_TRACK))
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())

    def test_ext_config_startup_same_ticks(self):
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_same_ticks.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())

    def test_ext_config_post_startup_no_profile(self):
        # Run the startup goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        wire_client.return_artifacts_profile = None
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertFalse(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.NO_PROFILE in ext_conf.get_description())

    def test_ext_config_post_startup_no_profile_uri(self):
        # Run the startup goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        # Set a new FastTrack goal state that we won't find
        new_test_data_file = TestExtensionsConfigRetriever.get_test_data(
            ext_conf="wire/ext_conf_newer.xml", artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        new_test_data = WireProtocolData(new_test_data_file)
        wire_client.return_ext_config = new_test_data.ext_conf
        wire_client.return_artifacts_profile = InVMArtifactsProfile(new_test_data.vm_artifacts_profile)

        # Run with a new incarnation to read the uri
        ext_conf = retriever.get_ext_config(2, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))
        self.assertTrue(FastTrackChangeDetail.NO_PROFILE_URI in ext_conf.get_description())

    def test_ext_config_post_startup_fabric_no_extensions(self):
        # Run a FastTrack goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        # Now process a Fabric goal state with no extensions
        new_test_data_file = TestExtensionsConfigRetriever.get_test_data(ext_conf="wire/ext_conf_no_extensions.xml")
        new_test_data = WireProtocolData(new_test_data_file)
        wire_client.return_ext_config = new_test_data.ext_conf
        ext_conf = retriever.get_ext_config(2, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertIsNone(ext_conf.ext_handlers)
        self.assertTrue(ext_conf.get_description().startswith(GOAL_STATE_SOURCE_FABRIC))

    def test_ext_config_post_startup_fast_track_no_extensions(self):
        # Run a Fabric goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        new_test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_no_extensions.json")
        new_test_data = WireProtocolData(new_test_data_file)
        wire_client.return_artifacts_profile = InVMArtifactsProfile(new_test_data.vm_artifacts_profile)

        # Since we have no extensions, we won't have a new goal state
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertFalse(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(FastTrackChangeDetail.NO_EXTENSIONS in ext_conf.get_description())

    def test_ext_config_post_startup_fast_track_disabled(self):
        # Run a Fabric goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        new_test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        new_test_data = WireProtocolData(new_test_data_file)
        wire_client.return_artifacts_profile = InVMArtifactsProfile(new_test_data.vm_artifacts_profile)

        with patch("azurelinuxagent.common.conf.get_extensions_fast_track_enabled", return_value=False) as mock_conf:
            ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
            self.assertFalse(ext_conf.changed)
            self.assertTrue(ext_conf.is_fabric_change)
            self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
            self.assertTrue(FastTrackChangeDetail.TURNED_OFF_IN_CONFIG in ext_conf.get_description())

    def test_ext_config_post_startup_only_fabric_changed(self):
        # Run a FastTrack goal state because it's newer
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        new_test_data_file = TestExtensionsConfigRetriever.get_test_data(
            ext_conf="wire/ext_conf_svd_seq_no_changed.xml")
        new_test_data = WireProtocolData(new_test_data_file)
        wire_client.return_ext_config = new_test_data.ext_conf

        # Fabric goal state is older but has the incarnation changed
        ext_conf = retriever.get_ext_config(2, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertIsNone(ext_conf.ext_handlers)
        self.assertTrue(FastTrackChangeDetail.NO_CHANGE in ext_conf.get_description())

    def test_ext_config_post_startup_only_fast_track_changed(self):
        # Run a Fabric goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        # Next goal state is a FastTrack change
        new_test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        new_test_data = WireProtocolData(new_test_data_file)
        wire_client.return_artifacts_profile = InVMArtifactsProfile(new_test_data.vm_artifacts_profile)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertFalse(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())

    def test_ext_config_post_startup_both_changed(self):
        # Run a Fabric goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()
        self.assertEqual("ExtensionsConfig_fa.1.xml", ext_conf.get_ext_config_file_name())

        # Both goal states change
        new_test_data_file = TestExtensionsConfigRetriever.get_test_data(
            ext_conf="wire/ext_conf_svd_seq_no_changed.xml",
            artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        new_test_data = WireProtocolData(new_test_data_file)
        wire_client.return_ext_config = new_test_data.ext_conf
        wire_client.return_artifacts_profile = InVMArtifactsProfile(new_test_data.vm_artifacts_profile)

        # We'll first run the Fabric goal state
        ext_conf = retriever.get_ext_config(2, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())
        retriever.commit_processed()
        self.assertEqual("ExtensionsConfig_fa.2.xml", ext_conf.get_ext_config_file_name())

        # Then we'll run FastTrack because its createdOnTicks is higher
        ext_conf = retriever.get_ext_config(2, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertFalse(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(FastTrackChangeDetail.NO_CHANGE in ext_conf.get_description())
        retriever.commit_processed()
        self.assertEqual("ExtensionsConfig_ft.2.xml", ext_conf.get_ext_config_file_name())

    def test_ext_config_post_startup_svd_seq_no_not_changed(self):
        # Run a Fabric goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        # Incarnation changes, but the sequence number does not
        ext_conf = retriever.get_ext_config(2, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertIsNone(ext_conf.ext_handlers)
        self.assertTrue(FastTrackChangeDetail.NO_CHANGE in ext_conf.get_description())

    def test_ext_config_post_startup_svd_seq_no_not_changed_fast_track_changed_last_fabric(self):
        # Run a Fabric goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        # Set FastTrack to changed
        new_test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        new_test_data = WireProtocolData(new_test_data_file)
        wire_client.return_artifacts_profile = InVMArtifactsProfile(new_test_data.vm_artifacts_profile)

        # Since the last GoalState was Fabric, we'll process that first
        ext_conf = retriever.get_ext_config(2, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertIsNone(ext_conf.ext_handlers)
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())
        retriever.commit_processed()

        # Next we'll run FastTrack
        ext_conf = retriever.get_ext_config(2, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertFalse(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(FastTrackChangeDetail.NO_CHANGE in ext_conf.get_description())
        retriever.commit_processed()

    def test_ext_config_post_startup_svd_seq_no_not_changed_fast_track_changed_last_fast_track(self):
        # Run a FastTrack goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        # Set FastTrack to changed
        new_test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob.json")
        new_test_data = WireProtocolData(new_test_data_file)
        wire_client.return_artifacts_profile = InVMArtifactsProfile(new_test_data.vm_artifacts_profile)

        # We'll process the Fabric goal state without extensions
        ext_conf = retriever.get_ext_config(2, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertIsNone(ext_conf.ext_handlers)
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())
        retriever.commit_processed()

    def test_ext_config_post_startup_nothing_changed(self):
        # Run a Fabric goal state
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, wire_client = TestExtensionsConfigRetriever.create_retriever(test_data_file)
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        retriever.commit_processed()

        # Next run nothing changed
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertFalse(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(FastTrackChangeDetail.NO_CHANGE in ext_conf.get_description())
        retriever.commit_processed()

    def test_ext_config_no_commit(self):
        # Run a FastTrack goal state first
        test_data_file = TestExtensionsConfigRetriever.get_test_data(
            artifacts_profile="wire/in_vm_artifacts_profile_blob_newer.json")
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertFalse(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())

        # Don't commit, and verify we treat the next run as startup
        ext_conf = retriever.get_ext_config(1, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertFalse(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())

    def test_startup_fabric_string_incarnation(self):
        incarnation = "{7594AE98-19A4-48E4-946F-B60D533DBB07}"
        test_data_file = TestExtensionsConfigRetriever.get_test_data()
        retriever, _ = TestExtensionsConfigRetriever.create_retriever(test_data_file)

        ext_conf = retriever.get_ext_config(incarnation, TestExtensionsConfigRetriever.SAMPLE_URL)
        self.assertTrue(ext_conf.changed)
        self.assertTrue(ext_conf.is_fabric_change)
        self.assertEqual(1, len(ext_conf.ext_handlers.extHandlers))
        self.assertTrue(FastTrackChangeDetail.SEQ_NO_CHANGED in ext_conf.get_description())

    @staticmethod
    def get_test_data(
            ext_conf="wire/ext_conf_in_vm_artifacts_profile.xml",
            artifacts_profile="wire/in_vm_artifacts_profile_blob.json"):
        test_data_file = DATA_FILE.copy()
        test_data_file["vm_artifacts_profile"] = artifacts_profile
        test_data_file["ext_conf"] = ext_conf

        return test_data_file

    @staticmethod
    def create_retriever(test_data_file):
        test_data = WireProtocolData(test_data_file)
        profile = InVMArtifactsProfile(test_data.vm_artifacts_profile)
        wire_client = MockWireClient(test_data.ext_conf, profile)

        return ExtensionsConfigRetriever(wire_client=wire_client), wire_client


class MockWireClient:

    def __init__(self, ext_config=None, artifacts_profile=None):
        self.return_ext_config = ext_config
        self.return_artifacts_profile = artifacts_profile

    def get_header(self):
        return None

    def fetch_config(self, uri, header):
        return self.return_ext_config

    def get_endpoint(self):
        return "http://www.blahblahblah.lu"

    def get_artifacts_profile(self, artifacts_profile_uri):
        return self.return_artifacts_profile
