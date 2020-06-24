# Microsoft Azure Linux Agent
#
# Copyright Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and Openssl 1.0+
#

import os

from azurelinuxagent.common.future import ustr

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.protocol.goal_state import ExtensionsConfig

GOAL_STATE_SOURCE_FABRIC = "Fabric"
GOAL_STATE_SOURCE_FASTTRACK = "FastTrack"

_MSG_PREVIOUSLY_CACHED_PROFILE = "[PERIODIC] Using previously cached artifacts profile"
_MSG_FAST_TRACK_NOT_SUPPORTED = "[PERIODIC] FastTrack is not supported because the createdOnTicks property is missing"

_EXT_CONF_FILE_NAME = "ExtensionsConfig_{0}.{1}.xml"
_EXT_CONFIG_FAST_TRACK = "ft"
_EXT_CONFIG_FABRIC = "fa"


class ExtensionsConfigReasons:
    FABRIC_CHANGED = "FabricChanged"
    FAST_TRACK_CHANGED = "FastTrackChanged"
    NOTHING_CHANGED = "NothingChanged"
    STARTUP_NO_FAST_TRACK = "StartupNoFastTrack"
    STARTUP_FABRIC_NEWER = "StartupFabricNewer"
    STARTUP_FAST_TRACK_NEWER = "StartupFastTrackNewer"


class FastTrackChangeDetail:
    NO_CHANGE = "NoChange"
    NO_EXTENSIONS = "NoExtensions"
    NO_PROFILE = "NoProfile"
    NO_PROFILE_URI = "NoProfileUri"
    SEQ_NO_CHANGED = "SeqNoChanged"
    DISABLED = "Disabled"
    TURNED_OFF_IN_CONFIG = "TurnedOffConfig"
    RETRIEVED = "Retrieved"


class FabricChangeDetail:
    INCARNATION_CHANGED = "IncChanged"
    SVD_SEQ_NO_NOT_CHANGED = "SvdSeqNoNotChanged"
    NO_CHANGE = "NoChange"
    RETRIEVED = "Retrieved"


class GenericExtensionsConfig(ExtensionsConfig):
    """
    GenericExtensionsConfig abstracts whether we pulled the goal state from Fabric or from FastTrack
    consumers should not worry from where the ExtensionsConfig came. They should also have no knowledge
    of sequence numbers or incarnations, which are specific to FastTrack and Fabric respectively
    """
    def __init__(self, extensions_config, changed, ext_conf_retriever):
        super(GenericExtensionsConfig, self).__init__(extensions_config.xml_text)
        self.changed = changed
        self.is_fabric_change = False
        self._ext_conf_retriever = ext_conf_retriever

        # Preserve ext_handlers being set to null when the SvdSeqNo didn't change
        if extensions_config.ext_handlers is None:
            self.ext_handlers = None

    def commit_processed(self):
        self._ext_conf_retriever.commit_processed()

    def get_description(self):
        return self._ext_conf_retriever.get_description()

    def get_ext_config_file_name(self):
        return self._ext_conf_retriever.get_ext_config_file_name()

    def get_is_on_hold(self):
        return self._ext_conf_retriever.get_is_on_hold()


class ExtensionsConfigRetriever(object):
    def __init__(self, wire_client):
        self.status_upload_blob_url = None
        self.status_upload_blob_type = None
        self._is_on_hold = None
        self._wire_client = wire_client
        self._current_ext_conf = None
        self._last_fabric_incarnation = None
        self._last_svd_seq_no = None
        self._last_fast_track_seq_no = None
        self._saved_artifacts_profile = None
        self._last_mode = None
        self._pending_mode = None
        self._pending_fast_track_seq_no = None
        self._pending_svd_seq_no = None
        self._pending_fabric_incarnation = None
        self._fast_track_changed_detail = None
        self._fabric_changed_detail = None
        self._fast_track_conf_uri = None
        self._artifacts_profile_uri = None
        self._reason = None

    def get_ext_config(self, incarnation, fabric_ext_config_uri):
        # If we don't have a uri, return an empty extensions config
        if fabric_ext_config_uri is None or incarnation is None:
            return GenericExtensionsConfig(ExtensionsConfig(None), False, self)

        if self._last_mode is None:
            return self._get_ext_config_startup(incarnation, fabric_ext_config_uri)
        else:
            return self._get_ext_config_after_startup(incarnation, fabric_ext_config_uri)

    def get_is_on_hold(self):
        is_on_hold = self._is_on_hold
        if is_on_hold is None:
            # If FastTrack is disabled, we won't automatically retrieve the artifacts profile, so do that now
            # We don't want to cache is_on_hold here because we may then miss a change
            artifacts_profile = self._wire_client.get_artifacts_profile(self._artifacts_profile_uri)
            if artifacts_profile is None:
                is_on_hold = False
            else:
                is_on_hold = artifacts_profile.is_on_hold()
        return is_on_hold

    def _get_ext_config_startup(self, incarnation, fabric_ext_config_uri):
        # For startup, we choose the goal state based on:
        # 1) If we don't have a FastTrack goal state, then we choose Fabric
        # 2) Otherwise, we choose the more recent goal state

        # Get the Fabric extensions config, which has many properties that we need
        fabric_ext_conf = self._retrieve_fabric_ext_conf(fabric_ext_config_uri)
        self._pending_svd_seq_no = fabric_ext_conf.svd_seqNo
        self._fabric_changed_detail = FabricChangeDetail.RETRIEVED

        # Get the VmArtifactsProfile and whether fast track changed, if enabled
        artifacts_profile = None
        if self._artifacts_profile_uri is None:
            self._fast_track_changed_detail = FastTrackChangeDetail.NO_PROFILE_URI
        else:
            artifacts_profile = self._get_artifacts_profile()
        self._pending_fabric_incarnation = incarnation

        if artifacts_profile is None:
            self._set_reason(ExtensionsConfigReasons.STARTUP_NO_FAST_TRACK)
            self._pending_mode = GOAL_STATE_SOURCE_FABRIC
        else:
            self._pending_fast_track_seq_no = artifacts_profile.get_sequence_number()
            self._fast_track_changed_detail = FastTrackChangeDetail.RETRIEVED
            if int(fabric_ext_conf.created_on_ticks) >= int(artifacts_profile.get_created_on_ticks()):
                self._set_reason(ExtensionsConfigReasons.STARTUP_FABRIC_NEWER)
                self._pending_mode = GOAL_STATE_SOURCE_FABRIC
            else:
                self._set_reason(ExtensionsConfigReasons.STARTUP_FAST_TRACK_NEWER)
                self._pending_mode = GOAL_STATE_SOURCE_FASTTRACK

        logger.info("Using {0} for the first call to extensions. Reason={1}", self._pending_mode, self._reason)

        extensions_config = self._create_ext_config(fabric_ext_conf, artifacts_profile)
        self._current_ext_conf = GenericExtensionsConfig(extensions_config, True, self)
        self._check_set_is_fabric_change()

        return self._current_ext_conf

    def _get_ext_config_after_startup(self, incarnation, fabric_ext_config_uri):
        # For runs after startup, the following is our logic for determining the extensions config
        # 1) If the Fabric incarnation changed, we retrieve the Fabric extensions config. If the SvdSeqNo
        #    also changed, then we use the Fabric extensions config
        #    Note that if FastTrack also changed, then we cache its extensions config until the next run
        # 2) If the FastTrack sequence number changed, then we use FastTrack
        # 3) Otherwise, we return null, since nothing changed

        # Get individually whether FastTrack and Fabric have changed
        fabric_changed, fabric_ext_conf = self._determine_fabric_changed(incarnation, fabric_ext_config_uri)
        fast_track_changed, artifacts_profile = self._determine_fast_track_changed()

        # Figure out what to process
        if fabric_changed:
            self._pending_mode = GOAL_STATE_SOURCE_FABRIC
            self._pending_fabric_incarnation = incarnation
            self._pending_svd_seq_no = fabric_ext_conf.svd_seqNo
            self._set_reason(ExtensionsConfigReasons.FABRIC_CHANGED)
            if fast_track_changed:
                # If FastTrack changed too, then save the artifacts profile because the next time
                # we retrieve it, we'll receive a 304 because the etag didn't change
                logger.info("Both FastTrack and fabric changed. Saving the FastTrack profile for the next run")
                self._saved_artifacts_profile = artifacts_profile
        elif fast_track_changed:
            self._pending_mode = GOAL_STATE_SOURCE_FASTTRACK
            self._pending_fast_track_seq_no = artifacts_profile.get_sequence_number()
            self._set_reason(ExtensionsConfigReasons.FAST_TRACK_CHANGED)
        else:
            # Nothing changed, so use the last extensions config but mark it as unchanged
            self._current_ext_conf.is_fabric_change = False
            self._current_ext_conf.changed = False
            self._set_reason(ExtensionsConfigReasons.NOTHING_CHANGED)
            return self._current_ext_conf

        if self._pending_mode != self._last_mode:
            logger.info("Processing from previous mode {0}. New mode is {1}. Reason={2}",
                        self._last_mode, self._pending_mode, self._reason)
        else:
            logger.info("Processing extensions config: {0}. Reason={1}", self._pending_mode, self._reason)

        extensions_config = self._create_ext_config(fabric_ext_conf, artifacts_profile)
        self._current_ext_conf = GenericExtensionsConfig(extensions_config, True, self)
        self._check_set_is_fabric_change()

        return self._current_ext_conf

    def _create_ext_config(self, fabric_ext_conf, artifacts_profile):
        if self._pending_mode == GOAL_STATE_SOURCE_FABRIC:
            return fabric_ext_conf
        else:
            return artifacts_profile.transform_to_extensions_config()

    def _check_set_is_fabric_change(self):
        if self._pending_mode == GOAL_STATE_SOURCE_FABRIC:
            # We only need to retrieve certs if the Fabric incarnation changes. FastTrack won't change them
            self._current_ext_conf.is_fabric_change = True
        else:
            self._current_ext_conf.is_fabric_change = False

    def _determine_fabric_changed(self, incarnation, fabric_ext_config_uri):
        fabric_changed = False
        fabric_ext_conf = None

        if str(self._last_fabric_incarnation) != str(incarnation):
            fabric_ext_conf = self._retrieve_fabric_ext_conf(fabric_ext_config_uri)

            # If our last GoalState was FastTrack, don't process the Fabric extensions if the SVD number
            # didn't change. This may occur if WireServer restarts or for a JIT access
            if fabric_ext_conf.svd_seqNo == self._last_svd_seq_no and self._last_mode == GOAL_STATE_SOURCE_FASTTRACK:
                self._fabric_changed_detail = FabricChangeDetail.SVD_SEQ_NO_NOT_CHANGED
            else:
                self._fabric_changed_detail = FabricChangeDetail.INCARNATION_CHANGED
                fabric_changed = True
        else:
            self._fabric_changed_detail = FabricChangeDetail.NO_CHANGE

        return fabric_changed, fabric_ext_conf

    def _determine_fast_track_changed(self):
        fast_track_changed = False

        artifacts_profile = None
        if self._artifacts_profile_uri is None:
            self._fast_track_changed_detail = FastTrackChangeDetail.NO_PROFILE_URI
        else:
            artifacts_profile = self._get_artifacts_profile()

        if artifacts_profile is not None:
            if self._last_fast_track_seq_no != artifacts_profile.get_sequence_number():
                self._fast_track_changed_detail = FastTrackChangeDetail.SEQ_NO_CHANGED
                fast_track_changed = True
            else:
                self._fast_track_changed_detail = FastTrackChangeDetail.NO_CHANGE
        return fast_track_changed, artifacts_profile

    def _get_artifacts_profile(self):
        artifacts_profile = None

        if conf.get_extensions_fast_track_enabled():
            artifacts_profile = self._wire_client.get_artifacts_profile(self._artifacts_profile_uri)
            if artifacts_profile is None:
                self._fast_track_changed_detail = FastTrackChangeDetail.NO_PROFILE
            else:
                # Read OnHold from the artifacts profile since we have it
                self._is_on_hold = artifacts_profile.is_on_hold()

                if artifacts_profile.get_created_on_ticks() is None:
                    # If we don't have a createdOnTicks property, then we won't support FastTrack
                    logger.periodic_info(logger.EVERY_DAY, _MSG_FAST_TRACK_NOT_SUPPORTED)
                    self._fast_track_changed_detail = FastTrackChangeDetail.DISABLED
                    artifacts_profile = None
                elif not artifacts_profile.has_extensions():
                    # If we don't have any extensions, then treat this as a null profile. No extensions simply means
                    # that the goal state didn't go through FastTrack
                    logger.verbose("No extensions in the artifacts profile. Ignoring for FastTrack")
                    self._fast_track_changed_detail = FastTrackChangeDetail.NO_EXTENSIONS
                    artifacts_profile = None

                if self._saved_artifacts_profile is not None:
                    if artifacts_profile is None:
                        logger.periodic_info(logger.EVERY_DAY, _MSG_PREVIOUSLY_CACHED_PROFILE)
                        artifacts_profile = self._saved_artifacts_profile
                    else:
                        # If we use the cached profile again, we want to see that message
                        logger.reset_periodic_msg(_MSG_PREVIOUSLY_CACHED_PROFILE)
        else:
            self._fast_track_changed_detail = FastTrackChangeDetail.TURNED_OFF_IN_CONFIG

        return artifacts_profile

    def _retrieve_fabric_ext_conf(self, fabric_ext_conf_uri):
        try:
            if fabric_ext_conf_uri is not None:
                fabric_ext_conf_xml = self._wire_client.fetch_config(fabric_ext_conf_uri, self._wire_client.get_header())
                fabric_ext_conf = ExtensionsConfig(fabric_ext_conf_xml)
                logger.verbose("Retrieved the Fabric extension config with sdvSeqNo [{0}] and createdOnTicks [{1}]",
                               fabric_ext_conf.svd_seqNo, fabric_ext_conf.created_on_ticks)

                self._artifacts_profile_uri = fabric_ext_conf.artifacts_profile_blob_url
                self.status_upload_blob_url = fabric_ext_conf.status_upload_blob_url
                self.status_upload_blob_type = fabric_ext_conf.status_upload_blob_type

                return fabric_ext_conf
        except Exception as e:
            logger.warn("Fetching the fabric extension config failed: {0}", ustr(e))
            raise

    def commit_processed(self):
        if self._last_mode is None:
            logger.info("Finish and save data for first mode {0}.", self._pending_mode)
        elif self._pending_mode != self._last_mode:
            logger.info("Finish and save data from previous mode {0}. New mode is {1}", self._last_mode, self._pending_mode)

        if self._saved_artifacts_profile is not None:
            logger.info("Clearing saved FastTrack extensions config since it has been processed")
            self._saved_artifacts_profile = None

        self._last_mode = self._pending_mode
        self._last_fabric_incarnation = self._pending_fabric_incarnation
        self._last_fast_track_seq_no = self._pending_fast_track_seq_no
        self._last_svd_seq_no = self._pending_svd_seq_no

    def _set_reason(self, reason):
        self._reason = "{0} FastTrack={1}, Fabric={2}".format(reason, self._fast_track_changed_detail, self._fabric_changed_detail)

    def get_pending_description(self):
        return "{0} Incarnation={1} SeqNo={2} Reason={3}".format(
            self._pending_mode, self._pending_fabric_incarnation, self._pending_fast_track_seq_no, self._reason)

    def get_description(self):
        return "{0} Incarnation={1} SeqNo={2} Reason={3}".format(
            self._last_mode, self._last_fabric_incarnation, self._last_fast_track_seq_no, self._reason)

    def get_ext_config_file_name(self):
        if self._last_mode == GOAL_STATE_SOURCE_FASTTRACK:
            return _EXT_CONF_FILE_NAME.format(_EXT_CONFIG_FAST_TRACK, self._last_fast_track_seq_no)
        else:
            return _EXT_CONF_FILE_NAME.format(_EXT_CONFIG_FABRIC, self._last_fabric_incarnation)

