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
GOAL_STATE_SOURCE_FAST_TRACK = "FastTrack"
GOAL_STATE_UNCHANGED = "Unchanged"

_MSG_PREVIOUSLY_CACHED_PROFILE = "[PERIODIC] Using previously cached artifacts profile"
_MSG_FAST_TRACK_NOT_SUPPORTED = "[PERIODIC] FastTrack is not supported because the createdOnTicks property is missing"

_EXT_CONF_FILE_NAME = "ExtensionsConfig_{0}.{1}.xml"
_EXT_CONFIG_FAST_TRACK = "ft"
_EXT_CONFIG_FABRIC = "fa"

_SCHEMA_VERSION_FAST_TRACK_CREATED_ON_TICKS = 1


class FastTrackChangeDetail:
    NO_CHANGE = "NoChange"
    NO_EXTENSIONS = "NoExtensions"
    NO_PROFILE = "NoProfile"
    NO_PROFILE_URI = "NoProfileUri"
    SEQ_NO_CHANGED = "SeqNoChanged"
    DISABLED = "Disabled"
    TURNED_OFF_IN_CONFIG = "TurnedOffConfig"


class GenericExtensionsConfig(ExtensionsConfig):
    """
    GenericExtensionsConfig abstracts whether we pulled the goal state from Fabric or from FastTrack
    consumers should not worry from where the ExtensionsConfig came. They should also have no knowledge
    of sequence numbers or incarnations, which are specific to FastTrack and Fabric respectively
    """
    def __init__(self, extensions_config, changed, ext_conf_retriever, description, file_name):
        super(GenericExtensionsConfig, self).__init__(extensions_config.xml_text)
        self.changed = changed
        self.is_fabric_change = False
        self._ext_conf_retriever = ext_conf_retriever
        self._description = description
        self._file_name = file_name

        # Preserve ext_handlers being set to null when the SvdSeqNo didn't change
        if extensions_config.ext_handlers is None:
            self.ext_handlers = None

    def commit_processed(self):
        self._ext_conf_retriever.commit_processed()

    def get_description(self):
        return self._description

    def set_description(self, description):
        self._description = description

    def get_ext_config_file_name(self):
        return self._file_name

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
        self._last_fast_track_seq_no = None
        self._last_created_on_ticks = 0
        self._last_mode = None
        self._is_startup = True
        self._pending_fast_track_seq_no = None
        self._pending_fabric_incarnation = None
        self._pending_created_on_ticks = 0
        self._fast_track_changed_detail = None
        self._fast_track_conf_uri = None
        self._artifacts_profile_uri = None

    def get_ext_config(self, incarnation, fabric_ext_conf_uri):
        # If we don't have a uri, return an empty extensions config
        if fabric_ext_conf_uri is None or incarnation is None:
            return GenericExtensionsConfig(ExtensionsConfig(None), False, self, None, None)

        # Logic for choosing the goal state is the following
        # Note that if createdOnTicks is 0 for FastTrack, we'll always use Fabric
        # 1) If we cannot retrieve either goal state successfully we'll just skip this iteration since we can't
        # guarantee we'll choose correctly
        # 2) If we don't have a FastTrack goal state, and this is startup, then we'll use fabric
        # 3) If the incarnation changed and Fabric's createdOnTicks is greater than our cached value then use Fabric.
        # Note that the cached incarnation is null at startup.
        # 4) If the incarnation changed and Fabric's createdOnTicks is equal to our cached value, then we may have a JIT
        # request. If either createdOnTicks is greater than 0, then return no extension config, but mark the goal state
        # as changed. If both are 0, then we may have an RDFE goal state so we can just run the extensions as FastTrack
        # is not available.
        # 5) If either createdOnTicks value is greater than our cached value, then were either in startup and have at
        # least one extension config with a positive createdOnTicks or we have a new deployment.We need to check the
        # artifactsProfileSchemaVersion to know if CRP has the fix to set createdOnTicks in the VMArtifactsProfile to 0
        # when using a Fabric goal state.If it does have the fix, then we simply need to take the higher value.

        fabric_ext_conf = self._retrieve_fabric_ext_conf_if_changed(incarnation, fabric_ext_conf_uri)
        artifacts_profile = self._get_artifacts_profile()

        if self._is_startup and artifacts_profile is None:
            # Case 2 above
            self._trace_goal_state_selection_decision(
                "No FastTrack extension config exists. Processing the Fabric extension config",
                incarnation, fabric_ext_conf, artifacts_profile)
            return self._create_fabric_ext_conf(incarnation, fabric_ext_conf, artifacts_profile)

        fabric_created_on_ticks = 0 if fabric_ext_conf is None else int(fabric_ext_conf.created_on_ticks)
        fast_track_created_on_ticks = 0 if artifacts_profile is None else artifacts_profile.get_created_on_ticks()

        if not self._is_startup and incarnation != self._last_fabric_incarnation:
            if fabric_created_on_ticks <= self._last_created_on_ticks and self._last_created_on_ticks > 0:
                # Scenario 4 above
                self._trace_goal_state_selection_decision(
                    "Fabric incarnation changed but createdOnTicks did not. Not processing extensions.",
                    incarnation, fabric_ext_conf, artifacts_profile)
                fabric_ext_conf.ext_handlers = None
                return self._create_fabric_ext_conf(incarnation, fabric_ext_conf, artifacts_profile)
            else:
                # Scenario 3 above
                self._trace_goal_state_selection_decision(
                    "Fabric incarnation changed. Processing the Fabric extension config.",
                    incarnation, fabric_ext_conf, artifacts_profile)
                return self._create_fabric_ext_conf(incarnation, fabric_ext_conf, artifacts_profile)

        if fabric_created_on_ticks > self._last_created_on_ticks or \
                fast_track_created_on_ticks > self._last_created_on_ticks:
            return self._get_most_recent_ext_conf(incarnation, fabric_ext_conf, artifacts_profile)

        # There are no extension config changes to process.Skip this iteration.
        # Nothing changed, so use the last extensions config but mark it as unchanged
        self._set_ext_conf_not_changed()

        return self._current_ext_conf

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

    def _set_ext_conf_not_changed(self):
        self._current_ext_conf.changed = False
        if self._current_ext_conf.is_fabric_change:
            description = "{0} {1}, FastTrack={2}".format(
                GOAL_STATE_SOURCE_FABRIC, GOAL_STATE_UNCHANGED, self._fast_track_changed_detail)
            self._current_ext_conf.set_description(description)
        else:
            description = "{0} {1}, FastTrack={2}".format(
                GOAL_STATE_SOURCE_FAST_TRACK, GOAL_STATE_UNCHANGED, self._fast_track_changed_detail)
            self._current_ext_conf.set_description(description)

    def _get_most_recent_ext_conf(self, incarnation, fabric_ext_conf, artifacts_profile):
        fabric_created_on_ticks = 0 if fabric_ext_conf is None else int(fabric_ext_conf.created_on_ticks)
        fast_track_created_on_ticks = 0 if artifacts_profile is None else int(artifacts_profile.get_created_on_ticks())

        if fast_track_created_on_ticks > fabric_created_on_ticks:
            self._trace_goal_state_selection_decision(
                "Processing the FastTrack extension config because it has a higher createdOnTicks.",
                incarnation, fabric_ext_conf, artifacts_profile)
            return self._create_fast_track_ext_conf(incarnation, artifacts_profile)
        else:
            self._trace_goal_state_selection_decision(
                "Processing the Fabric extension config because it has a higher createdOnTicks.",
                incarnation, fabric_ext_conf, artifacts_profile)
            return self._create_fabric_ext_conf(incarnation, fabric_ext_conf, artifacts_profile)

    def _create_fast_track_ext_conf(self, incarnation, artifacts_profile):
        self._pending_created_on_ticks = int(artifacts_profile.get_created_on_ticks())
        self._pending_fabric_incarnation = incarnation
        self._pending_fast_track_seq_no = artifacts_profile.get_sequence_number()
        self._last_mode = GOAL_STATE_SOURCE_FAST_TRACK

        description = "{0} SeqNo={1}, FastTrack={2}".format(GOAL_STATE_SOURCE_FAST_TRACK,
                                                            artifacts_profile.get_sequence_number(),
                                                            self._fast_track_changed_detail)
        file_name = _EXT_CONF_FILE_NAME.format(_EXT_CONFIG_FAST_TRACK, self._last_fast_track_seq_no)
        ext_conf = artifacts_profile.transform_to_extensions_config()
        self._current_ext_conf = GenericExtensionsConfig(ext_conf, True, self, description, file_name)
        return self._current_ext_conf

    def _create_fabric_ext_conf(self, incarnation, fabric_ext_conf, artifacts_profile):
        self._pending_created_on_ticks = int(fabric_ext_conf.created_on_ticks)
        self._pending_fabric_incarnation = incarnation
        self._last_mode = GOAL_STATE_SOURCE_FABRIC
        if artifacts_profile is not None:
            self._pending_fast_track_seq_no = artifacts_profile.get_sequence_number()

        description = "{0} Incarnation={1}, FastTrack={2}".format(GOAL_STATE_SOURCE_FABRIC, incarnation,
                                                                  self._fast_track_changed_detail)
        file_name = _EXT_CONF_FILE_NAME.format(_EXT_CONFIG_FABRIC, incarnation)
        self._current_ext_conf = GenericExtensionsConfig(fabric_ext_conf, True, self, description, file_name)
        self._current_ext_conf.is_fabric_change = True
        return self._current_ext_conf

    def _trace_goal_state_selection_decision(self, decision, incarnation, fabric_ext_conf, artifacts_profile):
        logger.info(decision)
        fabric_has_extensions = False
        if fabric_ext_conf is not None and fabric_ext_conf.ext_handlers is not None and \
                fabric_ext_conf.ext_handlers.extHandlers is not None and \
                len(fabric_ext_conf.ext_handlers.extHandlers) > 0:
            fabric_has_extensions = True

        if artifacts_profile is None:
            logger.info(
                "Fabric incarnation={0}, createdOnTicks={1}, inSvdSeqNo={2}, hasExtensions={3}. Startup={4}. FastTrack "
                "not available. Cached CreatedOnTicks={5}, cached Incarnation={6}.",
                incarnation,
                0 if fabric_ext_conf is None else fabric_ext_conf.created_on_ticks,
                "N/A" if fabric_ext_conf is None else fabric_ext_conf.svd_seqNo,
                fabric_has_extensions,
                self._is_startup,
                self._last_created_on_ticks,
                self._last_fabric_incarnation)
        else:
            logger.info(
                "Fabric incarnation={0}, createdOnTicks={1}, inSvdSeqNo={2}, hasExtensions={3}. FastTrack "
                "ProfileBlobSeqNo={4}, hasExtensions={5}, createdOnTicks={6}, schemaVersion={7}. Startup={8}. "
                "Cached CreatedOnTicks={9}, cached Incarnation={10}.",
                incarnation,
                0 if fabric_ext_conf is None else fabric_ext_conf.created_on_ticks,
                "N/A" if fabric_ext_conf is None else fabric_ext_conf.svd_seqNo,
                fabric_has_extensions,
                artifacts_profile.get_sequence_number(),
                artifacts_profile.has_extensions,
                artifacts_profile.get_created_on_ticks(),
                artifacts_profile.get_schema_version(),
                self._is_startup,
                self._last_created_on_ticks,
                self._last_fabric_incarnation)

    def _get_artifacts_profile(self):
        artifacts_profile = None

        if self._artifacts_profile_uri is None:
            self._fast_track_changed_detail = FastTrackChangeDetail.NO_PROFILE_URI
        elif conf.get_extensions_fast_track_enabled():
            artifacts_profile = self._wire_client.get_artifacts_profile(self._artifacts_profile_uri)
            if artifacts_profile is None:
                self._fast_track_changed_detail = FastTrackChangeDetail.NO_PROFILE
            else:
                # Read OnHold from the artifacts profile since we have it
                self._is_on_hold = artifacts_profile.is_on_hold()

                if artifacts_profile.get_created_on_ticks() == 0:
                    # If we don't have a createdOnTicks property, then we won't support FastTrack
                    logger.periodic_info(logger.EVERY_DAY, _MSG_FAST_TRACK_NOT_SUPPORTED)
                    self._fast_track_changed_detail = FastTrackChangeDetail.DISABLED
                    artifacts_profile = None
                elif artifacts_profile.get_schema_version() < _SCHEMA_VERSION_FAST_TRACK_CREATED_ON_TICKS:
                    # If we don't have a schemaVersion indicating the latest FastTrack, then we won't support FastTrack
                    logger.periodic_info(logger.EVERY_DAY, _MSG_FAST_TRACK_NOT_SUPPORTED)
                    self._fast_track_changed_detail = FastTrackChangeDetail.DISABLED
                    artifacts_profile = None
                elif not artifacts_profile.has_extensions():
                    # If we don't have any extensions, then treat this as a null profile. No extensions simply means
                    # that the goal state didn't go through FastTrack
                    logger.verbose("No extensions in the artifacts profile. Ignoring for FastTrack")
                    self._fast_track_changed_detail = FastTrackChangeDetail.NO_EXTENSIONS
                    artifacts_profile = None
        else:
            self._fast_track_changed_detail = FastTrackChangeDetail.TURNED_OFF_IN_CONFIG

        if artifacts_profile is not None:
            if artifacts_profile.get_sequence_number() != self._last_fast_track_seq_no:
                self._fast_track_changed_detail = FastTrackChangeDetail.SEQ_NO_CHANGED
            else:
                self._fast_track_changed_detail = FastTrackChangeDetail.NO_CHANGE

        return artifacts_profile

    def _retrieve_fabric_ext_conf_if_changed(self, incarnation, fabric_ext_conf_uri):
        if self._last_fabric_incarnation is None:
            return self._retrieve_fabric_ext_conf(fabric_ext_conf_uri)
        if str(self._last_fabric_incarnation) != str(incarnation):
            return self._retrieve_fabric_ext_conf(fabric_ext_conf_uri)
        return None

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
        self._is_startup = False
        self._last_fabric_incarnation = self._pending_fabric_incarnation
        self._last_fast_track_seq_no = self._pending_fast_track_seq_no
        self._last_created_on_ticks = self._pending_created_on_ticks


