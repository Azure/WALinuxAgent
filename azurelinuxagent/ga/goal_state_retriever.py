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
from azurelinuxagent.common.utils import fileutil, restutil
from azurelinuxagent.common.exception import ProtocolError

INCARNATION_FILE_NAME = "Incarnation"
SEQUENCE_NUMBER_FILE_NAME = "ArtifactProfileSequenceNumber"
GOAL_STATE_SOURCE_FILE_NAME = "GoalStateSource"
EXT_CONF_FILE_NAME = "ExtensionsConfig.{0}.xml"
EXT_CONFIG_FAST_TRACK_FILE_NAME = "FastTrackExtensionsConfig.{0}.xml"

GOAL_STATE_SOURCE_FABRIC = "Fabric"
GOAL_STATE_SOURCE_FASTTRACK = "FastTrack"

""" 
GenericExtensionsConfig abstracts whether we pulled the goal state from Fabric or from FastTrack
consumers should not worry from where the ExtensionsConfig came. They should also have no knowledge
of sequence numbers or incarnations, which are specific to FastTrack and Fabric respectfully
"""
class GenericExtensionsConfig(object):
    def __init__(self, extensions_config, changed):
        self.extensions_config = extensions_config
        self.changed = changed

class ExtensionsConfigRetriever(object):
    def __init__(self, protocol):
        self._protocol = protocol
        self._last_incarnation = None
        self._last_seqNo = None
        self._last_fast_track_extensionsConfig = None
        self._last_mode = None
        self._pending_mode = None
        self._pending_seqNo = None
        self._pending_incarnation = None
        self._is_startup = True

    def get_ext_config(self):
        # Get the Fabric goal state and whether it changed
        goal_state = self._protocol.get_goal_state()
        fabric_changed = self._get_fabric_changed(goal_state)

        # Get the VmArtifactsProfile and whether fast track changed, if enabled
        artifacts_profile = None
        fast_track_changed = False
        if conf.get_extensions_fast_track_enabled():
            artifacts_profile = self._protocol.get_artifacts_profile()
            fast_track_changed = self._get_fast_track_changed(artifacts_profile)

        self._pending_mode = self._decide_what_to_process(fabric_changed, fast_track_changed)
        if self._last_mode is None:
            logger.info("Processing first mode {0}", self._pending_mode)
        elif self._pending_mode != self._last_mode:
            logger.info("Processing from previous mode {0}. New mode is {1}", self._last_mode, self._pending_mode)

        extensions_config = None
        changed = False
        if self._pending_mode == GOAL_STATE_SOURCE_FABRIC:
            extensions_config = goal_state.ext_conf
            changed = fabric_changed | self._is_startup
        else:
            if artifacts_profile is None:
                # If the VmArtifactsProfile didn't change, we'll receive a 304 response
                # we therefore need to cache the last copy for subsequent iterations
                extensions_config = self._last_fast_track_extensionsConfig
            else:
                extensions_config = artifacts_profile.transform_to_extensions_config()
                changed = fast_track_changed | self._is_startup
                self._last_fast_track_extensionsConfig = extensions_config

        if changed:
            if self._pending_mode == GOAL_STATE_SOURCE_FABRIC:
                self._pending_incarnation = int(goal_state.incarnation)
                msg = u"Handle extensions updates for incarnation {0}".format(self._pending_incarnation)
                logger.verbose(msg)
            else:
                self._pending_seqNo = artifacts_profile.get_sequence_number()
                msg = u"Handle extensions updates for seqNo {0}".format(self._pending_seqNo)
                logger.verbose(msg)

        self._is_startup = False

        return GenericExtensionsConfig(extensions_config, changed)

    def commit_processed(self):
        if self._last_mode is None:
            logger.info("Committing first mode {0}.", self._pending_mode)
        elif self._pending_mode != self._last_mode:
            logger.info("Committing from previous mode {0}. New mode is {1}", self._last_mode, self._pending_mode)

        self._last_mode = self._pending_mode
        if self._pending_mode == GOAL_STATE_SOURCE_FABRIC:
            self._last_incarnation = self._pending_incarnation
            self._set_fabric(self._last_incarnation)
        else:
            self._last_seqNo = self._pending_seqNo
            self._set_fast_track(self._last_seqNo)

    def _decide_what_to_process(self, fabric_changed, fast_track_changed):
        """
        If just Fabric GS changed, then process only that.
        If just FastTrack GS changed, then process only that.
        If both changed, then process Fabric and then FastTrack.
        If neither changed, then process whichever we used last (to keep with the current behavior)
        """
        if fabric_changed:
            return GOAL_STATE_SOURCE_FABRIC
        if fast_track_changed:
            return GOAL_STATE_SOURCE_FASTTRACK
        if self._get_mode() == GOAL_STATE_SOURCE_FASTTRACK:
            return GOAL_STATE_SOURCE_FASTTRACK
        return GOAL_STATE_SOURCE_FABRIC

    def _get_fast_track_changed(self, artifacts_profile):
        if artifacts_profile is None:
            return False
        if not artifacts_profile.has_extensions():
            return False

        sequence_number = self._last_seqNo
        if sequence_number is None:
            sequence_number = self._get_sequence_number()
        if sequence_number is None or sequence_number < artifacts_profile.get_sequence_number():
            return True
        return False

    def _get_fabric_changed(self, goal_state):
        if goal_state is None:
            return False
        incarnation = self._last_incarnation
        if incarnation is None:
            incarnation = self._get_incarnation()
        if incarnation is None or int(incarnation) < int(goal_state.incarnation):
            return True
        return False

    def _set_fast_track(self, vm_artifacts_seq_no=None):
        path = os.path.join(conf.get_lib_dir(), GOAL_STATE_SOURCE_FILE_NAME)
        self._save_cache(path, GOAL_STATE_SOURCE_FASTTRACK)
        if vm_artifacts_seq_no is not None:
            sequence_number_file_path = os.path.join(conf.get_lib_dir(), SEQUENCE_NUMBER_FILE_NAME)
            self._save_cache(sequence_number_file_path, ustr(vm_artifacts_seq_no))

    def _set_fabric(self, incarnation=None):
        path = os.path.join(conf.get_lib_dir(), GOAL_STATE_SOURCE_FILE_NAME)
        self._save_cache(path, GOAL_STATE_SOURCE_FABRIC)
        if incarnation is not None:
            incarnation_file_path = os.path.join(conf.get_lib_dir(), INCARNATION_FILE_NAME)
            self._save_cache(incarnation_file_path, ustr(incarnation))

    def _save_cache(self, local_file, data):
        try:
            fileutil.write_file(local_file, data)
        except IOError as e:
            fileutil.clean_ioerror(e, paths=[local_file])
            raise ProtocolError("Failed to write cache: {0}".format(e))

    def _get_sequence_number(self):
        path = os.path.join(conf.get_lib_dir(), SEQUENCE_NUMBER_FILE_NAME)
        if os.path.exists(path):
            sequence_number = fileutil.read_file(path)
            if sequence_number is not None:
                return int(sequence_number)
        return -1

    def _get_incarnation(self):
        path = os.path.join(conf.get_lib_dir(), INCARNATION_FILE_NAME)
        if os.path.exists(path):
            incarnation = fileutil.read_file(path)
            if incarnation is not None:
                return int(incarnation)
        return -1

    def _get_mode(self):
        path = os.path.join(conf.get_lib_dir(), GOAL_STATE_SOURCE_FILE_NAME)
        if os.path.exists(path):
            goal_state_source = fileutil.read_file(path)
            return goal_state_source
        else:
            return GOAL_STATE_SOURCE_FABRIC

    def get_description(self):
        if self._last_mode == GOAL_STATE_SOURCE_FASTTRACK:
            return "FastTrack: SeqNo={0}".format(self._last_seqNo)
        else:
            return "Fabric: Incarnation={0}".format(self._last_incarnation)
