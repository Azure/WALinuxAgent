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

class GoalStateRetriever(object):
    def __init__(self, protocol):
        self.protocol = protocol
        self.last_incarnation = None
        self.last_seqNo = None
        self.last_fast_track_extensionsConfig = None
        self.last_mode = None
        self.pending_mode = None
        self.pending_seqNo = None
        self.pending_incarnation = None

    def get_ext_config(self):
        # Get the Fabric goal state and whether it changed
        goal_state = self.protocol.get_goal_state()
        fabric_changed = self.get_fabric_changed(goal_state)

        # Get the VmArtifactsProfile and whether fast track changed, if enabled
        artifacts_profile = None
        fast_track_changed = False
        if conf.get_extensions_fast_track_enabled():
            artifacts_profile = self.protocol.get_artifacts_profile()
            fast_track_changed = self.get_fast_track_changed(artifacts_profile)

        self.pending_mode = self.decide_what_to_process(fabric_changed, fast_track_changed)
        if self.pending_mode  != self.last_mode:
            logger.info("Processing from previous mode {0}. New mode is {1}", self.last_mode, self.pending_mode)

        extensions_config = None
        changed = False
        if self.pending_mode  == GOAL_STATE_SOURCE_FABRIC:
            extensions_config = goal_state.ext_conf
            changed = fabric_changed
        else:
            if artifacts_profile is None:
                # If the VmArtifactsProfile didn't change, we'll receive a 304 response
                # we therefore need to cache the last copy for subsequent iterations
                extensions_config = self.last_fast_track_extensionsConfig
            else:
                extensions_config = artifacts_profile.transform_to_extensions_config()
                changed = fast_track_changed

            self.last_fast_track_extensionsConfig = extensions_config

        if changed:
            if self.pending_mode  == GOAL_STATE_SOURCE_FABRIC:
                msg = u"Handle extensions updates for incarnation {0}".format(goal_state.incarnation)
                logger.verbose(msg)
            else:
                msg = u"Handle extensions updates for seqNo {0}".format(artifacts_profile.get_sequence_number())
                logger.verbose(msg)

        return GenericExtensionsConfig(extensions_config, changed)

    def commit_processed(self):
        if self.pending_mode  != self.last_mode:
            logger.info("Committing from previous mode {0}. New mode is {1}", self.last_mode, self.pending_mode)
            self.last_mode = self.pending_mode
        if self.pending_mode == GOAL_STATE_SOURCE_FABRIC:
            self.last_incarnation = self.pending_incarnation
            self.set_fabric(self.last_incarnation)
        else:
            self.last_seqNo = self.pending_seqNo
            self.set_fast_track(self.last_seqNo)

    def decide_what_to_process(self, fabric_changed, fast_track_changed):
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
        if self.get_mode() == GOAL_STATE_SOURCE_FASTTRACK:
            return GOAL_STATE_SOURCE_FASTTRACK
        return GOAL_STATE_SOURCE_FABRIC

    def get_fast_track_changed(self, artifacts_profile):
        if artifacts_profile is None:
            return False
        sequence_number = self.last_seqNo
        if sequence_number is None:
            sequence_number= self.get_sequence_number()
        if sequence_number is not None and sequence_number < artifacts_profile.get_sequence_number():
            self.pending_seqNo = artifacts_profile.get_sequence_number()
            return True
        return False

    def get_fabric_changed(self, goal_state):
        if goal_state is None:
            return False
        incarnation = self.last_incarnation
        if incarnation is None:
            incarnation = self.get_incarnation()
        if incarnation is not None and int(incarnation) < int(goal_state.incarnation):
            self.pending_incarnation = int(goal_state.incarnation)
            return True;
        return False

    def set_fast_track(self, vm_artifacts_seq_no=None):
        path = os.path.join(conf.get_lib_dir(), GOAL_STATE_SOURCE_FILE_NAME)
        self.save_cache(path, GOAL_STATE_SOURCE_FASTTRACK)
        if vm_artifacts_seq_no is not None:
            sequence_number_file_path = os.path.join(conf.get_lib_dir(), SEQUENCE_NUMBER_FILE_NAME)
            self.save_cache(sequence_number_file_path, ustr(vm_artifacts_seq_no))

    def set_fabric(self, incarnation=None):
        path = os.path.join(conf.get_lib_dir(), GOAL_STATE_SOURCE_FILE_NAME)
        self.save_cache(path, GOAL_STATE_SOURCE_FABRIC)
        if incarnation is not None:
            incarnation_file_path = os.path.join(conf.get_lib_dir(), INCARNATION_FILE_NAME)
            self.save_cache(incarnation_file_path, ustr(incarnation))

    def save_cache(self, local_file, data):
        try:
            fileutil.write_file(local_file, data)
        except IOError as e:
            fileutil.clean_ioerror(e, paths=[local_file])
            raise ProtocolError("Failed to write cache: {0}".format(e))

    def get_sequence_number(self):
        path = os.path.join(conf.get_lib_dir(), SEQUENCE_NUMBER_FILE_NAME)
        if os.path.exists(path):
            sequence_number = fileutil.read_file(path)
            if sequence_number is not None:
                return int(sequence_number)
        return -1

    def get_incarnation(self):
        path = os.path.join(conf.get_lib_dir(), INCARNATION_FILE_NAME)
        if os.path.exists(path):
            incarnation = fileutil.read_file(path)
            if incarnation is not None:
                return int(incarnation)
        return -1

    def get_mode(self):
        path = os.path.join(conf.get_lib_dir(), GOAL_STATE_SOURCE_FILE_NAME)
        if os.path.exists(path):
            goal_state_source = fileutil.read_file(path)
            return goal_state_source
        else:
            return GOAL_STATE_SOURCE_FABRIC
