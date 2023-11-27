# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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

import glob
import os
import shutil

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.exception import AgentUpdateError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateSource
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_NAME, AGENT_DIR_PATTERN
from azurelinuxagent.ga.guestagent import GuestAgent


class VMEnabledRSMUpdates(TypeError):
    """
    Thrown when agent needs to switch to RSM update mode if vm turn on RSM updates
    """


class VMDisabledRSMUpdates(TypeError):
    """
    Thrown when agent needs to switch to self update mode if vm turn off RSM updates
    """


class GAVersionUpdater(object):

    def __init__(self, gs_id):
        self._gs_id = gs_id
        self._version = FlexibleVersion("0.0.0.0")  # Initialize to zero and retrieve from goal state later stage
        self._agent_manifest = None  # Initialize to None and fetch from goal state at different stage for different updater

    def is_update_allowed_this_time(self):
        """
        This function checks if we allowed to update the agent.
        return false when we don't allow updates.
        """
        raise NotImplementedError

    def check_and_switch_updater_if_changed(self, agent_family, gs_id):
        """
        checks and raise the updater exception if we need to switch to self-update from rsm update or vice versa
        @param agent_family: goal state agent family
        @param gs_id: incarnation of the goal state
        @return: VMDisabledRSMUpdates: raise when agent need to stop rsm updates and switch to self-update
                 VMEnabledRSMUpdates: raise when agent need to switch to rsm update
        """
        raise NotImplementedError

    def retrieve_agent_version(self, agent_family, goal_state):
        """
        This function fetches the agent version from the goal state for the given family.
        @param agent_family: goal state agent family
        @param goal_state: goal state
        """
        raise NotImplementedError

    def is_retrieved_version_allowed_to_update(self, goal_state):
        """
        Checks all base condition if new version allow to update.
        @param goal_state: goal state
        @return: True if allowed to update else False
        """
        raise NotImplementedError

    def log_new_agent_update_message(self):
        """
        This function logs the update message after we check agent allowed to update.
        """
        raise NotImplementedError

    def purge_extra_agents_from_disk(self):
        """
        Method remove the extra agents from disk.
        """
        raise NotImplementedError

    def proceed_with_update(self):
        """
        performs upgrade/downgrade
        @return: AgentUpgradeExitException
        """
        raise NotImplementedError

    @property
    def version(self):
        """
        Return version
        """
        return self._version

    def download_and_get_new_agent(self, protocol, agent_family, goal_state):
        """
        Function downloads the new agent and returns the downloaded version.
        @param protocol: protocol object
        @param agent_family: agent family
        @param goal_state: goal state
        @return: GuestAgent: downloaded agent
        """
        if self._agent_manifest is None:  # Fetch agent manifest if it's not already done
            self._agent_manifest = goal_state.fetch_agent_manifest(agent_family.name, agent_family.uris)
        package_to_download = self._get_agent_package_to_download(self._agent_manifest, self._version)
        is_fast_track_goal_state = goal_state.extensions_goal_state.source == GoalStateSource.FastTrack
        agent = GuestAgent.from_agent_package(package_to_download, protocol, is_fast_track_goal_state)
        return agent

    def _get_agent_package_to_download(self, agent_manifest, version):
        """
        Returns the package of the given Version found in the manifest. If not found, returns exception
        """
        for pkg in agent_manifest.pkg_list.versions:
            if FlexibleVersion(pkg.version) == version:
                # Found a matching package, only download that one
                return pkg

        raise AgentUpdateError("No matching package found in the agent manifest for version: {0} in goal state incarnation: {1}, "
                        "skipping agent update".format(str(version), self._gs_id))

    @staticmethod
    def _purge_unknown_agents_from_disk(known_agents):
        """
        Remove from disk all directories and .zip files of unknown agents
        """
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))

        for agent_path in glob.iglob(path):
            try:
                name = fileutil.trim_ext(agent_path, "zip")
                m = AGENT_DIR_PATTERN.match(name)
                if m is not None and FlexibleVersion(m.group(1)) not in known_agents:
                    if os.path.isfile(agent_path):
                        logger.info(u"Purging outdated Agent file {0}", agent_path)
                        os.remove(agent_path)
                    else:
                        logger.info(u"Purging outdated Agent directory {0}", agent_path)
                        shutil.rmtree(agent_path)
            except Exception as e:
                logger.warn(u"Purging {0} raised exception: {1}", agent_path, ustr(e))
