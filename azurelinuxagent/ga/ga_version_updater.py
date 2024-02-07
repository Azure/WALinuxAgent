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
import logging
import os
import shutil

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.exception import AgentUpdateError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateSource
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_NAME, AGENT_DIR_PATTERN, CURRENT_VERSION
from azurelinuxagent.ga.guestagent import GuestAgent, AGENT_MANIFEST_FILE


class GAVersionUpdater(object):

    def __init__(self, gs_id):
        self._gs_id = gs_id
        self._version = FlexibleVersion("0.0.0.0")  # Initialize to zero and retrieve from goal state later stage
        self._agent_manifest = None  # Initialize to None and fetch from goal state at different stage for different updater

    def is_update_allowed_this_time(self, ext_gs_updated):
        """
        This function checks if we allowed to update the agent.
        @param ext_gs_updated: True if extension goal state updated else False
        @return false when we don't allow updates.
        """
        raise NotImplementedError

    def is_rsm_update_enabled(self, agent_family, ext_gs_updated):
        """
        return True if we need to switch to RSM-update from self-update and vice versa.
        @param agent_family: agent family
        @param ext_gs_updated: True if extension goal state updated else False
        @return: False when agent need to stop rsm updates
                 True: when agent need to switch to rsm update
        """
        raise NotImplementedError

    def retrieve_agent_version(self, agent_family, goal_state):
        """
        This function fetches the agent version from the goal state for the given family.
        @param agent_family: agent family
        @param goal_state: goal state
        """
        raise NotImplementedError

    def is_retrieved_version_allowed_to_update(self, agent_family):
        """
        Checks all base condition if new version allow to update.
        @param agent_family: agent family
        @return: True if allowed to update else False
        """
        raise NotImplementedError

    def log_new_agent_update_message(self):
        """
        This function logs the update message after we check agent allowed to update.
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

    def sync_new_gs_id(self, gs_id):
        """
        Update gs_id
        @param gs_id: goal state id
        """
        self._gs_id = gs_id

    @staticmethod
    def download_new_agent_pkg(package_to_download, protocol, is_fast_track_goal_state):
        """
        Function downloads the new agent.
        @param package_to_download: package to download
        @param protocol: protocol object
        @param is_fast_track_goal_state: True if goal state is fast track else False
        """
        agent_name = "{0}-{1}".format(AGENT_NAME, package_to_download.version)
        agent_dir = os.path.join(conf.get_lib_dir(), agent_name)
        agent_pkg_path = ".".join((os.path.join(conf.get_lib_dir(), agent_name), "zip"))
        agent_handler_manifest_file = os.path.join(agent_dir, AGENT_MANIFEST_FILE)
        if not os.path.exists(agent_dir) or not os.path.isfile(agent_handler_manifest_file):
            protocol.client.download_zip_package("agent package", package_to_download.uris, agent_pkg_path, agent_dir, use_verify_header=is_fast_track_goal_state)
        else:
            logger.info("Agent {0} was previously downloaded - skipping download", agent_name)

        if not os.path.isfile(agent_handler_manifest_file):
            try:
                # Clean up the agent directory if the manifest file is missing
                logging.info("Agent handler manifest file is missing, cleaning up the agent directory: {0}".format(agent_dir))
                if os.path.isdir(agent_dir):
                    shutil.rmtree(agent_dir, ignore_errors=True)
            except Exception as err:
                logger.warn("Unable to delete Agent directory: {0}".format(err))
            raise AgentUpdateError("Downloaded agent package: {0} is missing agent handler manifest file: {1}".format(agent_name, agent_handler_manifest_file))

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
        self.download_new_agent_pkg(package_to_download, protocol, is_fast_track_goal_state)
        agent = GuestAgent.from_agent_package(package_to_download)
        return agent

    def purge_extra_agents_from_disk(self):
        """
        Remove the agents from disk except current version and new agent version
        """
        known_agents = [CURRENT_VERSION, self._version]
        self._purge_unknown_agents_from_disk(known_agents)

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
