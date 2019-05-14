# Copyright 2018 Microsoft Corporation
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

import os

from azurelinuxagent.common import logger
from azurelinuxagent.common.future import ustr

CGROUPS_FILE_SYSTEM_ROOT = '/sys/fs/cgroup'


class CGroupsApi(object):
    """
    Interface for the cgroups API
    """
    def create_agent_cgroups(self):
        raise NotImplementedError()

    def create_extension_cgroups_root(self):
        raise NotImplementedError()


class FileSystemCgroupsApi(CGroupsApi):
    """
    Cgroups interface using the cgroups file system directly
    """
    def create_agent_cgroups(self):
        try:
            # Creates /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent cgroup
            cg = CGroupConfigurator.for_extension(AGENT_CGROUP_NAME)
            pid = int(os.getpid())
            cg.add(pid)
            logger.info("Daemon process id {0} is tracked in cgroup {1}".format(pid, cg.name))
        except Exception as e:
            logger.info("Cannot create cgroups for the agent. Error: {0}".format(ustr(e)))

        # os.path.join(CGROUPS_FILE_SYSTEM_ROOT, hierarchy, cgroup_name)

    def create_extension_cgroups_root(self):
        try:
            CGroupConfigurator.for_extension("")
        except Exception as e:
            logger.info("Cannot create for directory for extension cgroups. Error: {0}".format(ustr(e)))



class SystemdCgroupsApi(CGroupsApi):
    """
    Cgroups interface via systemd
    """
    def create_agent_cgroups(self):
        pass

    def create_extension_cgroups_root(self):
        pass

