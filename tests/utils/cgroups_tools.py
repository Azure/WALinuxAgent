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
#

import os
from azurelinuxagent.common.cgroupapi import VM_AGENT_CGROUP_NAME
from azurelinuxagent.common.utils import fileutil

class CGroupsTools(object):
    @staticmethod
    def create_legacy_agent_cgroup(cgroups_file_system_root, controller, daemon_pid):
        """
        Previous versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent;
        starting from version 2.2.41 we track the agent service in walinuxagent.service instead of WALinuxAgent/WALinuxAgent.

        This method creates a mock cgroup using the legacy path and adds the given PID to it.
        """
        legacy_cgroup = os.path.join(cgroups_file_system_root, controller, "WALinuxAgent", "WALinuxAgent")
        if not os.path.exists(legacy_cgroup):
            os.makedirs(legacy_cgroup)
        fileutil.append_file(os.path.join(legacy_cgroup, "cgroup.procs"), daemon_pid + "\n")
        return legacy_cgroup

    @staticmethod
    def create_agent_cgroup(cgroups_file_system_root, controller, extension_handler_pid):
        """
        Previous versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent;
        starting from version 2.2.41 we track the agent service in walinuxagent.service instead of WALinuxAgent/WALinuxAgent.

        This method creates a mock cgroup using the newer path and adds the given PID to it.
        """
        new_cgroup = os.path.join(cgroups_file_system_root, controller, VM_AGENT_CGROUP_NAME)
        if not os.path.exists(new_cgroup):
            os.makedirs(new_cgroup)
        fileutil.append_file(os.path.join(new_cgroup, "cgroup.procs"), extension_handler_pid + "\n")
        return new_cgroup

