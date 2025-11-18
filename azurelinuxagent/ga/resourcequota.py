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

from azurelinuxagent.ga.cgroupapi import CGroupUtil


class ResourceName(object):
    CPU = "CPU"
    MEMORY = "Memory"
    ALL = "All"


class ResourceQuota(object):
    """
    Represents a resource quota configuration
    1. name: Resource name (CPU, Memory, etc)
    2. property: The cgroup property name associated with the resource quota
    3. format: A function that formats the quota value setting
    4. can_enforce: A function that checks if the resource quota can be enforced
    5. get_current_quota: A function that retrieves the current quota setting
    """
    def __init__(self, name, property_name, format_func, can_enforce_func, get_current_func):
        self.name = name
        self.property = property_name
        self.format = format_func
        self.can_enforce = can_enforce_func
        self.get_current_quota = get_current_func


class CpuQuota(ResourceQuota):
    def __init__(self, cgroups_api):
        super(CpuQuota, self).__init__(
            ResourceName.CPU,
            "CPUQuota",
            "{0}%".format,
            cgroups_api.can_enforce_cpu,
            CGroupUtil.get_current_cpu_quota
        )


class MemoryQuota(ResourceQuota):
    def __init__(self, cgroups_api):
        super(MemoryQuota, self).__init__(
            ResourceName.MEMORY,
            "MemoryHigh",
            "{0}".format,
            cgroups_api.can_enforce_memory,
            CGroupUtil.get_current_memory_quota
        )
