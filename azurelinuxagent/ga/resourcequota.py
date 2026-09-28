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
    """
    def __init__(self, name, property_name):
        self.name = name
        self.property = property_name
    def format(self, quota):
        """
        function that formats the quota value setting
        """
        raise NotImplementedError()

    def can_enforce(self):
        """
        function that checks if the resource quota can be enforced
        """
        raise NotImplementedError()

    def get_current_quota(self, unit_name):
        """
        function that retrieves the current quota setting
        """
        raise NotImplementedError()


class CpuQuota(ResourceQuota):
    def __init__(self, cgroups_api):
        super(CpuQuota, self).__init__(ResourceName.CPU,"CPUQuota")
        self._cgroups_api = cgroups_api

    def format(self, quota):
        return "{0}%".format(quota)

    def can_enforce(self):
        return self._cgroups_api.can_enforce_cpu()

    def get_current_quota(self, unit_name):
        return CGroupUtil.get_current_cpu_quota(unit_name)


class MemoryQuota(ResourceQuota):
    def __init__(self, cgroups_api):
        super(MemoryQuota, self).__init__(ResourceName.MEMORY,"MemoryHigh")
        self._cgroups_api = cgroups_api

    def format(self, quota):
        return "{0}".format(quota)

    def can_enforce(self):
        return self._cgroups_api.can_enforce_memory()

    def get_current_quota(self, unit_name):
        return CGroupUtil.get_current_memory_quota(unit_name)

