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

import time

from azurelinuxagent.common import logger
from azurelinuxagent.common.cgroup import CpuCgroup, MemoryCGroup

class CGroupsTelemetry(object):
    """
    """
    _tracked = {}

    @staticmethod
    def metrics_hierarchies():
        return CGroupsTelemetry._hierarchies

    @staticmethod
    def track_cgroup(cgroup):
        """
        Adds the given item to the list of tracked cgroups
        """
        pass  # TODO

    @staticmethod
    def is_tracked(name):
        """
        Returns true if the given item is in the list of tracked items
        """
        pass  # TODO

    @staticmethod
    def stop_tracking(name):
        """
        Stop tracking the cgroups for the given name
        """
        if CGroupsTelemetry.is_tracked(name):
            del (CGroupsTelemetry._tracked[name])  # TODO - thread-safeness; review implementation

    @staticmethod
    def collect_all_tracked():
        pass  # TODO

    def __init__(self):
        pass  # TODO

