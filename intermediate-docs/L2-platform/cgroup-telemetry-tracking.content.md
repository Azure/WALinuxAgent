# Compose Content for: L2-platform/cgroup-telemetry-tracking.md

Total files: 1

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry._tracked`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry._rlock`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry._get_tracking_id`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry._get_tracking_id.cgroup_controller`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry.track_cgroup_controller`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry.track_cgroup_controller.cgroup_controller`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry.is_tracked`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry.is_tracked.path`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry.stop_tracking`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry.stop_tracking.cgroup`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry.poll_all_tracked`
- `%REPO%/azurelinuxagent/common/logger.py.periodic_warn`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry.reset`

### Source excerpt

````
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
import errno
import threading

from azurelinuxagent.common import logger
from azurelinuxagent.ga.cpucontroller import _CpuController
from azurelinuxagent.common.future import ustr


class CGroupsTelemetry(object):
    """
    """
    _tracked = {}
    _rlock = threading.RLock()

    @staticmethod
    def _get_tracking_id(cgroup_controller):
        controller_type = cgroup_controller.get_controller_type()
        # Since the path is same for all controllers in v2, we need to differentiate to track them separately
        tracking_id = "{0}:{1}".format(controller_type, cgroup_controller.path)
        return tracking_id

    @staticmethod
    def track_cgroup_controller(cgroup_controller):
        """
        Adds the given item to the dictionary of tracked cgroup controllers
        """
        if isinstance(cgroup_controller, _CpuController):
            # set the current cpu usage
            cgroup_controller.initialize_cpu_usage()

        with CGroupsTelemetry._rlock:
            tracking_id = CGroupsTelemetry._get_tracking_id(cgroup_controller)
            if not CGroupsTelemetry.is_tracked(tracking_id):
                CGroupsTelemetry._tracked[tracking_id] = cgroup_controller
                logger.info("Started tracking {0} cgroup {1}", cgroup_controller.get_controller_type(), cgroup_controller)

    @staticmethod
    def is_tracked(path):
        """
        Returns true if the given item is in the list of tracked items
        O(1) operation.
        """
        with CGroupsTelemetry._rlock:
            if path in CGroupsTelemetry._track
````

---
