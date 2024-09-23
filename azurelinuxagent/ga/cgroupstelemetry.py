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
    _track_throttled_time = False
    _rlock = threading.RLock()

    @staticmethod
    def set_track_throttled_time(value):
        CGroupsTelemetry._track_throttled_time = value

    @staticmethod
    def get_track_throttled_time():
        return CGroupsTelemetry._track_throttled_time

    @staticmethod
    def track_cgroup_controller(cgroup_controller):
        """
        Adds the given item to the dictionary of tracked cgroup controllers
        """
        if isinstance(cgroup_controller, _CpuController):
            # set the current cpu usage
            cgroup_controller.initialize_cpu_usage()

        with CGroupsTelemetry._rlock:
            if not CGroupsTelemetry.is_tracked(cgroup_controller.path):
                CGroupsTelemetry._tracked[cgroup_controller.path] = cgroup_controller
                logger.info("Started tracking cgroup {0}", cgroup_controller)

    @staticmethod
    def is_tracked(path):
        """
        Returns true if the given item is in the list of tracked items
        O(1) operation.
        """
        with CGroupsTelemetry._rlock:
            if path in CGroupsTelemetry._tracked:
                return True

        return False

    @staticmethod
    def stop_tracking(cgroup):
        """
        Stop tracking the cgroups for the given path
        """
        with CGroupsTelemetry._rlock:
            if cgroup.path in CGroupsTelemetry._tracked:
                CGroupsTelemetry._tracked.pop(cgroup.path)
                logger.info("Stopped tracking cgroup {0}", cgroup)

    @staticmethod
    def poll_all_tracked():
        metrics = []
        inactive_controllers = []
        with CGroupsTelemetry._rlock:
            for controller in CGroupsTelemetry._tracked.values():
                try:
                    metrics.extend(controller.get_tracked_metrics(track_throttled_time=CGroupsTelemetry._track_throttled_time))
                except Exception as e:
                    # There can be scenarios when the CGroup has been deleted by the time we are fetching the values
                    # from it. This would raise IOError with file entry not found (ERRNO: 2). We do not want to log
                    # every occurrences of such case as it would be very verbose. We do want to log all the other
                    # exceptions which could occur, which is why we do a periodic log for all the other errors.
                    if not isinstance(e, (IOError, OSError)) or e.errno != errno.ENOENT:  # pylint: disable=E1101
                        logger.periodic_warn(logger.EVERY_HOUR, '[PERIODIC] Could not collect metrics for cgroup '
                                                                '{0}. Error : {1}'.format(controller.name, ustr(e)))
                if not controller.is_active():
                    inactive_controllers.append(controller)
            for inactive_controller in inactive_controllers:
                CGroupsTelemetry.stop_tracking(inactive_controller)

        return metrics

    @staticmethod
    def reset():
        with CGroupsTelemetry._rlock:
            CGroupsTelemetry._tracked.clear()  # emptying the dictionary
            CGroupsTelemetry._track_throttled_time = False
