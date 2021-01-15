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
from azurelinuxagent.common.cgroup import CpuCgroup
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logger import EVERY_SIX_HOURS
from azurelinuxagent.common.resourceusage import ProcessInfo

DELIM = " | "
DEFAULT_PROCESS_NAME = "NO_PROCESS_FOUND"
DEFAULT_PROCESS_COMMANDLINE = "NO_CMDLINE_FOUND"


class CGroupsTelemetry(object):
    """
    """
    _tracked = []
    _rlock = threading.RLock()

    @staticmethod
    def get_process_info_summary(process_id):
        process_cmdline = DEFAULT_PROCESS_COMMANDLINE
        process_name = DEFAULT_PROCESS_NAME

        # The ProcessName and ProcessCommandLine can generate Exception if the file /proc/<pid>/{comm,cmdline} cease to
        # exist; eg: the process can die, or finish. Which is why we need Default Names, in case we fail to fetch the
        # details from those files.
        try:
            process_cmdline = ProcessInfo.get_proc_cmdline(process_id) if not None else DEFAULT_PROCESS_COMMANDLINE
        except Exception as e: # pylint: disable=C0103
            logger.periodic_info(EVERY_SIX_HOURS, "[PERIODIC] {0}", ustr(e))

        try:
            process_name = ProcessInfo.get_proc_name(process_id) if not None else DEFAULT_PROCESS_NAME
        except Exception as e: # pylint: disable=C0103
            logger.periodic_info(EVERY_SIX_HOURS, "[PERIODIC] {0}", ustr(e))

        return process_id + DELIM + process_name + DELIM + process_cmdline

    @staticmethod
    def track_cgroup(cgroup):
        """
        Adds the given item to the dictionary of tracked cgroups
        """
        if isinstance(cgroup, CpuCgroup):
            # set the current cpu usage
            cgroup.initialize_cpu_usage()

        with CGroupsTelemetry._rlock:
            if not CGroupsTelemetry.is_tracked(cgroup.path):
                CGroupsTelemetry._tracked.append(cgroup)
                logger.info("Started tracking cgroup: {0}, path: {1}".format(cgroup.name, cgroup.path))

    @staticmethod
    def is_tracked(path):
        """
        Returns true if the given item is in the list of tracked items
        O(n) operation. But limited to few cgroup objects we have.
        """
        with CGroupsTelemetry._rlock:
            for cgroup in CGroupsTelemetry._tracked:
                if path == cgroup.path:
                    return True

        return False

    @staticmethod
    def stop_tracking(cgroup):
        """
        Stop tracking the cgroups for the given name
        """
        with CGroupsTelemetry._rlock:
            CGroupsTelemetry._tracked.remove(cgroup)
            logger.info("Stopped tracking cgroup: {0}, path: {1}".format(cgroup.name, cgroup.path))

    @staticmethod
    def poll_all_tracked():
        metrics = []

        with CGroupsTelemetry._rlock:
            for cgroup in CGroupsTelemetry._tracked[:]:
                try:
                    metrics.extend(cgroup.get_tracked_metrics())
                except Exception as e: # pylint: disable=C0103
                    # There can be scenarios when the CGroup has been deleted by the time we are fetching the values
                    # from it. This would raise IOError with file entry not found (ERRNO: 2). We do not want to log
                    # every occurrences of such case as it would be very verbose. We do want to log all the other
                    # exceptions which could occur, which is why we do a periodic log for all the other errors.
                    if not isinstance(e, (IOError, OSError)) or e.errno != errno.ENOENT: # pylint: disable=E1101
                        logger.periodic_warn(logger.EVERY_HOUR, '[PERIODIC] Could not collect metrics for cgroup '
                                                                '{0}. Error : {1}'.format(cgroup.name, ustr(e)))
                if not cgroup.is_active():
                    CGroupsTelemetry.stop_tracking(cgroup)

        return metrics

    @staticmethod
    def prune_all_tracked():
        with CGroupsTelemetry._rlock:
            for cgroup in CGroupsTelemetry._tracked[:]:
                if not cgroup.is_active():
                    CGroupsTelemetry.stop_tracking(cgroup)

    @staticmethod
    def reset():
        with CGroupsTelemetry._rlock:
            CGroupsTelemetry._tracked *= 0  # emptying the list
