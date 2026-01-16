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
import glob
import os
from datetime import timedelta

from azurelinuxagent.common import logger, conf
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import fileutil

_REPORT_EVERY_HOUR = timedelta(hours=1)

AGENT_NAME_TELEMETRY = "walinuxagent.service"  # Name used for telemetry; it needs to be consistent even if the name of the service changes
AGENT_LOG_COLLECTOR = "azure-walinuxagent-logcollector"


class CounterNotFound(Exception):
    pass


class MetricValue(object):
    """
    Class for defining all the required metric fields to send telemetry.
    """

    def __init__(self, category, counter, instance, value, report_period=None):
        self._category = category
        self._counter = counter
        self._instance = instance
        self._value = value
        self._report_period = timedelta(seconds=conf.get_cgroup_check_period()) if report_period is None else report_period

    @property
    def category(self):
        return self._category

    @property
    def counter(self):
        return self._counter

    @property
    def instance(self):
        return self._instance

    @property
    def value(self):
        return self._value

    @property
    def report_period(self):
        return self._report_period


class MetricsCategory(object):
    MEMORY_CATEGORY = "Memory"
    CPU_CATEGORY = "CPU"


class MetricsCounter(object):
    PROCESSOR_PERCENT_TIME = "% Processor Time"
    THROTTLED_TIME = "Throttled Time (s)"
    TOTAL_MEM_USAGE = "Total Memory Usage (B)"
    ANON_MEM_USAGE = "Anon Memory Usage (B)"
    CACHE_MEM_USAGE = "Cache Memory Usage (B)"
    MAX_MEM_USAGE = "Max Memory Usage (B)"
    SWAP_MEM_USAGE = "Swap Memory Usage (B)"
    MEM_THROTTLED = "Total Memory Throttled Events"
    MEM_PRESSURE = "Memory Pressure (s)"
    AVAILABLE_MEM = "Available Memory (MB)"
    USED_MEM = "Used Memory (MB)"


class _CgroupController(object):
    def __init__(self, name, cgroup_path):
        """
        Initialize _data collection for the controller
        :param: name: Name of the CGroup
        :param: cgroup_path: Path of the controller
        :return:
        """
        self.name = name
        self.path = cgroup_path

    def __str__(self):
        return "{0} [{1}]".format(self.name, self.path)

    def _get_cgroup_file(self, file_name):
        return os.path.join(self.path, file_name)

    def _get_file_contents(self, file_name):
        """
        Retrieve the contents of file.

        :param str file_name: Name of file within that metric controller
        :return: Entire contents of the file
        :rtype: str
        """
        parameter_file = self._get_cgroup_file(file_name)

        return fileutil.read_file(parameter_file)

    def _get_parameters(self, parameter_name, first_line_only=False):
        """
        Retrieve the values of a parameter from a controller.
        Returns a list of values in the file.

        :param first_line_only: return only the first line.
        :param str parameter_name: Name of file within that metric controller
        :return: The first line of the file, without line terminator
        :rtype: [str]
        """
        result = []
        try:
            values = self._get_file_contents(parameter_name).splitlines()
            result = values[0] if first_line_only else values
        except IndexError:
            parameter_filename = self._get_cgroup_file(parameter_name)
            logger.error("File {0} is empty but should not be".format(parameter_filename))
            raise CGroupsException("File {0} is empty but should not be".format(parameter_filename))
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise e
            parameter_filename = self._get_cgroup_file(parameter_name)
            raise CGroupsException("Exception while attempting to read {0}".format(parameter_filename), e)
        return result

    def is_active(self):
        """
        Returns True if any processes belong to the cgroup. In v1, cgroup.procs returns a list of the thread group IDs
        belong to the cgroup. In v2, cgroup.procs returns a list of the process IDs belonging to the cgroup.
        """
        try:
            def _found_cgroup_procs(file):
                try:
                    procs = fileutil.read_file(file).splitlines()
                    if len(procs) > 0:
                        return True
                except (IOError, OSError) as e:
                    if e.errno == errno.ENOENT:
                        # only suppressing file not found exceptions.
                        pass
                    else:
                        raise
                return False

            # In v1, the cgroup.procs file is present in the service/slice cgroup directory.
            if _found_cgroup_procs(os.path.join(self.path, "cgroup.procs")):
                return True

            # In v2, the cgroup.procs file is present in the scope cgroup for extensions
            for cgroup_file in glob.iglob(os.path.join(self.path, "*/cgroup.procs")):
                if _found_cgroup_procs(cgroup_file):
                    return True
        except Exception as e:
            logger.periodic_warn(logger.EVERY_HALF_HOUR,
                                 'Could not get list of procs from "cgroup.procs" file in the cgroup: {0}.'
                                 ' Internal error: {1}'.format(self.path, ustr(e)))
        return False

    def get_tracked_metrics(self):
        """
        Retrieves the current value of the metrics tracked for this controller/cgroup and returns them as an array.
        """
        raise NotImplementedError()

    def get_unit_properties(self):
        """
        Returns a list of the unit properties to collect for the controller.
        """
        raise NotImplementedError()

    def get_controller_type(self):
        """
        Returns the type of the controller. Example: CPU, Memory, etc.
        """
        raise NotImplementedError()
