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
import os
import re

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil

re_user_system_times = re.compile(r'user (\d+)\nsystem (\d+)\n')


class CGroup(object):
    @staticmethod
    def create(cgroup_path, controller, extension_name):
        """
        Factory method to create the correct CGroup.
        """
        if controller == "cpu":
            return CpuCgroup(extension_name, cgroup_path)
        if controller == "memory":
            return MemoryCgroup(extension_name, cgroup_path)
        raise CGroupsException('CGroup controller {0} is not supported'.format(controller))

    def __init__(self, name, cgroup_path, controller_type):
        """
        Initialize _data collection for the Memory controller
        :param: name: Name of the CGroup
        :param: cgroup_path: Path of the controller
        :param: controller_type:
        :return:
        """
        self.name = name
        self.path = cgroup_path
        self.controller = controller_type

    def _get_cgroup_file(self, file_name):
        return os.path.join(self.path, file_name)

    def _get_file_contents(self, file_name):
        """
        Retrieve the contents to file.

        :param str file_name: Name of file within that metric controller
        :return: Entire contents of the file
        :rtype: str
        """

        parameter_file = self._get_cgroup_file(file_name)

        try:
            return fileutil.read_file(parameter_file)
        except Exception:
            raise

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
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:
                raise e
            parameter_filename = self._get_cgroup_file(parameter_name)
            raise CGroupsException("Exception while attempting to read {0}".format(parameter_filename), e)
        return result

    def is_active(self):
        try:
            tasks = self._get_parameters("tasks")
            if tasks:
                return len(tasks) != 0
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                # only suppressing file not found exceptions.
                pass
            else:
                logger.periodic_warn(logger.EVERY_HALF_HOUR,
                                     'Could not get list of tasks from "tasks" file in the cgroup: {0}.'
                                     ' Internal error: {1}'.format(self.path, ustr(e)))
        except CGroupsException as e:
            logger.periodic_warn(logger.EVERY_HALF_HOUR,
                                 'Could not get list of tasks from "tasks" file in the cgroup: {0}.'
                                 ' Internal error: {1}'.format(self.path, ustr(e)))
            return False

        return False


class CpuCgroup(CGroup):
    def __init__(self, name, cgroup_path):
        """
        Initialize _data collection for the Cpu controller. User must call update() before attempting to get
        any useful metrics.

        :return: CpuCgroup
        """
        super(CpuCgroup, self).__init__(name, cgroup_path, "cpu")

        self._osutil = get_osutil()
        self._current_cpu_total = 0
        self._previous_cpu_total = 0
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()
        self._previous_system_cpu = 0

    def __str__(self):
        return "cgroup: Name: {0}, cgroup_path: {1}; Controller: {2}".format(
            self.name, self.path, self.controller
        )

    def _get_current_cpu_total(self):
        """
        Compute the number of USER_HZ of CPU time (user and system) consumed by this cgroup since boot.

        :return: int
        """
        cpu_total = 0
        try:
            cpu_stat = self._get_file_contents('cpuacct.stat')
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:
                raise e
            raise CGroupsException("Exception while attempting to read {0}".format("cpuacct.stat"), e)

        if cpu_stat:
            m = re_user_system_times.match(cpu_stat)
            if m:
                cpu_total = int(m.groups()[0]) + int(m.groups()[1])
        return cpu_total

    def _update_cpu_data(self):
        """
        Update all raw _data required to compute metrics of interest. The intent is to call update() once, then
        call the various get_*() methods which use this _data, which we've collected exactly once.
        """
        self._previous_cpu_total = self._current_cpu_total
        self._previous_system_cpu = self._current_system_cpu
        self._current_cpu_total = self._get_current_cpu_total()
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()

    def _get_cpu_percent(self):
        """
        Compute the percent CPU time used by this cgroup over the elapsed time since the last time this instance was
        update()ed.  If the cgroup fully consumed 2 cores on a 4 core system, return 200.

        :return: CPU usage in percent of a single core
        :rtype: float
        """
        cpu_delta = self._current_cpu_total - self._previous_cpu_total
        system_delta = max(1, self._current_system_cpu - self._previous_system_cpu)

        return round(float(cpu_delta * self._osutil.get_processor_cores() * 100) / float(system_delta), 3)

    def get_cpu_usage(self):
        """
        Collects and return the cpu usage.

        :rtype: float
        """
        self._update_cpu_data()
        return self._get_cpu_percent()


class MemoryCgroup(CGroup):
    def __init__(self, name, cgroup_path):
        """
        Initialize _data collection for the Memory controller

        :return: MemoryCgroup
        """
        super(MemoryCgroup, self).__init__(name, cgroup_path, "memory")

    def __str__(self):
        return "cgroup: Name: {0}, cgroup_path: {1}; Controller: {2}".format(
            self.name, self.path, self.controller
        )

    def get_memory_usage(self):
        """
        Collect memory.usage_in_bytes from the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = None

        try:
            usage = self._get_parameters('memory.usage_in_bytes', first_line_only=True)
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                # only suppressing file not found exceptions.
                pass
            else:
                raise e

        if not usage:
            usage = "0"
        return int(usage)

    def get_max_memory_usage(self):
        """
        Collect memory.usage_in_bytes from the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = None
        try:
            usage = self._get_parameters('memory.max_usage_in_bytes', first_line_only=True)
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                # only suppressing file not found exceptions.
                pass
            else:
                raise e
        if not usage:
            usage = "0"
        return int(usage)
