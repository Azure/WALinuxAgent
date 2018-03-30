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
# Requires Python 2.4+ and Openssl 1.0+
import glob
import os
import getpass
import re

from pwd import getpwnam
from azurelinuxagent.common import logger, conf
from azurelinuxagent.common.utils import fileutil

BASE_CGROUPS = '/sys/fs/cgroup'

HIERARCHIES = ['cpu', 'memory']

MEMORY_DEFAULT = -1

CPU_DEFAULT = 0.25

CGROUP_AGENT = 'azure-agent'

CGROUP_EXTENSION_FORMAT = 'azure-ext-{0}'


class CGroupsTelemetry(object):
    def __init__(self, name):
        self.name = name
        self.cgroup = CGroups(name)
        self.cpu_count = Cgroups.get_num_cores()
        self.current_cpu_total = self.get_current_cpu_total()
        self.previous_cpu_total = 0
        self.current_system_cpu = self.get_current_system_cpu()
        self.previous_system_cpu = 0

    def get_cpu_percent(self):
        """
        Compute the percent CPU time used by this cgroup over the elapsed time since the last call to this method
        (or since this object was instantiated).  If the cgroup fully consumed 2 cores on a 4 core system, return 200.

        :return: float
        """
        self.previous_cpu_total = self.current_cpu_total
        self.previous_system_cpu = self.current_system_cpu
        self.current_cpu_total = self.get_current_cpu_total()
        self.current_system_cpu = self.get_current_system_cpu()

        cpu_delta = self.current_cpu_total - self.previous_cpu_total
        system_delta = max(1, self.current_system_cpu - self.previous_system_cpu)

        return float(cpu_delta * self.cpu_count * 100) / float(system_delta)

    def get_current_cpu_total(self):
        """
        Compute the number of ticks of CPU time (user and system) consumed by this cgroup since boot.

        :return: int
        """
        cpu_total = 0
        cpu_stat = self.cgroup.get_cpu_stat()
        m = re.match('user (\d+)\nsystem (\d+)\n', cpu_stat)
        if m:
            cpu_total = int(m.groups()[0]) + int(m.groups()[1])
        return cpu_total

    def get_current_system_cpu(self):
        """
        Compute the total ticks of CPU time (in all categories and all cores) since boot.

        :return: int
        """
        system_cpu = 0
        proc_stat = self.cgroup.get_proc_stat()
        if proc_stat is not None:
            for line in proc_stat.splitlines():
                if re.match('^cpu .*', line):
                    system_cpu = sum(int(i) for i in line.split(' ')[2:7])
                    break
        return system_cpu


class CGroupsException(Exception):

    def __init__(self, msg):
        self.msg = msg
        if CGroups.enabled():
            pid = os.getpid()
            logger.verbose("[{1}] Disabling cgroup support: {0}"
                           .format(msg, pid))
            CGroups.disable()

    def __str__(self):
        return repr(self.msg)


class CGroups(object):

    # whether cgroup support is enabled
    _enabled = True

    def __init__(self, name):
        self.name = name
        self.user = getpass.getuser()
        self.user_cgroups = {}
        self.cgroups = {}
        self.hierarchies = HIERARCHIES

        if not self.enabled():
            return

        system_hierarchies = os.listdir(BASE_CGROUPS)
        for hierarchy in self.hierarchies:
            if hierarchy not in system_hierarchies:
                raise CGroupsException("Hierarchy {0} is not mounted"
                                       .format(hierarchy))

            user_cgroup = os.path.join(BASE_CGROUPS, hierarchy, self.user)
            self.user_cgroups[hierarchy] = user_cgroup

        self.create_user_cgroups(self.user)
        for hierarchy, user_cgroup in self.user_cgroups.items():
            cgroup = os.path.join(user_cgroup, self.name)
            if not os.path.exists(cgroup):
                os.mkdir(cgroup)
            self.cgroups[hierarchy] = cgroup

    def add(self, pid):
        try:
            if not self.enabled():
                return
            # determine if pid exists
            os.kill(pid, 0)
        except OSError:
            raise CGroupsException('PID {0} does not exist'.format(pid))
        for hierarchy, cgroup in self.cgroups.items():
            tasks_file = self._get_cgroup_file(hierarchy, 'tasks')
            with open(tasks_file, 'r+') as f:
                cgroups_pids = f.read().split('\n')
            if not str(pid) in cgroups_pids:
                with open(tasks_file, 'a+') as f:
                    f.write('%s\n' % pid)

    @staticmethod
    def enabled():
        return CGroups._enabled

    @staticmethod
    def disable():
        CGroups._enabled = False

    @staticmethod
    #
    # Mount the cgroup fs if necessary, and add the daemon
    # pid to the azure-agent cgroup with appropriate limits
    #
    def setup():
        status = ""
        cgroups_enabled = False
        try:
            from azurelinuxagent.common import osutil
            osutil.get_osutil().mount_cgroups()
            cg = CGroups(CGROUP_AGENT)

            # TODO: set limits, simply record telemetry for now
            # cg.set_cpu_limit(50)
            # cg.set_memory_limit(500)

            # add the daemon process
            pid_file = conf.get_agent_pid_file_path()
            if os.path.isfile(pid_file):
                pid = fileutil.read_file(pid_file)
                logger.info("Add daemon process pid {0} to {1} cgroup"
                            .format(pid, cg.name))
                cg.add(int(pid))
                cgroups_enabled = True
            else:
                logger.warn("No pid file at {0}".format(pid_file))
        except CGroupsException as cge:
            status = cge.msg

        from azurelinuxagent.common.event import add_event, WALAEventOperation
        from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
        add_event(
            AGENT_NAME,
            version=CURRENT_VERSION,
            op=WALAEventOperation.InitializeCGroups,
            is_success=cgroups_enabled,
            message=status,
            log_event=False)

    @staticmethod
    def add_to_agent_cgroup():
        try:
            pid = os.getpid()
            cg = CGroups(CGROUP_AGENT)
            cg.add(int(pid))
        except Exception:
            pass

    @staticmethod
    def add_to_extension_cgroup(name):
        try:
            pid = os.getpid()
            logger.info("Create extension group: {0}".format(name))
            cg = CGroups(CGROUP_EXTENSION_FORMAT.format(name))
            cg.add(int(pid))
        except Exception:
            pass

    @staticmethod
    def get_user_info(user):
        try:
            user_system = getpwnam(user)
        except KeyError:
            raise CGroupsException("User {0} does not exist".format(user))
        else:
            uid = user_system.pw_uid
            gid = user_system.pw_gid
        return uid, gid

    def create_user_cgroups(self, user):
        try:
            hierarchies = os.listdir(BASE_CGROUPS)
        except OSError as e:
            if e.errno == 2:
                raise CGroupsException("cgroups not mounted on {0}"
                                       .format(BASE_CGROUPS))
            else:
                raise OSError(e)

        uid, gid = self.get_user_info(user)
        for hierarchy in hierarchies:
            user_cgroup = os.path.join(BASE_CGROUPS, hierarchy, user)
            if not os.path.exists(user_cgroup):
                try:
                    os.mkdir(user_cgroup)
                except OSError as e:
                    if e.errno == 13:
                        raise CGroupsException("Create cgroup permission denied")
                    elif e.errno == 17:
                        # file exists
                        pass
                    else:
                        raise OSError(e)
                else:
                    os.chown(user_cgroup, uid, gid)

    def _get_cgroup_file(self, hierarchy, file_name):
        return os.path.join(self.cgroups[hierarchy], file_name)

    @staticmethod
    def _format_cpu_value(value=None):
        if value is None:
            limit = CPU_DEFAULT
        else:
            try:
                limit = float(value)
            except ValueError:
                raise CGroupsException('CPU Limit must be convertible to a float')
            else:
                if limit <= float(0) or limit > float(getProcessorCores() * 100):
                    raise CGroupsException('CPU Limit must be between 0 and 100 * numCores')
                else:
                    limit = limit / 100
        return limit

    def get_parameter(self, subsystem, parameter):
        """
        Retrieve the value of a parameter from a subsystem.

        :param subsystem: str
        :param parameter: str
        :return: str
        """
        if subsystem in self.cgroups:
            parameter_file = self._get_cgroup_file(subsystem, parameter)
            try:
                with open(parameter_file, 'r') as f:
                    values = f.read().split('\n')
                    return values[0]
            except Exception:
                raise CGroupsException("Could not retrieve cgroup parameter {0}/{1}".format(subsystem, parameter))
        else:
            raise CGroupsException("{0} subsystem not available".format(subsystem))

    def set_cpu_limit(self, limit=None):
        """
        Limit this cgroup to a percentage of a single core. limit=10 means 10% of one core; 150 means 150%, which
        is useful only in multicore systems.
        To limit a cgroup to utilize 10% of a single CPU, use the following commands:
            # echo 10000 > /cgroup/cpu/red/cpu.cfs_quota_us
            # echo 100000 > /cgroup/cpu/red/cpu.cfs_period_us

        :param limit:
        """
        if 'cpu' in self.cgroups:
            total_units = float(self.get_parameter('cpu', 'cpu.cfs_period_us'))
            limit_units = self._format_cpu_value(limit) * total_units
            cpu_shares_file = self._get_cgroup_file('cpu', 'cpu.cfs_quota_us')
            with open(cpu_shares_file, 'w+') as f:
                f.write("{0}\n".format(limit_units))
        else:
            raise CGroupsException("CPU hierarchy not available in this cgroup")

    def get_cpu_stat(self):
        cpu_stat = None
        if 'cpu' in self.cgroups:
            cpu_stat_file = self._get_cgroup_file('cpu', 'cpuacct.stat')
            cpu_stat = fileutil.read_file(cpu_stat_file)
        return cpu_stat

    @staticmethod
    def get_proc_stat():
        """
        Return the contents of /proc/stat

        :return: str
        """
        proc_stat = fileutil.read_file('/proc/stat')
        if proc_stat is None:
            raise CGroupsException("Could not read /proc/stat")
        return proc_stat

    @staticmethod
    def get_num_cores():
        """
        Return the number of CPU cores exposed to this system.

        :return: int
        """
        proc_count = 0
        proc_stat = CGroups.get_proc_stat()
        if proc_stat is None:
            raise CGroupsException("Could not read /proc/stat")
        for line in proc_stat.splitlines():
            if re.match('^cpu[0-9]', line):
                proc_count += 1
        if proc_count == 0:
            proc_count = 1
        return proc_count

    @staticmethod
    def _format_memory_value(unit, limit=None):
        units = {'bytes': 1, 'kilobytes': 1024, 'megabytes': 1024*1024, 'gigabytes': 1024*1024*1024}
        if unit not in units:
            raise CGroupsException("Unit must be one of {0}".format(units.keys()))
        if limit is None:
            value = MEMORY_DEFAULT
        else:
            try:
                limit = int(limit)
            except ValueError:
                raise CGroupsException('Limit must be convertible to an int')
            else:
                value = limit * units[unit]
        return value

    def set_memory_limit(self, limit=None, unit='megabytes'):
        if 'memory' in self.cgroups:
            value = self._format_memory_value(unit, limit)
            memory_limit_file = self._get_cgroup_file('memory', 'memory.limit_in_bytes')
            with open(memory_limit_file, 'w+') as f:
                f.write("{0}\n".format(value))
        else:
            raise CGroupsException("Memory hierarchy not available in this cgroup")

    @staticmethod
    def get_extension_group_names():
        return ([os.path.basename(p) for p in
                 glob.glob(os.path.join(BASE_CGROUPS,
                                        HIERARCHIES[0],
                                        getpass.getuser(),
                                        CGROUP_EXTENSION_FORMAT
                                        .format('*')))])
