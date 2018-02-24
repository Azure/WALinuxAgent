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

CPU_DEFAULT = 1024

CGROUP_AGENT = 'azure-agent'

CGROUP_EXTENSION_FORMAT = 'azure-ext-{0}'


class CGroupsTelemetry(object):
    def __init__(self, name):
        self.name = name
        self.cpu_count = 0
        self.current_cpu_total = 0
        self.previous_cpu_total = 0
        self.current_system_cpu = 0
        self.previous_system_cpu = 0
        self.cgroup = CGroups(name)

    def get_cpu_percent(self):
        self.previous_cpu_total = self.current_cpu_total
        self.previous_system_cpu = self.current_system_cpu
        self.current_cpu_total = self.get_current_cpu_total()
        self.current_system_cpu = self.get_current_system_cpu()

        cpu_delta = self.current_cpu_total - self.previous_cpu_total
        system_delta = max(1, self.current_system_cpu - self.previous_system_cpu)

        return (float(cpu_delta) / float(system_delta)) * self.cpu_count * 100

    def get_current_cpu_total(self):
        cpu_total = 0
        cpu_stat = self.cgroup.get_cpu_stat()
        m = re.match('user (\d+)\nsystem (\d+)\n', cpu_stat)
        if m:
            cpu_total = int(m.groups()[0]) + int(m.groups()[1])
        return cpu_total

    def get_current_system_cpu(self):
        system_cpu = 0
        proc_stat = self.cgroup.get_proc_stat()
        logger.info(proc_stat)
        if proc_stat is not None:
            cpu_entries = [l for l in proc_stat.splitlines() if l.startswith('cpu')]
            for line in cpu_entries:
                if re.match('cpu .*', line):
                    system_cpu = sum(int(i) for i in line.split(' ')[2:7])
                    break
            self.cpu_count = len(cpu_entries) - 1
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
                    uid, gid = self.get_user_info(user)
                    os.chown(user_cgroup, uid, gid)

    def _get_cgroup_file(self, hierarchy, file_name):
        return os.path.join(self.cgroups[hierarchy], file_name)

    @staticmethod
    def _format_cpu_value(limit=None):
        if limit is None:
            value = CPU_DEFAULT
        else:
            try:
                limit = float(limit)
            except ValueError:
                raise CGroupsException('Limit must be convertible to a float')
            else:
                if limit <= float(0) or limit > float(100):
                    raise CGroupsException('Limit must be between 0 and 100')
                else:
                    limit = limit / 100
                    value = int(round(CPU_DEFAULT * limit))
        return value

    def set_cpu_limit(self, limit=None):
        if 'cpu' in self.cgroups:
            value = self._format_cpu_value(limit)
            cpu_shares_file = self._get_cgroup_file('cpu', 'cpu.shares')
            with open(cpu_shares_file, 'w+') as f:
                f.write("{0}\n".format(value))
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
        proc_stat = fileutil.read_file('/proc/stat')
        return proc_stat

    @staticmethod
    def _format_memory_value(unit, limit=None):
        units = ('bytes', 'kilobytes', 'megabytes', 'gigabytes')
        if unit not in units:
            raise CGroupsException('Unit must be in %s' % units)
        if limit is None:
            value = MEMORY_DEFAULT
        else:
            try:
                limit = int(limit)
            except ValueError:
                raise CGroupsException('Limit must be convertible to an int')
            else:
                if unit == 'bytes':
                    value = limit
                elif unit == 'kilobytes':
                    value = limit * 1024
                elif unit == 'megabytes':
                    value = limit * 1024 * 1024
                elif unit == 'gigabytes':
                    value = limit * 1024 * 1024 * 1024
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
        return [os.path.basename(p) for p in
                glob.glob(os.path.join(BASE_CGROUPS,
                                       HIERARCHIES[0],
                                       getpass.getuser(),
                                       CGROUP_EXTENSION_FORMAT.format('*')))]
