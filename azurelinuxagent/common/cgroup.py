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

import os
import getpass

from pwd import getpwnam
from azurelinuxagent.common import logger, conf
from azurelinuxagent.common.utils import fileutil

BASE_CGROUPS = '/sys/fs/cgroup'

HIERARCHIES = ['cpu', 'memory']

MEMORY_DEFAULT = -1

CPU_DEFAULT = 1024

CGROUP_AGENT = 'azure-agent'

CGROUP_EXTENSION_FORMAT = 'azure-ext-{0}'


class CGroupsException(Exception):
    pass


class CGroup(object):

    def __init__(self, name):
        self.name = name
        self.user = getpass.getuser()
        self.user_cgroups = {}
        self.cgroups = {}
        self.hierarchies = HIERARCHIES

        system_hierarchies = os.listdir(BASE_CGROUPS)
        for hierarchy in self.hierarchies:
            if hierarchy not in system_hierarchies:
                raise CGroupsException("Hierarchy {0} is not mounted".format(hierarchy))

            user_cgroup = os.path.join(BASE_CGROUPS, hierarchy, self.user)
            self.user_cgroups[hierarchy] = user_cgroup

        self.create_user_cgroups(self.user)
        for hierarchy, user_cgroup in self.user_cgroups.items():
            cgroup = os.path.join(user_cgroup, self.name)
            if not os.path.exists(cgroup):
                os.mkdir(cgroup)
            self.cgroups[hierarchy] = cgroup

    @staticmethod
    def setup():
        logger.info("Setup cgroups")
        try:
            cg = CGroup(CGROUP_AGENT)
            # cg.set_cpu_limit(50)
            # cg.set_memory_limit(500)
            # add the daemon process
            pid_file = conf.get_agent_pid_file_path()
            if os.path.isfile(pid_file):
                pid = fileutil.read_file(pid_file)
                logger.info("Add daemon process pid {0} to {1} cgroup"
                            .format(pid, cg.name))
                cg.add(int(pid))
            else:
                logger.warn("No pid file at {0}".format(pid_file))

        except Exception as e:
            logger.error(e.message)

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
        logger.info("Creating cgroups for {0}".format(user))
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

        logger.info("cgroups created for {0}".format(user))

    def _get_cgroup_file(self, hierarchy, file_name):
        return os.path.join(self.cgroups[hierarchy], file_name)

    def _get_user_file(self, hierarchy, file_name):
        return os.path.join(self.user_cgroups[hierarchy], file_name)

    def delete(self):
        for hierarchy, cgroup in self.cgroups.items():
            # Put all pids of name cgroup in user cgroup
            tasks_file = self._get_cgroup_file(hierarchy, 'tasks')
            with open(tasks_file, 'r+') as f:
                tasks = f.read().split('\n')
            user_tasks_file =  self._get_user_file(hierarchy, 'tasks')
            with open(user_tasks_file, 'a+') as f:
                f.write('\n'.join(tasks))
            os.rmdir(cgroup)

    def add(self, pid):
        try:
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

    def remove(self, pid):
        try:
            os.kill(pid, 0)
        except OSError:
            raise CGroupsException('Pid %s does not exists' % pid)
        for hierarchy, cgroup in self.cgroups.items():
            tasks_file = self._get_cgroup_file(hierarchy, 'tasks')
            with open(tasks_file, 'r+') as f:
                pids = f.read().split('\n')
                if str(pid) in pids:
                    user_tasks_file = self._get_user_file(hierarchy, 'tasks')
                    with open(user_tasks_file, 'a+') as f:
                        f.write('%s\n' % pid)

    @property
    def pids(self):
        hierarchy = self.hierarchies[0]
        tasks_file = self._get_cgroup_file(hierarchy, 'tasks')
        with open(tasks_file, 'r+') as f:
            pids = f.read().split('\n')[:-1]
        pids = [int(pid) for pid in pids]
        return pids

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

    @property
    def cpu_limit(self):
        if 'cpu' in self.cgroups:
            cpu_shares_file = self._get_cgroup_file('cpu', 'cpu.shares')
            with open(cpu_shares_file, 'r+') as f:
                value = int(f.read().split('\n')[0])
                value = int(round((value / CPU_DEFAULT) * 100))
                return value
        else:
            return None

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

    @property
    def memory_limit(self):
        if 'memory' in self.cgroups:
            memory_limit_file = self._get_cgroup_file(
                'memory', 'memory.limit_in_bytes')
            with open(memory_limit_file, 'r+') as f:
                value = f.read().split('\n')[0]
                value = int(int(value) / 1024 / 1024)
                return value
        else:
            return None

    @staticmethod
    def add_to_agent_cgroup(msg):
        try:
            pid = os.getpid()
            cg = CGroup(CGROUP_AGENT)
            logger.info("Add pid {0} to cgroup {1} [{2}]".format(pid,
                                                                 cg.name,
                                                                 msg))
            cg.add(int(pid))
        except Exception as e:
            logger.error("Add to agent cgroup: " + e.message)

    @staticmethod
    def add_to_extension_cgroup(name):
        try:
            pid = os.getpid()
            cg = CGroup(CGROUP_EXTENSION_FORMAT.format(name))
            logger.info("Add pid {0} to cgroup {1}".format(pid,
                                                           cg.name))
            cg.add(int(pid))
        except Exception as e:
            logger.error("Add to extension cgroup: " + e.message)
