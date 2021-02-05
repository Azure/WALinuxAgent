# -*- coding: utf-8 -*-
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
#
import contextlib
import os
import re
import subprocess

from azurelinuxagent.common.utils import fileutil
from tests.tools import patch, data_dir

#
# Default values for the mocked commands.
#
# The output comes from an Ubuntu 18 system
#
__DEFAULT_COMMANDS = [
    (r"^systemctl --version$",
'''systemd 237
+PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD -IDN2 +IDN -PCRE2 default-hierarchy=hybrid
'''),

    (r"^mount -t cgroup$",
'''cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
'''),
    (r"^mount -t cgroup2$",
'''cgroup on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime) 
'''),

    (r"^systemctl show walinuxagent\.service --property CPUAccounting$",
'''CPUAccounting=no
'''),

    (r"^systemctl show walinuxagent\.service --property MemoryAccounting$",
'''MemoryAccounting=no
'''),

    (r"^systemd-run --unit=([^\s]+) --scope ([^\s]+)",
''' 
Running scope as unit: TEST_UNIT.scope
Thu 28 May 2020 07:25:55 AM PDT
'''),

]

__DEFAULT_FILES = [
    (r"^/proc/self/cgroup$", os.path.join(data_dir, 'cgroups', 'proc_self_cgroup')),
    (r"^/proc/[0-9]+/cgroup$", os.path.join(data_dir, 'cgroups', 'proc_pid_cgroup')),
    (r"^/sys/fs/cgroup/unified/cgroup.controllers$", os.path.join(data_dir, 'cgroups', 'sys_fs_cgroup_unified_cgroup.controllers')),
]


@contextlib.contextmanager
def mock_cgroup_commands():
    original_popen = subprocess.Popen
    original_read_file = fileutil.read_file
    original_write_file = fileutil.write_file
    original_path_exists = os.path.exists

    def add_file(pattern, file_path):
        patcher.files.insert(0, (pattern, file_path))

    def add_command(pattern, output):
        patcher.commands.insert(0, (pattern, output))

    def mock_popen(command, *args, **kwargs):
        if isinstance(command, list):
            command_string = " ".join(command)
        else:
            command_string = command

        for cmd in patcher.commands:
            match = re.match(cmd[0], command_string)
            if match is not None:
                command = ["echo", cmd[1]]
                break

        return original_popen(command, *args, **kwargs)
    
    def mock_read_file(filepath, **kwargs):
        for item in patcher.files:
            match = re.match(item[0], filepath)
            if match is not None:
                filepath = item[1]
        return original_read_file(filepath, **kwargs)

    def mock_write_file(filepath, content, **kwargs):
        for item in patcher.files:
            match = re.match(item[0], filepath)
            if match is not None:
                filepath = item[1]
        return original_write_file(filepath, content, **kwargs)

    def mock_path_exists(path):
        for item in patcher.files:
            match = re.match(item[0], path)
            if match is not None:
                return True
        return original_path_exists(path)

    with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as patcher:
        with patch("azurelinuxagent.common.cgroupapi.os.path.exists", side_effect=mock_path_exists):
            with patch("azurelinuxagent.common.cgroupapi.fileutil.read_file", side_effect=mock_read_file):
                with patch("azurelinuxagent.common.cgroupapi.fileutil.write_file", side_effect=mock_write_file):
                    with patch('azurelinuxagent.common.cgroupapi.CGroupsApi.cgroups_supported', return_value=True):
                        with patch('azurelinuxagent.common.cgroupapi.CGroupsApi.is_systemd', return_value=True):
                            patcher.commands = __DEFAULT_COMMANDS[:]
                            patcher.files = __DEFAULT_FILES[:]
                            patcher.add_file = add_file
                            patcher.add_command = add_command
                            yield patcher

