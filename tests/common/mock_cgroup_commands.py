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

    (r"^systemctl daemon-reload", ""),

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

# These paths are mapped to the given tmp_dir, e.g. "/lib/systemd/system" becomes "<tmp_dir>/lib/systemd/system".
# The mapping is done only during calls to fileutil.read_file, fileutil.write_file, fileutil.mkdir and os.path.exists.
__SYSTEM_PATHS = [
    "/lib/systemd/system",
    "/etc/systemd/system"
]


@contextlib.contextmanager
def mock_cgroup_commands(tmp_dir):
    original_popen = subprocess.Popen
    original_read_file = fileutil.read_file
    original_write_file = fileutil.write_file
    original_mkdir = fileutil.mkdir
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

    def get_mapped_path(path):
        for item in patcher.files:
            match = re.match(item[0], path)
            if match is not None:
                return item[1]
        for item in __SYSTEM_PATHS:
            mapped = re.sub(r"^({0})".format(item), r"{0}\1".format(tmp_dir), path)
            if mapped != path:
                mapped_parent = os.path.split(mapped)[0]
                if not original_path_exists(mapped_parent):
                    os.makedirs(mapped_parent)
                return mapped
        return path

    def mock_read_file(filepath, **kwargs):
        return original_read_file(get_mapped_path(filepath), **kwargs)

    def mock_write_file(filepath, content, **kwargs):
        return original_write_file(get_mapped_path(filepath), content, **kwargs)

    def mock_mkdir(path, *args, **kwargs):
        return original_mkdir(get_mapped_path(path), *args, **kwargs)

    def mock_path_exists(path):
        return original_path_exists(get_mapped_path(path))

    with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as patcher:
        with patch("azurelinuxagent.common.cgroupconfigurator.fileutil.mkdir", side_effect=mock_mkdir):
            with patch("azurelinuxagent.common.cgroupapi.os.path.exists", side_effect=mock_path_exists):
                with patch("azurelinuxagent.common.cgroupapi.fileutil.read_file", side_effect=mock_read_file):
                    with patch("azurelinuxagent.common.cgroupapi.fileutil.write_file", side_effect=mock_write_file):
                        with patch('azurelinuxagent.common.cgroupapi.CGroupsApi.cgroups_supported', return_value=True):
                            with patch('azurelinuxagent.common.cgroupapi.CGroupsApi.is_systemd', return_value=True):
                                patcher.commands = __DEFAULT_COMMANDS[:]
                                patcher.files = __DEFAULT_FILES[:]
                                patcher.add_file = add_file
                                patcher.add_command = add_command
                                patcher.get_mapped_path = get_mapped_path
                                yield patcher

