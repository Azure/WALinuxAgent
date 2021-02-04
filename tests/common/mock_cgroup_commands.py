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
import shutil
import subprocess
import sys

from azurelinuxagent.common.utils import fileutil
from tests.tools import patch, data_dir

__MOCKED_COMMANDS = [
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
    (r"^systemctl show walinuxagent\.service --property Slice",
'''Slice=system.slice
'''),
    (r"^systemctl show walinuxagent\.service --property CPUAccounting$",
'''CPUAccounting=no
'''),
    (r"^systemctl show walinuxagent\.service --property CPUQuotaPerSecUSec$",
'''CPUQuotaPerSecUSec=infinity
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

__MOCKED_FILES = [
    ("/proc/self/cgroup", os.path.join(data_dir, 'cgroups', 'proc_self_cgroup')),
    (r"/proc/[0-9]+/cgroup", os.path.join(data_dir, 'cgroups', 'proc_pid_cgroup')),
    ("/sys/fs/cgroup/unified/cgroup.controllers", os.path.join(data_dir, 'cgroups', 'sys_fs_cgroup_unified_cgroup.controllers'))
]

__MOCKED_PATHS = [
    r"^(/lib/systemd/system)",
    r"^(/etc/systemd/system)"
]


class UnitFilePaths:
    walinuxagent = "/lib/systemd/system/walinuxagent.service"
    azure = "/lib/systemd/system/azure.slice"
    vmextensions = "/lib/systemd/system/azure-vmextensions.slice"
    slice = "/lib/systemd/system/walinuxagent.service.d/10-Slice.conf"
    cpu_accounting = "/lib/systemd/system/walinuxagent.service.d/11-CPUAccounting.conf"
    cpu_quota = "/lib/systemd/system/walinuxagent.service.d/12-CPUQuota.conf"


# W0212: Access to a protected member __commands of a client class (protected-access) - Disabled: __commands, __files and __paths
# are added only for debugging purposes and should not be public (hence it is marked as private).
# pylint: disable=protected-access
@contextlib.contextmanager
def mock_cgroup_commands(tmp_dir):
    """
    Creates a set of mocks useful for tests related to cgroups (currently it only provides support for systemd platforms).

    The function mocks Popen, fileutil.mkdir, os.path.exists and the open builtin function.

    The mock for Popen looks for a match in __MOCKED_COMMANDS and, if found, forwards the call to the the echo command
    to produce the output for the matching item. Otherwise it forwards the call to the original Popen function.

    The mocks for the other functions first look for a match in __MOCKED_FILES and, if found, map the file to the
    corresponding path in the matching item. If there is no match, then it checks if the file is under one of the paths
    in  __MOCKED_PATHS and map the path to the given tmp_dir (e.g. "/lib/systemd/system" becomes
    "<tmp_dir>/lib/systemd/system".) If there no matches, the path is not changed. Once this mapping has completed
    the mocks invoke the corresponding original function.

    Matches are done using regular expressions; the regular expressions in __MOCKED_PATHS must create group 0 to indicate
    the section of the path that needs to be mapped (i.e. use parenthesis around the section that needs to be mapped.)

    The command output used in __MOCKED_COMMANDS comes from an Ubuntu 18 system.

    The object returned by this function includes 3 methods (add_command_mock, add_path_mock, and add_file_mock) to add
    items to the list of mock objects. Items added by these methods take precedence over the default items.
    """
    original_popen = subprocess.Popen
    original_mkdir = fileutil.mkdir
    original_path_exists = os.path.exists
    original_open = open

    def add_command_mock(pattern, output):
        mock_cgroup_commands.__commands.insert(0, (pattern, output))

    def add_file_mock(actual, mock):
        mock_cgroup_commands.__files.insert(0, (actual, mock))

    def add_path_mock(mock):
        mock_cgroup_commands.__paths.insert(0, mock)

    def mock_popen(command, *args, **kwargs):
        if isinstance(command, list):
            command_string = " ".join(command)
        else:
            command_string = command

        for cmd in mock_cgroup_commands.__commands:
            match = re.match(cmd[0], command_string)
            if match is not None:
                command = ["echo", cmd[1]]
                break

        return original_popen(command, *args, **kwargs)

    def get_mapped_path(path):
        for item in mock_cgroup_commands.__files:
            match = re.match(item[0], path)
            if match is not None:
                return item[1]

        for item in mock_cgroup_commands.__paths:
            mapped = re.sub(item, r"{0}\1".format(tmp_dir), path)
            if mapped != path:
                mapped_parent = os.path.split(mapped)[0]
                if not original_path_exists(mapped_parent):
                    os.makedirs(mapped_parent)
                return mapped
        return path

    def mock_mkdir(path, *args, **kwargs):
        return original_mkdir(get_mapped_path(path), *args, **kwargs)

    def mock_open(path, *args, **kwargs):
        return original_open(get_mapped_path(path), *args, **kwargs)

    def mock_path_exists(path):
        return original_path_exists(get_mapped_path(path))

    data_files = [
        (os.path.join(data_dir, 'init', 'walinuxagent.service'), UnitFilePaths.walinuxagent),
        (os.path.join(data_dir, 'init', 'azure.slice'), UnitFilePaths.azure),
        (os.path.join(data_dir, 'init', 'azure-vmextensions.slice'), UnitFilePaths.vmextensions)
    ]

    def add_data_file(source, target):
        shutil.copyfile(source, get_mapped_path(target))

    builtin_popen = "__builtin__.open" if sys.version_info[0] == 2 else "builtins.open"

    with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen):
        with patch("azurelinuxagent.common.cgroupconfigurator.fileutil.mkdir", side_effect=mock_mkdir):
            with patch("azurelinuxagent.common.cgroupapi.os.path.exists", side_effect=mock_path_exists):
                with patch(builtin_popen, side_effect=mock_open):
                    with patch('azurelinuxagent.common.cgroupapi.CGroupsApi.cgroups_supported', return_value=True):
                        with patch('azurelinuxagent.common.cgroupapi.CGroupsApi.is_systemd', return_value=True):
                            mock_cgroup_commands.__commands = __MOCKED_COMMANDS[:]
                            mock_cgroup_commands.__files = __MOCKED_FILES[:]
                            mock_cgroup_commands.__paths = __MOCKED_PATHS[:]
                            mock_cgroup_commands.add_command_mock = add_command_mock
                            mock_cgroup_commands.add_file_mock = add_file_mock
                            mock_cgroup_commands.add_path_mock = add_path_mock
                            mock_cgroup_commands.add_data_file = add_data_file
                            mock_cgroup_commands.get_mapped_path = get_mapped_path

                            for items in data_files:
                                add_data_file(items[0], items[1])

                            yield mock_cgroup_commands
