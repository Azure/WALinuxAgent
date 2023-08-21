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
from tests.lib.tools import patch, data_dir
from tests.lib.mock_environment import MockEnvironment, MockCommand

_MOCKED_COMMANDS = [
   MockCommand(r"^systemctl --version$",
'''systemd 237
+PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD -IDN2 +IDN -PCRE2 default-hierarchy=hybrid
'''),

    MockCommand(r"^mount -t cgroup$",
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

    MockCommand(r"^mount -t cgroup2$",
'''cgroup on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime) 
'''),

    MockCommand(r"^systemctl show walinuxagent\.service --property Slice",
'''Slice=system.slice
'''),

    MockCommand(r"^systemctl show walinuxagent\.service --property CPUAccounting$",
'''CPUAccounting=no
'''),

    MockCommand(r"^systemctl show walinuxagent\.service --property CPUQuotaPerSecUSec$",
'''CPUQuotaPerSecUSec=infinity
'''),

    MockCommand(r"^systemctl show walinuxagent\.service --property MemoryAccounting$",
'''MemoryAccounting=no
'''),

    MockCommand(r"^systemctl show extension\.service --property ControlGroup$",
'''ControlGroup=/system.slice/extension.service
'''),

    MockCommand(r"^systemctl daemon-reload", ""),

    MockCommand(r"^systemctl stop ([^\s]+)"),

    MockCommand(r"^systemd-run (.+) --unit=([^\s]+) --scope ([^\s]+)",
''' 
Running scope as unit: TEST_UNIT.scope
Thu 28 May 2020 07:25:55 AM PDT
'''),

]

_MOCKED_FILES = [
    ("/proc/self/cgroup", os.path.join(data_dir, 'cgroups', 'proc_self_cgroup')),
    (r"/proc/[0-9]+/cgroup", os.path.join(data_dir, 'cgroups', 'proc_pid_cgroup')),
    ("/sys/fs/cgroup/unified/cgroup.controllers", os.path.join(data_dir, 'cgroups', 'sys_fs_cgroup_unified_cgroup.controllers'))
]

_MOCKED_PATHS = [
    r"^(/lib/systemd/system)",
    r"^(/etc/systemd/system)"
]


class UnitFilePaths:
    walinuxagent = "/lib/systemd/system/walinuxagent.service"
    logcollector = "/lib/systemd/system/azure-walinuxagent-logcollector.slice"
    azure = "/lib/systemd/system/azure.slice"
    vmextensions = "/lib/systemd/system/azure-vmextensions.slice"
    extensionslice = "/lib/systemd/system/azure-vmextensions-Microsoft.CPlat.Extension.slice"
    slice = "/lib/systemd/system/walinuxagent.service.d/10-Slice.conf"
    cpu_accounting = "/lib/systemd/system/walinuxagent.service.d/11-CPUAccounting.conf"
    cpu_quota = "/lib/systemd/system/walinuxagent.service.d/12-CPUQuota.conf"
    memory_accounting = "/lib/systemd/system/walinuxagent.service.d/13-MemoryAccounting.conf"
    extension_service_cpu_accounting = '/lib/systemd/system/extension.service.d/11-CPUAccounting.conf'
    extension_service_cpu_quota = '/lib/systemd/system/extension.service.d/12-CPUQuota.conf'
    extension_service_memory_accounting = '/lib/systemd/system/extension.service.d/13-MemoryAccounting.conf'
    extension_service_memory_limit = '/lib/systemd/system/extension.service.d/14-MemoryLimit.conf'


@contextlib.contextmanager
def mock_cgroup_environment(tmp_dir):
    """
    Creates a mocks environment used by the tests related to cgroups (currently it only provides support for systemd platforms).
    The command output used in __MOCKED_COMMANDS comes from an Ubuntu 18 system.
   """
    data_files = [
        (os.path.join(data_dir, 'init', 'walinuxagent.service'), UnitFilePaths.walinuxagent),
        (os.path.join(data_dir, 'init', 'azure.slice'), UnitFilePaths.azure),
        (os.path.join(data_dir, 'init', 'azure-vmextensions.slice'), UnitFilePaths.vmextensions)
    ]

    with patch('azurelinuxagent.ga.cgroupapi.CGroupsApi.cgroups_supported', return_value=True):
        with patch('azurelinuxagent.common.osutil.systemd.is_systemd', return_value=True):
            with MockEnvironment(tmp_dir, commands=_MOCKED_COMMANDS, paths=_MOCKED_PATHS, files=_MOCKED_FILES, data_files=data_files) as mock:
                yield mock
