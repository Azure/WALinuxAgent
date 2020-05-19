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
import subprocess

from azurelinuxagent.common.utils import fileutil
from tests.tools import patch, data_dir

#
# Default values for the mocked commands.
#
# The output comes from an Ubuntu 18 system
#
_default_commands = {
    "systemctl --version":
'''systemd 237
+PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD -IDN2 +IDN -PCRE2 default-hierarchy=hybrid
''',

    "mount -t cgroup":
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
''',

    "mount -t cgroup2":
'''cgroup on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime)
''',

    "systemctl show walinuxagent.service --property CPUAccounting":
'''CPUAccounting=no
''',

    "systemctl show walinuxagent.service --property MemoryAccounting":
'''MemoryAccounting=no
''',
}

_default_files = {
    "/proc/self/cgroup": os.path.join(data_dir, 'cgroups', 'proc_self_cgroup'),
    "/sys/fs/cgroup/unified/cgroup.controllers": os.path.join(data_dir, 'cgroups', 'sys_fs_cgroup_unified_cgroup.controllers'),
}

@contextlib.contextmanager
def mock_cgroup_commands():
    original_popen = subprocess.Popen
    original_read_file = fileutil.read_file
    original_path_exists = os.path.exists

    def mock_popen(command, *args, **kwargs):
        if isinstance(command, list):
            key = " ".join(command)
            if key in _default_commands:
                command = ["echo", _default_commands[key]]
        return original_popen(command, *args, **kwargs)
    
    def mock_read_file(filepath, **kwargs):
        if filepath in _default_files:
            filepath = _default_files[filepath]
        return original_read_file(filepath, **kwargs)

    def mock_path_exists(path):
        if path in _default_files:
            return True
        return original_path_exists(path)

    with patch("azurelinuxagent.common.cgroupapi.subprocess.Popen", side_effect=mock_popen) as patcher:
        with patch("azurelinuxagent.common.cgroupapi.os.path.exists", side_effect=mock_path_exists):
            with patch("azurelinuxagent.common.cgroupapi.fileutil.read_file", side_effect=mock_read_file):
                yield patcher

