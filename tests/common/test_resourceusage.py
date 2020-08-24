# Copyright 2016 Microsoft Corporation
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

import os

from azurelinuxagent.common.resourceusage import MemoryResourceUsage, ProcessInfo, ProcessInfoException
from azurelinuxagent.common.utils import fileutil
from tests.tools import AgentTestCase, data_dir, patch


def raise_ioerror(*_):
    e = IOError() # pylint: disable=invalid-name
    from errno import ENOENT
    e.errno = ENOENT
    raise e


def raise_exception(*_):
    raise Exception()


class TestMemoryResourceUsage(AgentTestCase):
    @patch("azurelinuxagent.common.resourceusage.fileutil")
    def test_get_memory_usage_from_proc_statm(self, patch_read_file):
        patch_read_file.read_file.return_value = fileutil.read_file(os.path.join(
            data_dir, "cgroups", "dummy_proc_statm"))
        mem_usage = MemoryResourceUsage.get_memory_usage_from_proc_statm(1000)
        self.assertEqual(mem_usage, 331866112)

        # No such file exists. Throw IOError (similar to the IOError we throw for Cgroups).
        patch_read_file.read_file.side_effect = raise_ioerror
        with self.assertRaises(IOError):
            MemoryResourceUsage.get_memory_usage_from_proc_statm(1000)

        # Some other exception occured. Throw ProcessInfoException.
        patch_read_file.read_file.side_effect = raise_exception
        with self.assertRaises(ProcessInfoException):
            MemoryResourceUsage.get_memory_usage_from_proc_statm(1000)


class TestProcessInfo(AgentTestCase):
    @patch("azurelinuxagent.common.resourceusage.fileutil")
    def test_get_proc_cmdline(self, patch_read_file):
        patch_read_file.read_file.return_value = fileutil.read_file(os.path.join(data_dir, "cgroups", "dummy_proc_cmdline"))
        cmdline = ProcessInfo.get_proc_cmdline(1000)
        self.assertEqual("python -u bin/WALinuxAgent-2.2.45-py2.7.egg -run-exthandlers", cmdline)

        patch_read_file.read_file.side_effect = raise_ioerror
        # No such file exists; _get_proc_cmdline throws exception.
        with self.assertRaises(IOError):
            ProcessInfo._get_proc_cmdline(1000) # pylint: disable=protected-access

        patch_read_file.read_file.side_effect = raise_exception
        # Other exception; _get_proc_cmdline throws exception.
        with self.assertRaises(ProcessInfoException):
            ProcessInfo._get_proc_cmdline(1000) # pylint: disable=protected-access

    @patch("azurelinuxagent.common.resourceusage.fileutil")
    def test_get_proc_comm(self, patch_read_file):
        patch_read_file.read_file.return_value = fileutil.read_file(os.path.join(data_dir, "cgroups", "dummy_proc_comm"))
        proc_name = ProcessInfo.get_proc_name(1000)
        self.assertEqual("python", proc_name)

        patch_read_file.read_file.side_effect = raise_ioerror
        # No such file exists; expect None instead.
        with self.assertRaises(IOError):
            ProcessInfo.get_proc_name(1000)

        patch_read_file.read_file.side_effect = raise_exception
        # Other exception; _get_proc_cmdline throws exception.
        with self.assertRaises(ProcessInfoException):
            ProcessInfo._get_proc_comm(1000) # pylint: disable=protected-access
