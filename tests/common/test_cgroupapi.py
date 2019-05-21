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
#

from __future__ import print_function

from azurelinuxagent.common.cgroupapi import FileSystemCgroupsApi
from azurelinuxagent.common.cgroupconfigurator import CGroupConfigurator
from tests.tools import *


def i_am_root():
    return os.geteuid() == 0


@skip_if_predicate_false(CGroupConfigurator.enabled, "CGroups not supported in this environment")
class TestCGroupConfigurator(AgentTestCase):
    #
    # TODO -- Need to write actual tests
    #
    def test_dummy(self):
        api = FileSystemCgroupsApi()
        api.create_agent_cgroups()
        self.assertTrue(True)


@skip_if_predicate_false(CGroupConfigurator.enabled, "CGroups not supported in this environment")
class TestSystemdCgroupsApi(AgentTestCase):

    @skip_if_predicate_false(i_am_root, "Test does not run when normal user")
    def test_if_extensions_root_slice_is_created(self):
        SystemdCgroupsApi().create_extension_cgroups_root()

        unit_name = SystemdCgroupsApi()._get_extension_unit_root_path()
        _, status = shellutil.run_get_output("systemctl status {0}".format(unit_name))
        self.assertIn("Loaded: loaded", status)
        self.assertIn("Active: active", status)

        shellutil.run_get_output("systemctl stop {0}".format(unit_name))
        shellutil.run_get_output("systemctl disable {0}".format(unit_name))
        os.remove("/etc/systemd/system/{0}".format(unit_name))
        shellutil.run_get_output("systemctl daemon-reload")

    @skip_if_predicate_false(i_am_root, "Test does not run when normal user")
    def test_if_extension_slice_is_created(self):
        extension_name = "Microsoft.Azure.DummyExtension-1.0"
        cgroups = SystemdCgroupsApi().create_extension_cgroups(extension_name)
        cpu_cgroup, memory_cgroup = cgroups[0], cgroups[1]
        self.assertEqual(cpu_cgroup, "/sys/fs/cgroup/cpu/system.slice/Microsoft.Azure.DummyExtension_1.0")
        self.assertEqual(memory_cgroup, "/sys/fs/cgroup/memory/system.slice/Microsoft.Azure.DummyExtension_1.0")

        unit_name = SystemdCgroupsApi._get_extension_unit_path(extension_name)
        self.assertEqual("system-walinuxagent.extensions-Microsoft.Azure.DummyExtension_1.0.slice", unit_name)

        _, status = shellutil.run_get_output("systemctl status {0}".format(unit_name))
        self.assertIn("Loaded: loaded", status)
        self.assertIn("Active: active", status)

        shellutil.run_get_output("systemctl stop {0}".format(unit_name))
        shellutil.run_get_output("systemctl disable {0}".format(unit_name))
        os.remove("/etc/systemd/system/{0}".format(unit_name))
        shellutil.run_get_output("systemctl daemon-reload")