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

import contextlib
import os
import random
import re
import subprocess
import tempfile
import time
import threading

from nose.plugins.attrib import attr

from azurelinuxagent.common import conf
from azurelinuxagent.ga.cgroup import AGENT_NAME_TELEMETRY, MetricsCounter, MetricValue, MetricsCategory, CpuCgroup
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator, DisableCgroups
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.exception import CGroupsException, ExtensionError, ExtensionErrorCodes, \
    AgentMemoryExceededException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import shellutil, fileutil
from tests.lib.mock_environment import MockCommand
from tests.lib.mock_cgroup_environment import mock_cgroup_environment, UnitFilePaths
from tests.lib.tools import AgentTestCase, patch, mock_sleep, i_am_root, data_dir, is_python_version_26_or_34, skip_if_predicate_true
from tests.lib.miscellaneous_tools import format_processes, wait_for


class CGroupConfiguratorSystemdTestCase(AgentTestCase):
    @classmethod
    def tearDownClass(cls):
        CGroupConfigurator._instance = None
        AgentTestCase.tearDownClass()

    @contextlib.contextmanager
    def _get_cgroup_configurator(self, initialize=True, enable=True, mock_commands=None):
        CGroupConfigurator._instance = None
        configurator = CGroupConfigurator.get_instance()
        CGroupsTelemetry.reset()
        with mock_cgroup_environment(self.tmp_dir) as mock_environment:
            if mock_commands is not None:
                for command in mock_commands:
                    mock_environment.add_command(command)
            configurator.mocks = mock_environment
            if initialize:
                if not enable:
                    with patch.object(configurator, "enable"):
                        configurator.initialize()
                else:
                    configurator.initialize()
            yield configurator

    def test_initialize_should_enable_cgroups(self):
        with self._get_cgroup_configurator() as configurator:
            self.assertTrue(configurator.enabled(), "cgroups were not enabled")

    def test_initialize_should_start_tracking_the_agent_cgroups(self):
        with self._get_cgroup_configurator() as configurator:
            tracked = CGroupsTelemetry._tracked

            self.assertTrue(configurator.enabled(), "Cgroups should be enabled")
            self.assertTrue(any(cg for cg in tracked.values() if cg.name == AGENT_NAME_TELEMETRY and 'cpu' in cg.path),
                "The Agent's CPU is not being tracked. Tracked: {0}".format(tracked))
            self.assertTrue(any(cg for cg in tracked.values() if cg.name == AGENT_NAME_TELEMETRY and 'memory' in cg.path),
                "The Agent's Memory is not being tracked. Tracked: {0}".format(tracked))

    def test_initialize_should_start_tracking_other_controllers_when_one_is_not_present(self):
        command_mocks = [MockCommand(r"^mount -t cgroup$",
'''cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
''')]
        with self._get_cgroup_configurator(mock_commands=command_mocks) as configurator:
            tracked = CGroupsTelemetry._tracked

            self.assertTrue(configurator.enabled(), "Cgroups should be enabled")
            self.assertFalse(any(cg for cg in tracked.values() if cg.name == 'walinuxagent.service' and 'memory' in cg.path),
                "The Agent's memory should not be tracked. Tracked: {0}".format(tracked))

    def test_initialize_should_not_enable_cgroups_when_the_cpu_and_memory_controllers_are_not_present(self):
        command_mocks = [MockCommand(r"^mount -t cgroup$",
'''cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
''')]
        with self._get_cgroup_configurator(mock_commands=command_mocks) as configurator:
            tracked = CGroupsTelemetry._tracked

            self.assertFalse(configurator.enabled(), "Cgroups should not be enabled")
            self.assertEqual(len(tracked), 0, "No cgroups should be tracked. Tracked: {0}".format(tracked))

    def test_initialize_should_not_enable_cgroups_when_the_agent_is_not_in_the_system_slice(self):
        command_mocks = [MockCommand(r"^mount -t cgroup$",
'''cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
''')]

        with self._get_cgroup_configurator(mock_commands=command_mocks) as configurator:
            tracked = CGroupsTelemetry._tracked
            agent_drop_in_file_cpu_quota = configurator.mocks.get_mapped_path(UnitFilePaths.cpu_quota)

            self.assertFalse(configurator.enabled(), "Cgroups should not be enabled")
            self.assertEqual(len(tracked), 0, "No cgroups should be tracked. Tracked: {0}".format(tracked))
            self.assertFalse(os.path.exists(agent_drop_in_file_cpu_quota), "{0} should not have been created".format(agent_drop_in_file_cpu_quota))

    def test_initialize_should_not_create_unit_files(self):
        with self._get_cgroup_configurator() as configurator:
            # get the paths to the mocked files
            azure_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.azure)
            extensions_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.vmextensions)
            agent_drop_in_file_slice = configurator.mocks.get_mapped_path(UnitFilePaths.slice)
            agent_drop_in_file_cpu_accounting = configurator.mocks.get_mapped_path(UnitFilePaths.cpu_accounting)
            agent_drop_in_file_memory_accounting = configurator.mocks.get_mapped_path(UnitFilePaths.memory_accounting)

            # The mock creates the slice unit files; delete them
            os.remove(azure_slice_unit_file)
            os.remove(extensions_slice_unit_file)

            # The service file for the agent includes settings for the slice and cpu accounting, but not for cpu quota; initialize()
            # should not create drop in files for the first 2, but it should create one the cpu quota
            self.assertFalse(os.path.exists(azure_slice_unit_file), "{0} should not have been created".format(azure_slice_unit_file))
            self.assertFalse(os.path.exists(extensions_slice_unit_file), "{0} should not have been created".format(extensions_slice_unit_file))
            self.assertFalse(os.path.exists(agent_drop_in_file_slice), "{0} should not have been created".format(agent_drop_in_file_slice))
            self.assertFalse(os.path.exists(agent_drop_in_file_cpu_accounting), "{0} should not have been created".format(agent_drop_in_file_cpu_accounting))
            self.assertFalse(os.path.exists(agent_drop_in_file_memory_accounting), "{0} should not have been created".format(agent_drop_in_file_memory_accounting))

    def test_initialize_should_create_unit_files_when_the_agent_service_file_is_not_updated(self):
        with self._get_cgroup_configurator(initialize=False) as configurator:
            # get the paths to the mocked files
            azure_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.azure)
            extensions_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.vmextensions)
            agent_drop_in_file_slice = configurator.mocks.get_mapped_path(UnitFilePaths.slice)
            agent_drop_in_file_cpu_accounting = configurator.mocks.get_mapped_path(UnitFilePaths.cpu_accounting)
            agent_drop_in_file_memory_accounting = configurator.mocks.get_mapped_path(UnitFilePaths.memory_accounting)

            # The mock creates the service and slice unit files; replace the former and delete the latter
            configurator.mocks.add_data_file(os.path.join(data_dir, 'init', "walinuxagent.service.previous"), UnitFilePaths.walinuxagent)
            os.remove(azure_slice_unit_file)
            os.remove(extensions_slice_unit_file)

            configurator.initialize()

            # The older service file for the agent did not include settings for the slice and cpu parameters; in that case, initialize() should
            # create drop in files to set those properties
            self.assertTrue(os.path.exists(azure_slice_unit_file), "{0} was not created".format(azure_slice_unit_file))
            self.assertTrue(os.path.exists(extensions_slice_unit_file), "{0} was not created".format(extensions_slice_unit_file))
            self.assertTrue(os.path.exists(agent_drop_in_file_slice), "{0} was not created".format(agent_drop_in_file_slice))
            self.assertTrue(os.path.exists(agent_drop_in_file_cpu_accounting), "{0} was not created".format(agent_drop_in_file_cpu_accounting))
            self.assertTrue(os.path.exists(agent_drop_in_file_memory_accounting), "{0} was not created".format(agent_drop_in_file_memory_accounting))

    def test_initialize_should_update_logcollector_memorylimit(self):
        with self._get_cgroup_configurator(initialize=False) as configurator:
            log_collector_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.logcollector)
            original_memory_limit = "MemoryLimit=30M"

            # The mock creates the slice unit file with memory limit
            configurator.mocks.add_data_file(os.path.join(data_dir, 'init', "azure-walinuxagent-logcollector.slice"),
                                             UnitFilePaths.logcollector)
            if not os.path.exists(log_collector_unit_file):
                raise Exception("{0} should have been created during test setup".format(log_collector_unit_file))
            if not fileutil.findre_in_file(log_collector_unit_file, original_memory_limit):
                raise Exception("MemoryLimit was not set correctly. Expected: {0}. Got:\n{1}".format(
                    original_memory_limit, fileutil.read_file(log_collector_unit_file)))

            configurator.initialize()

            # initialize() should update the unit file to remove the memory limit
            self.assertFalse(fileutil.findre_in_file(log_collector_unit_file, original_memory_limit),
                             "Log collector slice unit file was not updated correctly. Expected no memory limit. Got:\n{0}".format(
                                 fileutil.read_file(log_collector_unit_file)))

    def test_setup_extension_slice_should_create_unit_files(self):
        with self._get_cgroup_configurator() as configurator:
            # get the paths to the mocked files
            extension_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.extensionslice)

            configurator.setup_extension_slice(extension_name="Microsoft.CPlat.Extension", cpu_quota=5)

            expected_cpu_accounting = "CPUAccounting=yes"
            expected_cpu_quota_percentage = "5%"
            expected_memory_accounting = "MemoryAccounting=yes"

            self.assertTrue(os.path.exists(extension_slice_unit_file), "{0} was not created".format(extension_slice_unit_file))
            self.assertTrue(fileutil.findre_in_file(extension_slice_unit_file, expected_cpu_accounting),
                "CPUAccounting was not set correctly. Expected: {0}. Got:\n{1}".format(expected_cpu_accounting, fileutil.read_file(
                    extension_slice_unit_file)))
            self.assertTrue(fileutil.findre_in_file(extension_slice_unit_file, expected_cpu_quota_percentage),
                "CPUQuota was not set correctly. Expected: {0}. Got:\n{1}".format(expected_cpu_quota_percentage, fileutil.read_file(
                    extension_slice_unit_file)))
            self.assertTrue(fileutil.findre_in_file(extension_slice_unit_file, expected_memory_accounting),
                "MemoryAccounting was not set correctly. Expected: {0}. Got:\n{1}".format(expected_memory_accounting, fileutil.read_file(
                    extension_slice_unit_file)))

    def test_remove_extension_slice_should_remove_unit_files(self):
        with self._get_cgroup_configurator() as configurator:
            with patch("os.path.exists") as mock_path:
                mock_path.return_value = True
                # get the paths to the mocked files
                extension_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.extensionslice)

                CGroupsTelemetry._tracked['/sys/fs/cgroup/cpu,cpuacct/azure.slice/azure-vmextensions.slice/' \
                                          'azure-vmextensions-Microsoft.CPlat.Extension.slice'] = \
                    CpuCgroup('Microsoft.CPlat.Extension',
                              '/sys/fs/cgroup/cpu,cpuacct/azure.slice/azure-vmextensions.slice/azure-vmextensions-Microsoft.CPlat.Extension.slice')

                configurator.remove_extension_slice(extension_name="Microsoft.CPlat.Extension")

                tracked = CGroupsTelemetry._tracked

                self.assertFalse(
                    any(cg for cg in tracked.values() if cg.name == 'Microsoft.CPlat.Extension' and 'cpu' in cg.path),
                    "The extension's CPU is being tracked")
                self.assertFalse(
                    any(cg for cg in tracked.values() if cg.name == 'Microsoft.CPlat.Extension' and 'memory' in cg.path),
                    "The extension's Memory is being tracked")

            self.assertFalse(os.path.exists(extension_slice_unit_file), "{0} should not be present".format(extension_slice_unit_file))

    def test_enable_should_raise_cgroups_exception_when_cgroups_are_not_supported(self):
        with self._get_cgroup_configurator(enable=False) as configurator:
            with patch.object(configurator, "supported", return_value=False):
                with self.assertRaises(CGroupsException) as context_manager:
                    configurator.enable()
                self.assertIn("Attempted to enable cgroups, but they are not supported on the current platform", str(context_manager.exception))

    def test_enable_should_set_agent_cpu_quota_and_track_throttled_time(self):
        with self._get_cgroup_configurator(initialize=False) as configurator:
            agent_drop_in_file_cpu_quota = configurator.mocks.get_mapped_path(UnitFilePaths.cpu_quota)
            if os.path.exists(agent_drop_in_file_cpu_quota):
                raise Exception("{0} should not have been created during test setup".format(agent_drop_in_file_cpu_quota))

            configurator.initialize()

            expected_quota = "CPUQuota={0}%".format(conf.get_agent_cpu_quota())
            self.assertTrue(os.path.exists(agent_drop_in_file_cpu_quota), "{0} was not created".format(agent_drop_in_file_cpu_quota))
            self.assertTrue(
                fileutil.findre_in_file(agent_drop_in_file_cpu_quota, expected_quota),
                "CPUQuota was not set correctly. Expected: {0}. Got:\n{1}".format(expected_quota, fileutil.read_file(agent_drop_in_file_cpu_quota)))
            self.assertTrue(CGroupsTelemetry.get_track_throttled_time(), "Throttle time should be tracked")

    def test_enable_should_not_track_throttled_time_when_setting_the_cpu_quota_fails(self):
        with self._get_cgroup_configurator(initialize=False) as configurator:
            if CGroupsTelemetry.get_track_throttled_time():
                raise Exception("Test setup should not start tracking Throttle Time")

            configurator.mocks.add_file(UnitFilePaths.cpu_quota, Exception("A TEST EXCEPTION"))

            configurator.initialize()

            self.assertFalse(CGroupsTelemetry.get_track_throttled_time(), "Throttle time should not be tracked")

    def test_disable_should_reset_cpu_quota(self):
        with self._get_cgroup_configurator() as configurator:
            if len(CGroupsTelemetry._tracked) == 0:
                raise Exception("Test setup should have started tracking at least 1 cgroup (the agent's)")
            if not CGroupsTelemetry._track_throttled_time:
                raise Exception("Test setup should have started tracking Throttle Time")

            configurator.disable("UNIT TEST", DisableCgroups.AGENT)

            agent_drop_in_file_cpu_quota = configurator.mocks.get_mapped_path(UnitFilePaths.cpu_quota)
            self.assertTrue(os.path.exists(agent_drop_in_file_cpu_quota), "{0} was not created".format(agent_drop_in_file_cpu_quota))
            self.assertTrue(
                fileutil.findre_in_file(agent_drop_in_file_cpu_quota, "^CPUQuota=$"),
                "CPUQuota was not set correctly. Expected an empty value. Got:\n{0}".format(fileutil.read_file(agent_drop_in_file_cpu_quota)))
            self.assertEqual(len(CGroupsTelemetry._tracked), 1, "Memory cgroups should be tracked after disable. Tracking: {0}".format(CGroupsTelemetry._tracked))
            self.assertFalse(any(cg for cg in CGroupsTelemetry._tracked.values() if cg.name == 'walinuxagent.service' and 'cpu' in cg.path),
                "The Agent's cpu should not be tracked. Tracked: {0}".format(CGroupsTelemetry._tracked))

    def test_disable_should_reset_cpu_quota_for_all_cgroups(self):
        service_list = [
            {
                "name": "extension.service",
                "cpuQuotaPercentage": 5
            }
        ]
        extension_name = "Microsoft.CPlat.Extension"
        extension_services = {extension_name: service_list}
        with self._get_cgroup_configurator() as configurator:
            with patch.object(configurator, "get_extension_services_list", return_value=extension_services):
                # get the paths to the mocked files
                agent_drop_in_file_cpu_quota = configurator.mocks.get_mapped_path(UnitFilePaths.cpu_quota)
                extension_slice_unit_file = configurator.mocks.get_mapped_path(UnitFilePaths.extensionslice)
                extension_service_cpu_quota = configurator.mocks.get_mapped_path(UnitFilePaths.extension_service_cpu_quota)

                configurator.setup_extension_slice(extension_name=extension_name, cpu_quota=5)
                configurator.set_extension_services_cpu_memory_quota(service_list)
                CGroupsTelemetry._tracked['/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service'] = \
                    CpuCgroup('extension.service', '/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service')
                CGroupsTelemetry._tracked['/sys/fs/cgroup/cpu,cpuacct/azure.slice/azure-vmextensions.slice/' \
                                          'azure-vmextensions-Microsoft.CPlat.Extension.slice'] = \
                    CpuCgroup('Microsoft.CPlat.Extension',
                              '/sys/fs/cgroup/cpu,cpuacct/azure.slice/azure-vmextensions.slice/azure-vmextensions-Microsoft.CPlat.Extension.slice')

                configurator.disable("UNIT TEST", DisableCgroups.ALL)

                self.assertTrue(os.path.exists(agent_drop_in_file_cpu_quota),
                                "{0} was not created".format(agent_drop_in_file_cpu_quota))
                self.assertTrue(
                    fileutil.findre_in_file(agent_drop_in_file_cpu_quota, "^CPUQuota=$"),
                    "CPUQuota was not set correctly. Expected an empty value. Got:\n{0}".format(
                        fileutil.read_file(agent_drop_in_file_cpu_quota)))
                self.assertTrue(os.path.exists(extension_slice_unit_file),
                                "{0} was not created".format(extension_slice_unit_file))
                self.assertTrue(
                    fileutil.findre_in_file(extension_slice_unit_file, "^CPUQuota=$"),
                    "CPUQuota was not set correctly. Expected an empty value. Got:\n{0}".format(
                        fileutil.read_file(extension_slice_unit_file)))
                self.assertTrue(os.path.exists(extension_service_cpu_quota),
                                "{0} was not created".format(extension_service_cpu_quota))
                self.assertTrue(
                    fileutil.findre_in_file(extension_service_cpu_quota, "^CPUQuota=$"),
                    "CPUQuota was not set correctly. Expected an empty value. Got:\n{0}".format(
                        fileutil.read_file(extension_service_cpu_quota)))
                self.assertEqual(len(CGroupsTelemetry._tracked), 0,
                                 "No cgroups should be tracked after disable. Tracking: {0}".format(
                                     CGroupsTelemetry._tracked))

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_not_use_systemd_when_cgroups_are_not_enabled(self, _):
        with self._get_cgroup_configurator() as configurator:
            configurator.disable("UNIT TEST", DisableCgroups.ALL)

            with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as patcher:
                configurator.start_extension_command(
                    extension_name="Microsoft.Compute.TestExtension-1.2.3",
                    command="date",
                    cmd_name="test",
                    timeout=300,
                    shell=False,
                    cwd=self.tmp_dir,
                    env={},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

                command_calls = [args[0] for args, _ in patcher.call_args_list if len(args) > 0 and "date" in args[0]]
                self.assertEqual(len(command_calls), 1, "The test command should have been called exactly once [{0}]".format(command_calls))
                self.assertNotIn("systemd-run", command_calls[0], "The command should not have been invoked using systemd")
                self.assertEqual(command_calls[0], "date", "The command line should not have been modified")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_use_systemd_run_when_cgroups_are_enabled(self, _):
        with self._get_cgroup_configurator() as configurator:
            with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                configurator.start_extension_command(
                    extension_name="Microsoft.Compute.TestExtension-1.2.3",
                    command="the-test-extension-command",
                    cmd_name="test",
                    timeout=300,
                    shell=False,
                    cwd=self.tmp_dir,
                    env={},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

                command_calls = [args[0] for (args, _) in popen_patch.call_args_list if "the-test-extension-command" in args[0]]

                self.assertEqual(len(command_calls), 1, "The test command should have been called exactly once [{0}]".format(command_calls))
                self.assertIn("systemd-run", command_calls[0], "The extension should have been invoked using systemd")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_start_tracking_the_extension_cgroups(self, _):
        # CPU usage is initialized when we begin tracking a CPU cgroup; since this test does not retrieve the
        # CPU usage, there is no need for initialization
        with self._get_cgroup_configurator() as configurator:
            configurator.start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="test command",
                cmd_name="test",
                timeout=300,
                shell=False,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

        tracked = CGroupsTelemetry._tracked

        self.assertTrue(
            any(cg for cg in tracked.values() if cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'cpu' in cg.path),
            "The extension's CPU is not being tracked")
        self.assertTrue(
            any(cg for cg in tracked.values() if cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and 'memory' in cg.path),
            "The extension's Memory is not being tracked")

    def test_start_extension_command_should_raise_an_exception_when_the_command_cannot_be_started(self):
        with self._get_cgroup_configurator() as configurator:
            original_popen = subprocess.Popen

            def mock_popen(command_arg, *args, **kwargs):
                if "test command" in command_arg:
                    raise Exception("A TEST EXCEPTION")
                return original_popen(command_arg, *args, **kwargs)

            with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", side_effect=mock_popen):
                with self.assertRaises(Exception) as context_manager:
                    configurator.start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="test command",
                        cmd_name="test",
                        timeout=300,
                        shell=False,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)

                    self.assertIn("A TEST EXCEPTION", str(context_manager.exception))

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_disable_cgroups_and_invoke_the_command_directly_if_systemd_fails(self, _):
        with self._get_cgroup_configurator() as configurator:

            configurator.mocks.add_command(MockCommand("systemd-run", return_value=1, stdout='', stderr='Failed to start transient scope unit: syntax error'))

            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as output_file:
                with patch("azurelinuxagent.ga.cgroupconfigurator.add_event") as mock_add_event:
                    with patch("subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                        CGroupsTelemetry.reset()

                        command = "echo TEST_OUTPUT"

                        command_output = configurator.start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command=command,
                            cmd_name="test",
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=output_file,
                            stderr=output_file)

                        self.assertFalse(configurator.enabled(), "Cgroups should have been disabled")

                        disabled_events = [kwargs for _, kwargs in mock_add_event.call_args_list if kwargs['op'] == WALAEventOperation.CGroupsDisabled]

                        self.assertTrue(len(disabled_events) == 1, "Exactly one CGroupsDisabled telemetry event should have been issued. Found: {0}".format(disabled_events))
                        self.assertIn("Failed to start Microsoft.Compute.TestExtension-1.2.3 using systemd-run",
                                      disabled_events[0]['message'],
                                      "The systemd-run failure was not included in the telemetry message")
                        self.assertEqual(False, disabled_events[0]['is_success'], "The telemetry event should indicate a failure")

                        extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if command in args[0]]

                        self.assertEqual(2, len(extension_calls), "The extension should have been invoked exactly twice")
                        self.assertIn("systemd-run", extension_calls[0],
                                      "The first call to the extension should have used systemd")
                        self.assertEqual(command, extension_calls[1],
                                          "The second call to the extension should not have used systemd")

                        self.assertEqual(len(CGroupsTelemetry._tracked), 0, "No cgroups should have been created")

                        self.assertIn("TEST_OUTPUT\n", command_output, "The test output was not captured")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_disable_cgroups_and_invoke_the_command_directly_if_systemd_times_out(self, _):
        with self._get_cgroup_configurator() as configurator:
            # Systemd has its own internal timeout which is shorter than what we define for extension operation timeout.
            # When systemd times out, it will write a message to stderr and exit with exit code 1.
            # In that case, we will internally recognize the failure due to the non-zero exit code, not as a timeout.
            configurator.mocks.add_command(MockCommand("systemd-run", return_value=1, stdout='', stderr='Failed to start transient scope unit: Connection timed out'))

            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
                with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                    with patch("subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                        CGroupsTelemetry.reset()

                        configurator.start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command="echo 'success'",
                            cmd_name="test",
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                        self.assertFalse(configurator.enabled(), "Cgroups should have been disabled")

                        extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if "echo 'success'" in args[0]]
                        self.assertEqual(2, len(extension_calls), "The extension should have been called twice. Got: {0}".format(extension_calls))
                        self.assertIn("systemd-run", extension_calls[0], "The first call to the extension should have used systemd")
                        self.assertNotIn("systemd-run", extension_calls[1], "The second call to the extension should not have used systemd")

                        self.assertEqual(len(CGroupsTelemetry._tracked), 0, "No cgroups should have been created")

    @skip_if_predicate_true(is_python_version_26_or_34, "Disabled on Python 2.6 and 3.4 for now. Need to revisit to fix it")
    @attr('requires_sudo')
    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_not_use_fallback_option_if_extension_fails(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        command = "ls folder_does_not_exist"

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                    with self.assertRaises(ExtensionError) as context_manager:
                        configurator.start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command=command,
                            cmd_name="test",
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                    extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if command in args[0]]

                    self.assertEqual(1, len(extension_calls), "The extension should have been invoked exactly once")
                    self.assertIn("systemd-run", extension_calls[0],
                                  "The first call to the extension should have used systemd")

                    self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginUnknownFailure)
                    self.assertIn("Non-zero exit code", ustr(context_manager.exception))
                    # The scope name should appear in the process output since systemd-run was invoked and stderr
                    # wasn't truncated.
                    self.assertIn("Running scope as unit", ustr(context_manager.exception))

    @skip_if_predicate_true(is_python_version_26_or_34, "Disabled on Python 2.6 and 3.4 for now. Need to revisit to fix it")
    @attr('requires_sudo')
    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    @patch("azurelinuxagent.ga.extensionprocessutil.TELEMETRY_MESSAGE_MAX_LEN", 5)
    def test_start_extension_command_should_not_use_fallback_option_if_extension_fails_with_long_output(self, *args):
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        long_output = "a"*20  # large enough to ensure both stdout and stderr are truncated
        long_stdout_stderr_command = "echo {0} && echo {0} >&2 && ls folder_does_not_exist".format(long_output)

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                    with self.assertRaises(ExtensionError) as context_manager:
                        configurator.start_extension_command(
                            extension_name="Microsoft.Compute.TestExtension-1.2.3",
                            command=long_stdout_stderr_command,
                            cmd_name="test",
                            timeout=300,
                            shell=True,
                            cwd=self.tmp_dir,
                            env={},
                            stdout=stdout,
                            stderr=stderr)

                    extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if long_stdout_stderr_command in args[0]]

                    self.assertEqual(1, len(extension_calls), "The extension should have been invoked exactly once")
                    self.assertIn("systemd-run", extension_calls[0],
                                  "The first call to the extension should have used systemd")

                    self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginUnknownFailure)
                    self.assertIn("Non-zero exit code", ustr(context_manager.exception))
                    # stdout and stderr should have been truncated, so the scope name doesn't appear in stderr
                    # even though systemd-run ran
                    self.assertNotIn("Running scope as unit", ustr(context_manager.exception))

    @attr('requires_sudo')
    def test_start_extension_command_should_not_use_fallback_option_if_extension_times_out(self, *args):  # pylint: disable=unused-argument
        self.assertTrue(i_am_root(), "Test does not run when non-root")

        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.ga.extensionprocessutil.wait_for_process_completion_or_timeout",
                           return_value=[True, None, 0]):
                    with patch("azurelinuxagent.ga.cgroupapi.SystemdCgroupsApi._is_systemd_failure",
                               return_value=False):
                        with self.assertRaises(ExtensionError) as context_manager:
                            configurator.start_extension_command(
                                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                                command="date",
                                cmd_name="test",
                                timeout=300,
                                shell=True,
                                cwd=self.tmp_dir,
                                env={},
                                stdout=stdout,
                                stderr=stderr)

                        self.assertEqual(context_manager.exception.code, ExtensionErrorCodes.PluginHandlerScriptTimedout)
                        self.assertIn("Timeout", ustr(context_manager.exception))

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_command_should_capture_only_the_last_subprocess_output(self, _):
        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        original_popen = subprocess.Popen

        def mock_popen(command, *args, **kwargs):
            # Inject a syntax error to the call
            
            # Popen can accept both strings and lists, handle both here.
            if isinstance(command, str):
                systemd_command = command.replace('systemd-run', 'systemd-run syntax_error')
            elif isinstance(command, list) and command[0] == 'systemd-run':
                systemd_command = ['systemd-run', 'syntax_error'] + command[1:]

            return original_popen(systemd_command, *args, **kwargs)

        expected_output = "[stdout]\n{0}\n\n\n[stderr]\n"

        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", side_effect=mock_popen):
                    # We expect this call to fail because of the syntax error
                    process_output = configurator.start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="echo 'very specific test message'",
                        cmd_name="test",
                        timeout=300,
                        shell=True,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=stdout,
                        stderr=stderr)

                    self.assertEqual(expected_output.format("very specific test message"), process_output)

    def test_it_should_set_extension_services_cpu_memory_quota(self):
        service_list = [
            {
                "name": "extension.service",
                "cpuQuotaPercentage": 5
            }
        ]
        with self._get_cgroup_configurator() as configurator:
            # get the paths to the mocked files
            extension_service_cpu_accounting = configurator.mocks.get_mapped_path(UnitFilePaths.extension_service_cpu_accounting)
            extension_service_cpu_quota = configurator.mocks.get_mapped_path(UnitFilePaths.extension_service_cpu_quota)

            configurator.set_extension_services_cpu_memory_quota(service_list)
            expected_cpu_accounting = "CPUAccounting=yes"
            expected_cpu_quota_percentage = "CPUQuota=5%"

            # create drop in files to set those properties
            self.assertTrue(os.path.exists(extension_service_cpu_accounting), "{0} was not created".format(extension_service_cpu_accounting))
            self.assertTrue(
                fileutil.findre_in_file(extension_service_cpu_accounting, expected_cpu_accounting),
                "CPUAccounting was not enabled. Expected: {0}. Got:\n{1}".format(expected_cpu_accounting, fileutil.read_file(extension_service_cpu_accounting)))

            self.assertTrue(os.path.exists(extension_service_cpu_quota), "{0} was not created".format(extension_service_cpu_quota))
            self.assertTrue(
                fileutil.findre_in_file(extension_service_cpu_quota, expected_cpu_quota_percentage),
                "CPUQuota was not set. Expected: {0}. Got:\n{1}".format(expected_cpu_quota_percentage, fileutil.read_file(extension_service_cpu_quota)))

    def test_it_should_set_extension_services_when_quotas_not_defined(self):
        service_list = [
            {
                "name": "extension.service"
            }
        ]
        with self._get_cgroup_configurator() as configurator:
            # get the paths to the mocked files
            extension_service_cpu_accounting = configurator.mocks.get_mapped_path(UnitFilePaths.extension_service_cpu_accounting)
            extension_service_cpu_quota = configurator.mocks.get_mapped_path(UnitFilePaths.extension_service_cpu_quota)
            extension_service_memory_accounting = configurator.mocks.get_mapped_path(UnitFilePaths.extension_service_memory_accounting)
            extension_service_memory_quota = configurator.mocks.get_mapped_path(UnitFilePaths.extension_service_memory_limit)

            configurator.set_extension_services_cpu_memory_quota(service_list)

            self.assertTrue(os.path.exists(extension_service_cpu_accounting),
                            "{0} was not created".format(extension_service_cpu_accounting))
            self.assertFalse(os.path.exists(extension_service_cpu_quota),
                            "{0} should not have been created during setup".format(extension_service_cpu_quota))

            self.assertTrue(os.path.exists(extension_service_memory_accounting),
                            "{0} was not created".format(extension_service_memory_accounting))
            self.assertFalse(os.path.exists(extension_service_memory_quota),
                            "{0} should not have been created during setup".format(extension_service_memory_quota))

    def test_it_should_start_tracking_extension_services_cgroups(self):
        service_list = [
            {
                "name": "extension.service"
            }
        ]
        with self._get_cgroup_configurator() as configurator:
            configurator.start_tracking_extension_services_cgroups(service_list)

        tracked = CGroupsTelemetry._tracked

        self.assertTrue(
            any(cg for cg in tracked.values() if cg.name == 'extension.service' and 'cpu' in cg.path),
            "The extension service's CPU is not being tracked")
        self.assertTrue(
            any(cg for cg in tracked.values() if cg.name == 'extension.service' and 'memory' in cg.path),
            "The extension service's Memory is not being tracked")

    def test_it_should_stop_tracking_extension_services_cgroups(self):
        service_list = [
            {
                "name": "extension.service"
            }
        ]

        with self._get_cgroup_configurator() as configurator:
            with patch("os.path.exists") as mock_path:
                mock_path.return_value = True
                CGroupsTelemetry.track_cgroup(CpuCgroup('extension.service', '/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service'))
                configurator.stop_tracking_extension_services_cgroups(service_list)

                tracked = CGroupsTelemetry._tracked

                self.assertFalse(
                    any(cg for cg in tracked.values() if cg.name == 'extension.service' and 'cpu' in cg.path),
                    "The extension service's CPU is being tracked")
                self.assertFalse(
                    any(cg for cg in tracked.values() if cg.name == 'extension.service' and 'memory' in cg.path),
                    "The extension service's Memory is being tracked")

    def test_it_should_remove_extension_services_drop_in_files(self):
        service_list = [
            {
                "name": "extension.service",
                "cpuQuotaPercentage": 5
            }
        ]
        with self._get_cgroup_configurator() as configurator:
            extension_service_cpu_accounting = configurator.mocks.get_mapped_path(
            UnitFilePaths.extension_service_cpu_accounting)
            extension_service_cpu_quota = configurator.mocks.get_mapped_path(UnitFilePaths.extension_service_cpu_quota)
            extension_service_memory_accounting = configurator.mocks.get_mapped_path(
            UnitFilePaths.extension_service_memory_accounting)
            configurator.remove_extension_services_drop_in_files(service_list)
            self.assertFalse(os.path.exists(extension_service_cpu_accounting),
                            "{0} should not have been created".format(extension_service_cpu_accounting))
            self.assertFalse(os.path.exists(extension_service_cpu_quota),
                            "{0} should not have been created".format(extension_service_cpu_quota))
            self.assertFalse(os.path.exists(extension_service_memory_accounting),
                            "{0} should not have been created".format(extension_service_memory_accounting))

    def test_it_should_start_tracking_unit_cgroups(self):

        with self._get_cgroup_configurator() as configurator:
            configurator.start_tracking_unit_cgroups("extension.service")

        tracked = CGroupsTelemetry._tracked

        self.assertTrue(
            any(cg for cg in tracked.values() if cg.name == 'extension.service' and 'cpu' in cg.path),
            "The extension service's CPU is not being tracked")

        self.assertTrue(
            any(cg for cg in tracked.values() if cg.name == 'extension.service' and 'memory' in cg.path),
            "The extension service's Memory is not being tracked")

    def test_it_should_stop_tracking_unit_cgroups(self):

        def side_effect(path):
            if path == '/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service':
                return True
            return False

        with self._get_cgroup_configurator() as configurator:
            with patch("os.path.exists") as mock_path:
                mock_path.side_effect = side_effect
                CGroupsTelemetry._tracked['/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service'] = \
                    CpuCgroup('extension.service', '/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service')
                configurator.stop_tracking_unit_cgroups("extension.service")

                tracked = CGroupsTelemetry._tracked

                self.assertFalse(
                    any(cg for cg in tracked.values() if cg.name == 'extension.service' and 'cpu' in cg.path),
                    "The extension service's CPU is being tracked")
                self.assertFalse(
                    any(cg for cg in tracked.values() if cg.name == 'extension.service' and 'memory' in cg.path),
                    "The extension service's Memory is being tracked")

    def test_check_processes_in_agent_cgroup_should_raise_a_cgroups_exception_when_there_are_unexpected_processes_in_the_agent_cgroup(self):
        with self._get_cgroup_configurator() as configurator:
            pass  # release the mocks used to create the test CGroupConfigurator so that they do not conflict the mock Popen below

        # The test script recursively creates a given number of descendant processes, then it blocks until the
        # 'stop_file' exists. It produces an output file containing the PID of each descendant process.
        test_script = os.path.join(self.tmp_dir, "create_processes.sh")
        stop_file = os.path.join(self.tmp_dir, "create_processes.stop")
        AgentTestCase.create_script(test_script, """
#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
    echo "Usage: $0 <output_file> <count>"
    exit 1
fi

echo $$ >> $1

if [[ $2 > 1 ]]; then
    $0 $1 $(($2 - 1))
else
    timeout 30s /usr/bin/env bash -c "while ! [[ -f {0} ]]; do sleep 0.25s; done"
fi

exit 0
""".format(stop_file))

        number_of_descendants = 3

        def wait_for_processes(processes_file):
            def _all_present():
                if os.path.exists(processes_file):
                    with open(processes_file, "r") as file_stream:
                        _all_present.processes = [int(process) for process in file_stream.read().split()]
                return len(_all_present.processes) >= number_of_descendants
            _all_present.processes = []

            if not wait_for(_all_present):
                raise Exception("Timeout waiting for processes. Expected {0}; got: {1}".format(
                    number_of_descendants, format_processes(_all_present.processes)))

            return _all_present.processes

        threads = []

        try:
            #
            # Start the processes that will be used by the test. We use two sets of processes: the first set simulates a command executed by the agent
            # (e.g. iptables) and its child processes, if any. The second set of processes simulates an extension.
            #
            agent_command_output = os.path.join(self.tmp_dir, "agent_command.pids")
            agent_command = threading.Thread(target=lambda: shellutil.run_command([test_script, agent_command_output, str(number_of_descendants)]))
            agent_command.start()
            threads.append(agent_command)
            agent_command_processes = wait_for_processes(agent_command_output)

            extension_output = os.path.join(self.tmp_dir, "extension.pids")

            def start_extension():
                original_sleep = time.sleep
                original_popen = subprocess.Popen

                # Extensions are started using systemd-run; mock Popen to remove the call to systemd-run; the test script creates a couple of
                # child processes, which would simulate the extension's processes.
                def mock_popen(command, *args, **kwargs):
                    match = re.match(r"^systemd-run --property=CPUAccounting=no --property=MemoryAccounting=no --unit=[^\s]+ --scope --slice=[^\s]+ (.+)", command)
                    is_systemd_run = match is not None
                    if is_systemd_run:
                        command = match.group(1)
                    process = original_popen(command, *args, **kwargs)
                    if is_systemd_run:
                        start_extension.systemd_run_pid = process.pid
                    return process

                with patch('time.sleep', side_effect=lambda _: original_sleep(0.1)):  # start_extension_command has a small delay; skip it
                    with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", side_effect=mock_popen):
                        with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stdout:
                            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as stderr:
                                configurator.start_extension_command(
                                    extension_name="TestExtension",
                                    command="{0} {1} {2}".format(test_script, extension_output, number_of_descendants),
                                    cmd_name="test",
                                    timeout=30,
                                    shell=True,
                                    cwd=self.tmp_dir,
                                    env={},
                                    stdout=stdout,
                                    stderr=stderr)
            start_extension.systemd_run_pid = None

            extension = threading.Thread(target=start_extension)
            extension.start()
            threads.append(extension)
            extension_processes = wait_for_processes(extension_output)

            #
            # check_processes_in_agent_cgroup uses shellutil and the cgroups api to get the commands that are currently running;
            # wait for all the processes to show up
            #
            if not wait_for(lambda: len(shellutil.get_running_commands()) > 0 and len(configurator._cgroups_api.get_systemd_run_commands()) > 0):
                raise Exception("Timeout while attempting to track the child commands")

            #
            # Verify that check_processes_in_agent_cgroup raises when there are unexpected processes in the agent's cgroup.
            #
            # For the agent's processes, we use the current process and its parent (in the actual agent these would be the daemon and the extension
            # handler), and the commands started by the agent.
            #
            # For other processes, we use process 1, a process that already completed, and an extension. Note that extensions are started using
            # systemd-run and the process for that commands belongs to the agent's cgroup but the processes for the extension should be in a
            # different cgroup
            #
            def get_completed_process():
                random.seed()
                completed = random.randint(1000, 10000)
                while os.path.exists("/proc/{0}".format(completed)):  # ensure we do not use an existing process
                    completed = random.randint(1000, 10000)
                return completed

            agent_processes = [os.getppid(), os.getpid()] + agent_command_processes + [start_extension.systemd_run_pid]
            other_processes = [1, get_completed_process()] + extension_processes

            with patch("azurelinuxagent.ga.cgroupconfigurator.CGroupsApi.get_processes_in_cgroup", return_value=agent_processes + other_processes):
                with self.assertRaises(CGroupsException) as context_manager:
                    configurator._check_processes_in_agent_cgroup()

                # The list of processes in the message is an array of strings: "['foo', ..., 'bar']"
                message = ustr(context_manager.exception)
                search = re.search(r'unexpected processes: \[(?P<processes>.+)\]', message)
                self.assertIsNotNone(search, "The event message is not in the expected format: {0}".format(message))
                reported = search.group('processes').split(',')

                self.assertEqual(
                    len(other_processes), len(reported),
                    "An incorrect number of processes was reported. Expected: {0} Got: {1}".format(format_processes(other_processes), reported))
                for pid in other_processes:
                    self.assertTrue(
                        any("[PID: {0}]".format(pid) in reported_process for reported_process in reported),
                        "Process {0} was not reported. Got: {1}".format(format_processes([pid]), reported))
        finally:
            # create the file that stops the test processes and wait for them to complete
            open(stop_file, "w").close()
            for thread in threads:
                thread.join(timeout=5)

    def test_check_agent_throttled_time_should_raise_a_cgroups_exception_when_the_threshold_is_exceeded(self):
        metrics = [MetricValue(MetricsCategory.CPU_CATEGORY, MetricsCounter.THROTTLED_TIME, AGENT_NAME_TELEMETRY, conf.get_agent_cpu_throttled_time_threshold() + 1)]

        with self.assertRaises(CGroupsException) as context_manager:
            CGroupConfigurator._Impl._check_agent_throttled_time(metrics)

        self.assertIn("The agent has been throttled", ustr(context_manager.exception), "An incorrect exception was raised")

    def test_check_cgroups_should_disable_cgroups_when_a_check_fails(self):
        with self._get_cgroup_configurator() as configurator:
            checks = ["_check_processes_in_agent_cgroup", "_check_agent_throttled_time"]
            for method_to_fail in checks:
                patchers = []
                try:
                    # mock 'method_to_fail' to raise an exception and the rest to do nothing
                    for method_to_mock in checks:
                        side_effect = CGroupsException(method_to_fail) if method_to_mock == method_to_fail else lambda *_: None
                        p = patch.object(configurator, method_to_mock, side_effect=side_effect)
                        patchers.append(p)
                        p.start()

                    with patch("azurelinuxagent.ga.cgroupconfigurator.add_event") as add_event:
                        configurator.enable()

                        tracked_metrics = [
                            MetricValue(MetricsCategory.CPU_CATEGORY, MetricsCounter.PROCESSOR_PERCENT_TIME, "test",
                                        10)]
                        configurator.check_cgroups(tracked_metrics)
                        if method_to_fail == "_check_processes_in_agent_cgroup":
                            self.assertFalse(configurator.enabled(), "An error in {0} should have disabled cgroups".format(method_to_fail))
                        else:
                            self.assertFalse(configurator.agent_enabled(), "An error in {0} should have disabled cgroups".format(method_to_fail))

                        disable_events = [kwargs for _, kwargs in add_event.call_args_list if kwargs["op"] == WALAEventOperation.CGroupsDisabled]
                        self.assertTrue(
                            len(disable_events) == 1,
                            "Exactly 1 event should have been emitted when {0} fails. Got: {1}".format(method_to_fail, disable_events))
                        self.assertIn(
                            "[CGroupsException] {0}".format(method_to_fail),
                            disable_events[0]["message"],
                            "The error message is not correct when {0} failed".format(method_to_fail))
                finally:
                    for p in patchers:
                        p.stop()

    def test_check_agent_memory_usage_should_raise_a_cgroups_exception_when_the_limit_is_exceeded(self):
        metrics = [MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.TOTAL_MEM_USAGE, AGENT_NAME_TELEMETRY, conf.get_agent_memory_quota() + 1),
                   MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.SWAP_MEM_USAGE, AGENT_NAME_TELEMETRY, conf.get_agent_memory_quota() + 1)]

        with self.assertRaises(AgentMemoryExceededException) as context_manager:
            with self._get_cgroup_configurator() as configurator:
                with patch("azurelinuxagent.ga.cgroup.MemoryCgroup.get_tracked_metrics") as tracked_metrics:
                    tracked_metrics.return_value = metrics
                    configurator.check_agent_memory_usage()

        self.assertIn("The agent memory limit {0} bytes exceeded".format(conf.get_agent_memory_quota()), ustr(context_manager.exception), "An incorrect exception was raised")