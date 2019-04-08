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

import json
import random

from azurelinuxagent.common.cgroups.cgroups import CGroupsTelemetry, CGroups, BASE_CGROUPS
from azurelinuxagent.common.cgroups.cgutils import CGroupsException, Cpu, Memory
from azurelinuxagent.common.version import AGENT_NAME
from azurelinuxagent.ga.utils.exthandler_utils import HandlerConfiguration, DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN, CGroupsLimits
from tests.tools import *


def consume_cpu_time():
    waste = 0
    for x in range(1, 200000):
        waste += random.random()
    return waste


def make_self_cgroups(resource_limits=None):
    """
    Build a CGroups object for the cgroup to which this process already belongs

    :return: CGroups containing this process
    :rtype: CGroups
    """

    def path_maker(hierarchy, __):
        suffix = CGroups.get_my_cgroup_path(CGroups.get_hierarchy_id('cpu'))
        return os.path.join(BASE_CGROUPS, hierarchy, suffix)

    return CGroups("inplace", path_maker, resource_limits=resource_limits)


def make_root_cgroups():
    """
    Build a CGroups object for the topmost cgroup

    :return: CGroups for most-encompassing cgroup
    :rtype: CGroups
    """

    def path_maker(hierarchy, _):
        return os.path.join(BASE_CGROUPS, hierarchy)

    return CGroups("root", path_maker)


def i_am_root():
    return os.geteuid() == 0


@skip_if_predicate_false(CGroups.enabled, "CGroups not supported in this environment")
class TestCGroups(AgentTestCase):
    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()
        CGroups.setup(True)

    def test_cgroup_utilities(self):
        """
        Test utilities for querying cgroup metadata
        """
        cpu_id = CGroups.get_hierarchy_id('cpu')
        self.assertGreater(int(cpu_id), 0)
        memory_id = CGroups.get_hierarchy_id('memory')
        self.assertGreater(int(memory_id), 0)
        self.assertNotEqual(cpu_id, memory_id)

    def test_telemetry_inplace(self):
        """
        Test raw measures and basic statistics for the cgroup in which this process is currently running.
        """
        cg = make_self_cgroups()
        self.assertIn('cpu', cg.cgroups)
        self.assertIn('memory', cg.cgroups)
        ct = CGroupsTelemetry("test", cg)
        cpu = Cpu(ct)
        self.assertGreater(cpu.current_system_cpu, 0)

        consume_cpu_time()  # Eat some CPU
        cpu.update()

        self.assertGreater(cpu.current_cpu_total, cpu._previous_cpu_total)
        self.assertGreater(cpu.current_system_cpu, cpu._previous_system_cpu)

        percent_used = cpu.get_cpu_percent()
        self.assertGreater(percent_used, 0)

    def test_telemetry_in_place_leaf_cgroup(self):
        """
        Ensure this leaf (i.e. not root of cgroup tree) cgroup has distinct metrics from the root cgroup.
        """
        # Does nothing on systems where the default cgroup for a randomly-created process (like this test invocation)
        # is the root cgroup.
        cg = make_self_cgroups()
        root = make_root_cgroups()
        if cg.cgroups['cpu'] != root.cgroups['cpu']:
            ct = CGroupsTelemetry("test", cg)
            cpu = Cpu(ct)
            self.assertLess(cpu.current_cpu_total, cpu.current_system_cpu)

            consume_cpu_time()  # Eat some CPU
            time.sleep(1)  # Generate some idle time
            cpu.update()
            self.assertLess(cpu.current_cpu_total, cpu.current_system_cpu)

    def exercise_telemetry_instantiation(self, test_cgroup, resource_limits_passed=False):
        test_extension_name = test_cgroup.name
        CGroupsTelemetry.track_cgroup(test_cgroup)

        try:
            self.assertIn('cpu', test_cgroup.cgroups)
            self.assertIn('memory', test_cgroup.cgroups)
            self.assertTrue(CGroupsTelemetry.is_tracked(test_extension_name))
            consume_cpu_time()
            time.sleep(1)
            metrics, limits = CGroupsTelemetry.collect_all_tracked()
            my_metrics = metrics[test_extension_name]
            self.assertEqual(len(my_metrics), 2)
            for item in my_metrics:
                metric_family, metric_name, metric_value = item
                if metric_family == "Process":
                    self.assertEqual(metric_name, "% Processor Time")
                    self.assertGreater(metric_value, 0.0)
                elif metric_family == "Memory":
                    self.assertEqual(metric_name, "Total Memory Usage")
                    self.assertGreater(metric_value, 100000)
                else:
                    self.fail("Unknown metric {0}/{1} value {2}".format(metric_family, metric_name, metric_value))

            my_limits = limits[test_extension_name]
            if resource_limits_passed:
                self.assertIsInstance(my_limits, CGroupsLimits, msg="is not the correct instance")
                self.assertGreater(my_limits.cpu_limit, 0.0)
                self.assertGreater(my_limits.memory_limit, 0.0)
            else:
                self.assertIsNone(my_limits)
        finally:
            CGroupsTelemetry.stop_tracking(test_cgroup.name)

    @skip_if_predicate_false(i_am_root, "Test does not run when non-root")
    def test_telemetry_instantiation_as_superuser(self):
        """
        Tracking a new cgroup for an extension; collect all metrics.
        """
        # Record initial state
        initial_cgroup = make_self_cgroups()

        # Put the process into a different cgroup, consume some resources, ensure we see them end-to-end
        test_cgroup = CGroups.for_extension("agent_unittest")
        test_cgroup.add(os.getpid())
        self.assertNotEqual(initial_cgroup.cgroups['cpu'], test_cgroup.cgroups['cpu'])
        self.assertNotEqual(initial_cgroup.cgroups['memory'], test_cgroup.cgroups['memory'])

        self.exercise_telemetry_instantiation(test_cgroup)

        # Restore initial state
        CGroupsTelemetry.stop_tracking("agent_unittest")
        initial_cgroup.add(os.getpid())

    @skip_if_predicate_true(i_am_root, "Test does not run when root")
    def test_telemetry_instantiation_as_normal_user(self):
        """
        Tracking an existing cgroup for an extension; collect all metrics.
        """
        self.exercise_telemetry_instantiation(make_self_cgroups())

    @skip_if_predicate_true(i_am_root, "Test does not run when root")
    @patch("azurelinuxagent.common.conf.get_cgroups_enforce_limits")
    @patch("azurelinuxagent.common.cgroups.cgroups.CGroups.set_cpu_limit")
    @patch("azurelinuxagent.common.cgroups.cgroups.CGroups.set_memory_limit")
    @patch("azurelinuxagent.common.cgroups.cgroups.CGroups.set_memory_oom_flag")
    def test_telemetry_instantiation_as_normal_user_with_no_limits_passed(self, mock_get_cgroups_enforce_limits,
                                                                          mock_set_cpu_limit,
                                                                          mock_set_memory_limit,
                                                                          mock_set_memory_oom_flag):
        """
        Tracking an existing cgroup for an extension; collect all metrics.
        """
        mock_get_cgroups_enforce_limits.return_value = True

        cg = make_self_cgroups()
        cg.set_limits()
        self.exercise_telemetry_instantiation(cg)

    @skip_if_predicate_true(i_am_root, "Test does not run when root")
    @patch("azurelinuxagent.common.conf.get_cgroups_enforce_limits")
    @patch("azurelinuxagent.common.cgroups.cgroups.CGroups.set_cpu_limit")
    @patch("azurelinuxagent.common.cgroups.cgroups.CGroups.set_memory_limit")
    @patch("azurelinuxagent.common.cgroups.cgroups.CGroups.set_memory_oom_flag")
    def test_telemetry_instantiation_as_normal_user_with_limits(self, mock_get_cgroups_enforce_limits,
                                                                mock_set_cpu_limit,
                                                                mock_set_memory_limit,
                                                                mock_set_memory_oom_flag):
        """
        Tracking an existing cgroup for an extension; collect all metrics.
        """
        mock_get_cgroups_enforce_limits.return_value = True

        name = "ExampleHandlerLinux"
        data = '''{
              "name": "ExampleHandlerLinux",
              "version": 1.0,
              "handlerConfiguration": {
                "linux": {
                  "resources": {
                    "cpu": [
                      {
                        "cores": 2,
                        "limit_percentage": 25
                      },
                      {
                        "cores": 8,
                        "limit_percentage": 20
                      },
                      {
                        "cores": -1,
                        "limit_percentage": 15
                      }
                    ]
                  }
                }
              }
            }
            '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        cg = make_self_cgroups(resource_limits=handler_config.resource_limits)
        cg.set_limits()
        self.exercise_telemetry_instantiation(cg, resource_limits_passed=True)

    def test_cpu_telemetry(self):
        """
        Test Cpu telemetry class
        """
        cg = make_self_cgroups()
        self.assertIn('cpu', cg.cgroups)
        ct = CGroupsTelemetry('test', cg)
        self.assertIs(cg, ct.cgroup)
        cpu = Cpu(ct)
        self.assertIs(cg, cpu.cgt.cgroup)
        ticks_before = cpu.current_cpu_total
        consume_cpu_time()
        time.sleep(1)
        cpu.update()
        ticks_after = cpu.current_cpu_total
        self.assertGreater(ticks_after, ticks_before)
        p2 = cpu.get_cpu_percent()
        self.assertGreater(p2, 0)
        # when running under PyCharm, this is often > 100
        # on a multi-core machine
        self.assertLess(p2, 200)

    def test_memory_telemetry(self):
        """
        Test Memory telemetry class
        """
        cg = make_self_cgroups()
        raw_usage_file_contents = cg.get_file_contents('memory', 'memory.usage_in_bytes')
        self.assertIsNotNone(raw_usage_file_contents)
        self.assertGreater(len(raw_usage_file_contents), 0)
        self.assertIn('memory', cg.cgroups)
        ct = CGroupsTelemetry('test', cg)
        self.assertIs(cg, ct.cgroup)
        memory = Memory(ct)
        usage_in_bytes = memory.get_memory_usage()
        self.assertGreater(usage_in_bytes, 100000)

    def test_format_memory_value(self):
        """
        Test formatting of memory amounts into human-readable units
        """
        self.assertEqual(-1, CGroups._format_memory_value('bytes', None))
        self.assertEqual(2048, CGroups._format_memory_value('kilobytes', 2))
        self.assertEqual(0, CGroups._format_memory_value('kilobytes', 0))
        self.assertEqual(2048000, CGroups._format_memory_value('kilobytes', 2000))
        self.assertEqual(2048 * 1024, CGroups._format_memory_value('megabytes', 2))
        self.assertEqual((1024 + 512) * 1024 * 1024, CGroups._format_memory_value('gigabytes', 1.5))
        self.assertRaises(CGroupsException, CGroups._format_memory_value, 'KiloBytes', 1)

    @patch('azurelinuxagent.common.event.add_event')
    @patch('azurelinuxagent.common.conf.get_cgroups_enforce_limits')
    @patch('azurelinuxagent.common.cgroups.cgroups.CGroups.set_memory_oom_flag')
    @patch('azurelinuxagent.common.cgroups.cgroups.CGroups.set_memory_limit')
    @patch('azurelinuxagent.common.cgroups.cgroups.CGroups.set_cpu_limit')
    @patch('azurelinuxagent.common.cgroups.cgroups.CGroups._try_mkdir')
    def assert_limits(self, _, patch_set_cpu, patch_set_memory_limit, patch_set_memory_oom_flag,
                      patch_get_enforce, patch_add_event, ext_name, expected_cpu_limit,
                      expected_memory_limit=None, limits_enforced=True, exception_raised=False,
                      resource_limits=None, set_memory_oom_flag_called=True):

        should_limit = expected_cpu_limit > 0
        patch_get_enforce.return_value = limits_enforced

        if exception_raised:
            patch_set_memory_limit.side_effect = CGroupsException('set_memory_limit error')

        try:
            cg = CGroups.for_extension(ext_name, resource_limits)
            cg.set_limits()
            if exception_raised:
                self.fail('exception expected')
        except CGroupsException:
            if not exception_raised:
                self.fail('exception not expected')

        self.assertEqual(should_limit, patch_set_cpu.called)
        self.assertEqual(should_limit, patch_set_memory_limit.called)
        self.assertEqual(should_limit & set_memory_oom_flag_called, patch_set_memory_oom_flag.called)
        self.assertEqual(should_limit, patch_add_event.called)

        if should_limit:
            actual_cpu_limit = patch_set_cpu.call_args[0][0]
            actual_memory_limit = patch_set_memory_limit.call_args[0][0]
            event_kw_args = patch_add_event.call_args[1]

            self.assertEqual(expected_cpu_limit, actual_cpu_limit)
            self.assertTrue(actual_memory_limit >= DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)
            self.assertEqual(actual_memory_limit, expected_memory_limit)
            self.assertEqual(event_kw_args['op'], 'SetCGroupsLimits')
            self.assertEqual(event_kw_args['is_success'], not exception_raised)
            self.assertTrue('{0}%'.format(expected_cpu_limit) in event_kw_args['message'])
            self.assertTrue(ext_name in event_kw_args['message'])
            self.assertEqual(exception_raised, 'set_memory_limit error' in event_kw_args['message'])

    def test_limits(self):
        not_expected_to_set_limits = -1
        self.assert_limits(ext_name="normal_extension", expected_cpu_limit=not_expected_to_set_limits,
                           limits_enforced=False)
        self.assert_limits(ext_name="customscript_extension", expected_cpu_limit=not_expected_to_set_limits)
        self.assert_limits(ext_name=AGENT_NAME, expected_cpu_limit=not_expected_to_set_limits)
        self.assert_limits(ext_name="normal_extension", expected_cpu_limit=not_expected_to_set_limits,
                           limits_enforced=False)
        self.assert_limits(ext_name=AGENT_NAME, expected_cpu_limit=not_expected_to_set_limits, limits_enforced=False)
        self.assert_limits(ext_name="normal_extension", expected_cpu_limit=not_expected_to_set_limits,
                           exception_raised=False,
                           set_memory_oom_flag_called=False)

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_total_mem")
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores")
    def test_limits_with_resource_configuration(self, patch_get_processor_cores, patch_get_total_mem):
        handler_config_json = '''{
          "name": "ExampleHandlerLinux",
          "version": 1.0,
          "handlerConfiguration": {
            "linux": {
              "resources": {
                "cpu": [
                  {
                    "cores": 2,
                    "limit_percentage": 25
                  },
                  {
                    "cores": 8,
                    "limit_percentage": 20
                  },
                  {
                    "cores": -1,
                    "limit_percentage": 15
                  }
                ],
                "memory": {
                  "max_limit_percentage": 20,
                  "max_limit_MBs": 1000,
                  "memory_pressure_warning": "low",
                  "memory_oom_kill": "enabled"
                }
              }
            },
            "windows": {}
          }
        }'''
        not_expected_to_set_limits = -1

        patch_get_processor_cores.return_value = 1
        patch_get_total_mem.return_value = 512
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name="customscript_extension", expected_cpu_limit=not_expected_to_set_limits,
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

        patch_get_processor_cores.return_value = 2
        patch_get_total_mem.return_value = 512
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name=AGENT_NAME, expected_cpu_limit=float(25),
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

        patch_get_processor_cores.return_value = 3
        patch_get_total_mem.return_value = 5120
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name="normal_extension", expected_cpu_limit=not_expected_to_set_limits,
                           limits_enforced=False,
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=1000)

        patch_get_processor_cores.return_value = 8
        patch_get_total_mem.return_value = 5120
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name=AGENT_NAME, expected_cpu_limit=not_expected_to_set_limits,
                           limits_enforced=False,
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=1000)

        patch_get_processor_cores.return_value = 10
        patch_get_total_mem.return_value = 1500
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name="normal_extension", expected_cpu_limit=float(15), exception_raised=True,
                           resource_limits=handler_config.get_resource_limits(),
                           set_memory_oom_flag_called=False,
                           expected_memory_limit=300) # 20% of total ram

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_total_mem")
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores")
    def test_limits_with_cpu_resource_configuration(self, patch_get_processor_cores, patch_get_total_mem):
        handler_config_json = '''{
          "name": "ExampleHandlerLinux",
          "version": 1.0,
          "handlerConfiguration": {
            "linux": {
              "resources": {
                "cpu": [
                  {
                    "cores": 2,
                    "limit_percentage": 25
                  },
                  {
                    "cores": 8,
                    "limit_percentage": 20
                  },
                  {
                    "cores": -1,
                    "limit_percentage": 15
                  }
                ]
              }
            },
            "windows": {}
          }
        }'''
        not_expected_to_set_limits = -1
        patch_get_total_mem.return_value = 2056
        expected_memory = CGroupsLimits.get_default_memory_limits("x")

        patch_get_processor_cores.return_value = 1
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name="customscript_extension",
                           expected_cpu_limit=not_expected_to_set_limits,
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=expected_memory)

        patch_get_processor_cores.return_value = 2
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name=AGENT_NAME, expected_cpu_limit=float(25),
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=expected_memory)

        patch_get_processor_cores.return_value = 3
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name="normal_extension", expected_cpu_limit=not_expected_to_set_limits,
                           limits_enforced=False,
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=expected_memory)

        patch_get_processor_cores.return_value = 8
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name=AGENT_NAME, expected_cpu_limit=not_expected_to_set_limits,
                           limits_enforced=False,
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=expected_memory)

        patch_get_processor_cores.return_value = 10
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name="normal_extension", expected_cpu_limit=float(15), exception_raised=True,
                           resource_limits=handler_config.get_resource_limits(),
                           set_memory_oom_flag_called=False,
                           expected_memory_limit=expected_memory)

    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_total_mem")
    @patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores")
    def test_limits_with_memory_resource_configuration(self, patch_get_processor_cores, patch_get_total_mem):
        handler_config_json = '''{
          "name": "ExampleHandlerLinux",
          "version": 1.0,
          "handlerConfiguration": {
            "linux": {
              "resources": {
                "memory": {
                  "max_limit_percentage": 20,
                  "max_limit_MBs": 1000,
                  "memory_pressure_warning": "low",
                  "memory_oom_kill": "enabled"
                }
              }
            },
            "windows": {}
          }
        }'''
        not_expected_to_set_limits = -1

        patch_get_processor_cores.return_value = 1
        patch_get_total_mem.return_value = 512
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name="customscript_extension", expected_cpu_limit=not_expected_to_set_limits,
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

        # Expecting default 40% CPU as no CPU passed.
        patch_get_processor_cores.return_value = 2
        patch_get_total_mem.return_value = 1024
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name=AGENT_NAME, expected_cpu_limit=float(40),
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

        patch_get_processor_cores.return_value = 3
        patch_get_total_mem.return_value = 512
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name="normal_extension", expected_cpu_limit=not_expected_to_set_limits,
                           limits_enforced=False,
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

        patch_get_processor_cores.return_value = 8
        patch_get_total_mem.return_value = 1024
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name=AGENT_NAME, expected_cpu_limit=not_expected_to_set_limits,
                           limits_enforced=False,
                           resource_limits=handler_config.get_resource_limits(),
                           expected_memory_limit=DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

        patch_get_processor_cores.return_value = 10
        patch_get_total_mem.return_value = 10000.0
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name="normal_extension",
                           expected_cpu_limit=float(40),
                           resource_limits=handler_config.get_resource_limits(),
                           set_memory_oom_flag_called=True,
                           expected_memory_limit=1000)

        patch_get_processor_cores.return_value = 10
        patch_get_total_mem.return_value = 512
        handler_config = HandlerConfiguration(json.loads(handler_config_json))
        self.assert_limits(ext_name="normal_extension", expected_cpu_limit=float(40), exception_raised=True,
                           resource_limits=handler_config.get_resource_limits(),
                           set_memory_oom_flag_called=False,
                           expected_memory_limit=DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

