# Microsoft Azure Linux Agent
#
# Copyright 2019 Microsoft Corporation
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


import json

from mock import patch

from azurelinuxagent.common.protocol.restapi import ExtHandler
from azurelinuxagent.ga.exthandlers import ExtHandlerInstance

from azurelinuxagent.ga.utils.exthandler_utils import CGroupsLimits, AGENT_CGROUP_NAME, HandlerConfiguration, \
    DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN
from tests.ga.test_extension import ExtensionTestCase
from tests.tools import AgentTestCase, load_data_path


@patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_total_mem", return_value=1024)
class TestCGroupsLimits(AgentTestCase):
    def test_no_limits_passed(self, patch_get_total_mem):
        cgroup_name = "test_cgroup"
        limits = CGroupsLimits(cgroup_name)
        self.assertEqual(limits.cpu_limit, CGroupsLimits.get_default_cpu_limits(cgroup_name))
        self.assertEqual(limits.memory_limit, CGroupsLimits.get_default_memory_limits(cgroup_name))

        limits = CGroupsLimits(None)
        self.assertEqual(limits.cpu_limit, CGroupsLimits.get_default_cpu_limits(cgroup_name))
        self.assertEqual(limits.memory_limit, CGroupsLimits.get_default_memory_limits(cgroup_name))

    def test_agent_name_limits_passed(self, patch_get_total_mem):
        cgroup_name = AGENT_CGROUP_NAME
        limits = CGroupsLimits(cgroup_name)
        self.assertEqual(limits.cpu_limit, CGroupsLimits.get_default_cpu_limits(cgroup_name))
        self.assertEqual(limits.memory_limit, CGroupsLimits.get_default_memory_limits(cgroup_name))

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
                }
                '''
        handler_config = HandlerConfiguration(json.loads(data))
        resource_config = handler_config.get_resource_configurations()

        with patch(
                "azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores") as patch_get_processor_cores:
            total_ram = 1024
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 20
            expected_memory_limit = 256  # .2 of total ram is lower than default, reset to default.

            cgroup_name = AGENT_CGROUP_NAME
            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)

            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)

    def test_with_valid_cpu_memory_limits_passed(self, patch_get_total_mem):
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
        }
        '''
        handler_config = HandlerConfiguration(json.loads(data))
        resource_config = handler_config.get_resource_configurations()
        cgroup_name = "test_cgroup"
        expected_memory_flags = {"memory_pressure_warning": "low", "memory_oom_kill": "enabled"}

        with patch(
                "azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores") as patch_get_processor_cores:
            total_ram = 1024
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 20
            expected_memory_limit = 256  # .2 of total ram is lower than default, reset to default.

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 512
            patch_get_processor_cores.return_value = 2
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 25
            expected_memory_limit = 256  # .2 of total ram is lower than default, reset to default.

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 256
            patch_get_processor_cores.return_value = 1
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 25
            expected_memory_limit = 256  # .2 of total ram is lower than default, reset to default.

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 2048
            patch_get_processor_cores.return_value = 16
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 15
            expected_memory_limit = total_ram * 0.2  # 20 %

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 40960
            patch_get_processor_cores.return_value = 32
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 15
            expected_memory_limit = 1000  # 20 %

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

    def test_with_valid_cpu_limits_passed(self, patch_get_total_mem):
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
            },
            "windows": {}
          }
        }
        '''
        handler_config = HandlerConfiguration(json.loads(data))
        resource_config = handler_config.get_resource_configurations()

        cgroup_name = "test_cgroup"
        expected_memory_flags = CGroupsLimits.get_default_memory_flags()

        with patch(
                "azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores") as patch_get_processor_cores:

            total_ram = 1024
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 20
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 512
            patch_get_processor_cores.return_value = 2
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 25
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 256
            patch_get_processor_cores.return_value = 1
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 25
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 2048
            patch_get_processor_cores.return_value = 16
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 15
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 40960
            patch_get_processor_cores.return_value = 32
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 15
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

    def test_with_valid_memory_limits_passed(self, patch_get_total_mem):
        data = '''{
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
        }
        '''
        handler_config = HandlerConfiguration(json.loads(data))
        resource_config = handler_config.get_resource_configurations()
        cgroup_name = "test_cgroup"
        expected_memory_flags = {"memory_pressure_warning": "low", "memory_oom_kill": "enabled"}

        with patch(
                "azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores") as patch_get_processor_cores:

            total_ram = 1024
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = max(total_ram * 0.2, DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 512
            patch_get_processor_cores.return_value = 2
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = max(total_ram * 0.2, DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 256
            patch_get_processor_cores.return_value = 1
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = max(total_ram * 0.2, DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 2048
            patch_get_processor_cores.return_value = 16
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = max(total_ram * 0.2, DEFAULT_MEM_LIMIT_MIN_MB_FOR_EXTN)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 40960
            patch_get_processor_cores.return_value = 32
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = 1000  # 20 %

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

        data = '''{
                  "name": "ExampleHandlerLinux",
                  "version": 1.0,
                  "handlerConfiguration": {
                    "linux": {
                      "resources": {
                        "memory": {
                          "max_limit_percentage": 100,
                          "max_limit_MBs": 512
                        }
                      }
                    },
                    "windows": {}
                  }
                }
                '''
        handler_config = HandlerConfiguration(json.loads(data))
        resource_config = handler_config.get_resource_configurations()
        cgroup_name = "test_cgroup"
        expected_memory_flags = CGroupsLimits.get_default_memory_flags()

        with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores") as \
                patch_get_processor_cores:

            total_ram = 256
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = total_ram * 1  # min of %age of totalram vs max gives total ram edge here.

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 1024
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = 512  # Even if asked 100%, capped by max

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

        data = '''{
                  "name": "ExampleHandlerLinux",
                  "version": 1.0,
                  "handlerConfiguration": {
                    "linux": {
                      "resources": {
                        "memory": {
                          "max_limit_percentage": 10,
                          "max_limit_MBs": 2500,
                          "memory_pressure_warning": "critical"
                        }
                      }
                    },
                    "windows": {}
                  }
                }
                '''
        handler_config = HandlerConfiguration(json.loads(data))
        resource_config = handler_config.get_resource_configurations()
        cgroup_name = "test_cgroup"
        expected_memory_flags = {"memory_pressure_warning": "critical", "memory_oom_kill": "disabled"}

        with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores") as \
                patch_get_processor_cores:

            total_ram = 256
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = total_ram * 1  # min of %age of totalram vs max gives total ram edge here.

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 1024
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = 256  # It asked for 10% of 1024, which is lower than default, thus you get
            # default.

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

        data = '''{
                      "name": "ExampleHandlerLinux",
                      "version": 1.0,
                      "handlerConfiguration": {
                        "linux": {
                          "resources": {
                            "memory": {
                              "max_limit_percentage": 10,
                              "max_limit_MBs": 2500,
                              "memory_oom_kill": "enabled"
                            }
                          }
                        },
                        "windows": {}
                      }
                    }
                    '''
        handler_config = HandlerConfiguration(json.loads(data))
        resource_config = handler_config.get_resource_configurations()
        cgroup_name = "test_cgroup"
        expected_memory_flags = {"memory_pressure_warning": None, "memory_oom_kill": "enabled"}

        with patch("azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores") as \
                patch_get_processor_cores:

            total_ram = 256
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = 256  # Default Value

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 1024
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = 256  # It asked for 10% of 1024, which is lower than default, thus you get
            # default.

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

    def test_with_invalid_cpu_memory_limits_passed(self, patch_get_total_mem):
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
                  }
                ],
                "memory": {
                  "max_limit_percentage": 20,
                  "memory_pressure_warning": "low",
                  "memory_oom_kill": "enabled"
                }
              }
            },
            "windows": {}
          }
        }
        '''
        handler_config = HandlerConfiguration(json.loads(data))
        resource_config = handler_config.get_resource_configurations()
        cgroup_name = "test_cgroup"

        with patch(
                "azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores") as patch_get_processor_cores:

            total_ram = 1024
            patch_get_processor_cores.return_value = 0  # misconfigured get_processor_cores case.
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = 40  # Default Value of 40 %
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)

            total_ram = 2048
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)

            total_ram = 512
            patch_get_processor_cores.return_value = 2
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)

            total_ram = 256
            patch_get_processor_cores.return_value = 1
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)

            total_ram = 2048
            patch_get_processor_cores.return_value = 16
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)

            total_ram = 40960
            patch_get_processor_cores.return_value = 32
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)

    def test_with_no_cpu_memory_limits_passed(self, patch_get_total_mem):
        data = '''{
          "name": "ExampleHandlerLinux",
          "version": 1.0,
          "handlerConfiguration": {
            "linux": {
              "resources": {
              }
            },
            "windows": {}
          }
        }
        '''
        handler_config = HandlerConfiguration(json.loads(data))
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())

        resource_config = None
        cgroup_name = "test_cgroup"
        expected_memory_flags = CGroupsLimits.get_default_memory_flags()

        with patch(
                "azurelinuxagent.common.osutil.default.DefaultOSUtil.get_processor_cores") as patch_get_processor_cores:

            total_ram = 1024
            patch_get_processor_cores.return_value = 8
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 512
            patch_get_processor_cores.return_value = 2
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 256
            patch_get_processor_cores.return_value = 1
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 2048
            patch_get_processor_cores.return_value = 16
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)

            total_ram = 40960
            patch_get_processor_cores.return_value = 32
            patch_get_total_mem.return_value = total_ram

            expected_cpu_limit = CGroupsLimits.get_default_cpu_limits(cgroup_name)
            expected_memory_limit = CGroupsLimits.get_default_memory_limits(cgroup_name)

            limits = CGroupsLimits(cgroup_name, resource_configuration=resource_config)
            self.assertEqual(limits.cpu_limit, expected_cpu_limit)
            self.assertEqual(limits.memory_limit, expected_memory_limit)
            self.assertEqual(limits.memory_flags, expected_memory_flags)


class TestHandlerConfiguration(ExtensionTestCase):
    def test_handler_configuration_complete_configuration(self, *args):
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
    }
    '''
        handler_config = HandlerConfiguration(json.loads(data), name)
        resource_config = handler_config.get_resource_configurations()

        self.assertEqual(handler_config.get_name(), "ExampleHandlerLinux")
        self.assertEqual(handler_config.get_version(), 1.0)

        cpu_limits = resource_config.get_cpu_limits_for_extension().cpu_limits
        self.assertEqual(3, len(cpu_limits))

        memory_limits = resource_config.get_memory_limits_for_extension()
        self.assertEqual(memory_limits.max_limit_percentage, 20)
        self.assertEqual(memory_limits.max_limit_MBs, 1000)
        self.assertEqual(memory_limits.memory_pressure_warning, "low")
        self.assertEqual(memory_limits.memory_oom_kill, "enabled")

    def test_handler_configuration_only_cpu_configuration(self, *args):
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
        resource_config = handler_config.get_resource_configurations()

        self.assertEqual(resource_config.get_memory_limits_for_extension(), None)

        cpu_limits = resource_config.get_cpu_limits_for_extension().cpu_limits
        self.assertEqual(3, len(cpu_limits))

        data = '''{
      "name": "ExampleHandlerLinux",
      "version": 1.0,
      "handlerConfiguration": {
        "linux": {
          "resources": {
            "cpu": [
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
        resource_config = handler_config.get_resource_configurations()

        self.assertEqual(resource_config.get_memory_limits_for_extension(), None)

        cpu_limits = resource_config.get_cpu_limits_for_extension().cpu_limits
        self.assertEqual(1, len(cpu_limits))
        self.assertEqual(-1, cpu_limits[0].cores)
        self.assertEqual(15, cpu_limits[0].limit_percentage)

    def test_handler_configuration_incorrect_cpu_configuration(self, *args):
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
              }
            ]
          }
        }
      }
    }
    '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)

        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

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
                "cores": 8
              }
            ]
          }
        }
      }
    }
    '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)

        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

        data = '''{
      "name": "ExampleHandlerLinux",
      "version": 1.0,
      "handlerConfiguration": {
        "linux": {
          "resources": {
            "cpu": [
              {
                "cores": 0,
                "limit_percentage": 25
              },
              {
                "cores": -1,
                "limit_percentage": 25
              }
            ]
          }
        }
      }
    }
    '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)

        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

        data = '''{
      "name": "ExampleHandlerLinux",
      "version": 1.0,
      "handlerConfiguration": {
        "linux": {
          "resources": {
            "cpu": [
              {
                "cores": 2,
                "limit_percentage": 251
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
        self.assertIsNotNone(handler_config)

        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

        data = '''{
      "name": "ExampleHandlerLinux",
      "version": 1.0,
      "handlerConfiguration": {
        "linux": {
          "resources": {
            "cpu": [
              {
                "cores": 2,
                "limit_percentage": 0.25
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
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

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
                "limit_percentage": "15"
              }
            ]
          }
        }
      }
    }
    '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

    def test_handler_configuration_only_memory_configuration(self, *args):
        name = "ExampleHandlerLinux"
        data = '''{
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
            }
          }
        }
        '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        resource_config = handler_config.get_resource_configurations()

        self.assertEqual(resource_config.get_cpu_limits_for_extension(), None)

        memory_limits = resource_config.get_memory_limits_for_extension()
        self.assertEqual(memory_limits.max_limit_percentage, 20)
        self.assertEqual(memory_limits.max_limit_MBs, 1000)
        self.assertEqual(memory_limits.memory_pressure_warning, "low")
        self.assertEqual(memory_limits.memory_oom_kill, "enabled")

        data = '''{
          "name": "ExampleHandlerLinux",
          "version": 1.0,
          "handlerConfiguration": {
            "linux": {
              "resources": {
                "memory": {
                  "max_limit_percentage": 20,
                  "max_limit_MBs": 1000,
                  "memory_pressure_warning": "low"
                }
              }
            }
          }
        }
                '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        resource_config = handler_config.get_resource_configurations()

        memory_limits = resource_config.get_memory_limits_for_extension()
        self.assertEqual(memory_limits.max_limit_percentage, 20)
        self.assertEqual(memory_limits.max_limit_MBs, 1000)
        self.assertEqual(memory_limits.memory_pressure_warning, "low")
        self.assertEqual(memory_limits.memory_oom_kill, None)  # Default is set by CGroupsLimits class.

        data = '''{
          "name": "ExampleHandlerLinux",
          "version": 1.0,
          "handlerConfiguration": {
            "linux": {
              "resources": {
                "memory": {
                  "max_limit_percentage": 20,
                  "max_limit_MBs": 1000
                }
              }
            }
          }
        }
        '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        resource_config = handler_config.get_resource_configurations()

        memory_limits = resource_config.get_memory_limits_for_extension()
        self.assertEqual(memory_limits.max_limit_percentage, 20)
        self.assertEqual(memory_limits.max_limit_MBs, 1000)
        self.assertEqual(memory_limits.memory_pressure_warning, None)
        self.assertEqual(memory_limits.memory_oom_kill, None)  # Default is set by CGroupsLimits class.

    def test_handler_configuration_incorrect_memory_configuration(self, *args):
        name = "ExampleHandlerLinux"
        data = '''{
      "name": "ExampleHandlerLinux",
      "version": 1.0,
      "handlerConfiguration": {
        "linux": {
          "resources": {
            "memory": {
              "max_limit_percentage": 20,
              "max_limit_MBs": 1000,
              "memory_pressure_warning": "low",
              "memory_oom_kill": "enabledd"
            }
          }
        }
      }
    }
    '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

        data = '''{
      "name": "ExampleHandlerLinux",
      "version": 1.0,
      "handlerConfiguration": {
        "linux": {
          "resources": {
            "memory": {
              "max_limit_percentage": 200,
              "max_limit_MBs": 1000
            }
          }
        }
      }
    }
    '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

        data = '''{
      "name": "ExampleHandlerLinux",
      "version": 1.0,
      "handlerConfiguration": {
        "linux": {
          "resources": {
            "memory": {
              "max_limit_percentage": "20",
              "max_limit_MBs": 1000
            }
          }
        }
      }
    }
    '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

        data = '''{
      "name": "ExampleHandlerLinux",
      "version": 1.0,
      "handlerConfiguration": {
        "linux": {
          "resources": {
            "memory": {
              "max_limit_percentage": 20,
              "max_limit_MBs": "1000"
            }
          }
        }
      }
    }
    '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

    def test_handler_configuration_incorrect_configuration(self, *args):
        name = "ExampleHandlerLinux"
        data = '''{
          "name": "ExampleHandlerLinux",
          "version": 1.0,
          "handlerConfiguration": {
            "linux": {
              "resources": {
              }
            }
          }
        }
        '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

        data = '''{
                  "name": "ExampleHandlerLinux",
                  "version": 1.0,
                  "handlerConfiguration": {}
                }
                '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

        data = '''{
    "name": "ExampleHandlerLinux",
    "version": 1.0
    }
    '''
        handler_config = HandlerConfiguration(json.loads(data), name=name)
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

        # Testing to see if json.load() returns None.
        handler_config = HandlerConfiguration(None, name=name)
        self.assertIsNotNone(handler_config)
        self.assertIsNone(handler_config.get_resource_configurations())
        self.assertIsNone(handler_config.get_resource_limits())

    @patch("azurelinuxagent.ga.exthandlers.HandlerConfiguration.send_handler_configuration_event")
    def test_load_handler_configuration(self, patch_send_handler_configuration_event, *args):
        handler_name = "Not.A.Real.Extension"
        handler_version = "1.2.3"

        ext_handler = ExtHandler(handler_name)
        ext_handler.properties.version = handler_version
        ext_handler_i = ExtHandlerInstance(ext_handler, "dummy protocol")

        with patch(
                "azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_handler_configuration_file") as \
                patch_get_handler_configuration_file:
            patch_get_handler_configuration_file.return_value = load_data_path("ext/SampleHandlerConfiguration.json")
            handler_config = ext_handler_i.load_handler_configuration()
            self.assertNotEqual(handler_config, None)
            self.assertEqual(patch_send_handler_configuration_event.call_count, 0)

        with patch(
                "azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_handler_configuration_file") as \
                patch_get_handler_configuration_file:
            patch_get_handler_configuration_file.return_value = load_data_path("ext/NotPresent.json")
            handler_config = ext_handler_i.load_handler_configuration()
            self.assertEqual(handler_config, None)
            self.assertEqual(patch_send_handler_configuration_event.call_count, 0)

        with patch(
                "azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_handler_configuration_file") as \
                patch_get_handler_configuration_file:
            patch_get_handler_configuration_file.return_value = load_data_path(
                "ext/SampleMalformedHandlerConfiguration.json")
            handler_config = ext_handler_i.load_handler_configuration()
            self.assertEqual(handler_config, None)
            self.assertEqual(patch_send_handler_configuration_event.call_count, 1)

        with patch(
                "azurelinuxagent.ga.exthandlers.ExtHandlerInstance.get_handler_configuration_file") as \
                patch_get_handler_configuration_file:
            patch_get_handler_configuration_file.return_value = load_data_path(
                "ext/SampleInvalidButCorrectJsonHandlerConfiguration.json")
            handler_config = ext_handler_i.load_handler_configuration()
            self.assertNotEqual(handler_config, None)
            self.assertEqual(patch_send_handler_configuration_event.call_count, 3)
