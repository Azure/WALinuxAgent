# Copyright 2016 F5 Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
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
import socket
import time
import unittest

import azurelinuxagent.common.osutil.bigip as osutil
import azurelinuxagent.common.osutil.default as default
import azurelinuxagent.common.utils.shellutil as shellutil

from azurelinuxagent.common.exception import OSUtilError
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.osutil.bigip import BigIpOSUtil
from .test_default import osutil_get_dhcp_pid_should_return_a_list_of_pids
from tests.tools import AgentTestCase, patch # pylint: disable=wrong-import-order


class TestBigIpOSUtil_wait_until_mcpd_is_initialized(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(shellutil, "run", return_value=0)
    @patch.object(logger, "info", return_value=None)
    def test_success(self, *args):
        result = osutil.BigIpOSUtil._wait_until_mcpd_is_initialized( # pylint: disable=protected-access
            osutil.BigIpOSUtil()
        )
        self.assertEqual(result, True)

        # There are two logger calls in the mcpd wait function. The second
        # occurs after mcpd is found to be "up"
        self.assertEqual(args[0].call_count, 2)

    @patch.object(shellutil, "run", return_value=1)
    @patch.object(logger, "info", return_value=None)
    @patch.object(time, "sleep", return_value=None)
    def test_failure(self, *args): # pylint: disable=unused-argument
        self.assertRaises(
            OSUtilError,
            osutil.BigIpOSUtil._wait_until_mcpd_is_initialized, # pylint: disable=protected-access
            osutil.BigIpOSUtil()
        )


class TestBigIpOSUtil_save_sys_config(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(shellutil, "run", return_value=0)
    @patch.object(logger, "error", return_value=None)
    def test_success(self, *args):
        result = osutil.BigIpOSUtil._save_sys_config(osutil.BigIpOSUtil()) # pylint: disable=protected-access
        self.assertEqual(result, 0)
        self.assertEqual(args[0].call_count, 0)

    @patch.object(shellutil, "run", return_value=1)
    @patch.object(logger, "error", return_value=None)
    def test_failure(self, *args):
        result = osutil.BigIpOSUtil._save_sys_config(osutil.BigIpOSUtil()) # pylint: disable=protected-access
        self.assertEqual(result, 1)
        self.assertEqual(args[0].call_count, 1)


class TestBigIpOSUtil_useradd(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(osutil.BigIpOSUtil, 'get_userentry', return_value=None)
    @patch.object(shellutil, "run_command")
    def test_success(self, *args):
        args[0].return_value = (0, None)
        result = osutil.BigIpOSUtil.useradd(
            osutil.BigIpOSUtil(), 'foo', expiration=None
        )
        self.assertEqual(result, 0)

    @patch.object(osutil.BigIpOSUtil, 'get_userentry', return_value=None)
    def test_user_already_exists(self, *args):
        args[0].return_value = 'admin'
        result = osutil.BigIpOSUtil.useradd(
            osutil.BigIpOSUtil(), 'admin', expiration=None
        )
        self.assertEqual(result, None)

    @patch.object(shellutil, "run", return_value=1)
    def test_failure(self, *args): # pylint: disable=unused-argument
        self.assertRaises(
            OSUtilError,
            osutil.BigIpOSUtil.useradd,
            osutil.BigIpOSUtil(), 'foo', expiration=None
        )


class TestBigIpOSUtil_chpasswd(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(shellutil, "run_command")
    @patch.object(osutil.BigIpOSUtil, 'get_userentry', return_value=True)
    @patch.object(osutil.BigIpOSUtil, 'is_sys_user', return_value=False)
    @patch.object(osutil.BigIpOSUtil, '_save_sys_config', return_value=None)
    def test_success(self, *args):
        result = osutil.BigIpOSUtil.chpasswd(
            osutil.BigIpOSUtil(), 'admin', 'password', crypt_id=6, salt_len=10
        )
        self.assertEqual(result, 0)
        self.assertEqual(args[0].call_count, 1)
        self.assertEqual(args[0].call_count, 1)

    @patch.object(osutil.BigIpOSUtil, 'is_sys_user', return_value=True)
    def test_is_sys_user(self, *args): # pylint: disable=unused-argument
        self.assertRaises(
            OSUtilError,
            osutil.BigIpOSUtil.chpasswd,
            osutil.BigIpOSUtil(), 'admin', 'password', crypt_id=6, salt_len=10
        )

    @patch.object(shellutil, "run_get_output", return_value=(1, None))
    @patch.object(osutil.BigIpOSUtil, 'is_sys_user', return_value=False)
    def test_failed_to_set_user_password(self, *args): # pylint: disable=unused-argument
        self.assertRaises(
            OSUtilError,
            osutil.BigIpOSUtil.chpasswd,
            osutil.BigIpOSUtil(), 'admin', 'password', crypt_id=6, salt_len=10
        )

    @patch.object(shellutil, "run_get_output", return_value=(0, None))
    @patch.object(osutil.BigIpOSUtil, 'is_sys_user', return_value=False)
    @patch.object(osutil.BigIpOSUtil, 'get_userentry', return_value=None)
    def test_failed_to_get_user_entry(self, *args): # pylint: disable=unused-argument
        self.assertRaises(
            OSUtilError,
            osutil.BigIpOSUtil.chpasswd,
            osutil.BigIpOSUtil(), 'admin', 'password', crypt_id=6, salt_len=10
        )


class TestBigIpOSUtil_get_dvd_device(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(os, "listdir", return_value=['tty1','cdrom0'])
    def test_success(self, *args): # pylint: disable=unused-argument
        result = osutil.BigIpOSUtil.get_dvd_device(
            osutil.BigIpOSUtil(), '/dev'
        )
        self.assertEqual(result, '/dev/cdrom0')

    @patch.object(os, "listdir", return_value=['foo', 'bar'])
    def test_failure(self, *args): # pylint: disable=unused-argument
        self.assertRaises(
            OSUtilError,
            osutil.BigIpOSUtil.get_dvd_device,
            osutil.BigIpOSUtil(), '/dev'
        )


class TestBigIpOSUtil_restart_ssh_service(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(shellutil, "run", return_value=0)
    def test_success(self, *args): # pylint: disable=unused-argument
        result = osutil.BigIpOSUtil.restart_ssh_service(
            osutil.BigIpOSUtil()
        )
        self.assertEqual(result, 0)


class TestBigIpOSUtil_stop_agent_service(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(shellutil, "run", return_value=0)
    def test_success(self, *args): # pylint: disable=unused-argument
        result = osutil.BigIpOSUtil.stop_agent_service(
            osutil.BigIpOSUtil()
        )
        self.assertEqual(result, 0)


class TestBigIpOSUtil_start_agent_service(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(shellutil, "run", return_value=0)
    def test_success(self, *args): # pylint: disable=unused-argument
        result = osutil.BigIpOSUtil.start_agent_service(
            osutil.BigIpOSUtil()
        )
        self.assertEqual(result, 0)


class TestBigIpOSUtil_register_agent_service(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(shellutil, "run", return_value=0)
    def test_success(self, *args): # pylint: disable=unused-argument
        result = osutil.BigIpOSUtil.register_agent_service(
            osutil.BigIpOSUtil()
        )
        self.assertEqual(result, 0)


class TestBigIpOSUtil_unregister_agent_service(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(shellutil, "run", return_value=0)
    def test_success(self, *args): # pylint: disable=unused-argument
        result = osutil.BigIpOSUtil.unregister_agent_service(
            osutil.BigIpOSUtil()
        )
        self.assertEqual(result, 0)


class TestBigIpOSUtil_set_hostname(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(os.path, "exists", return_value=False)
    def test_success(self, *args):
        result = osutil.BigIpOSUtil.set_hostname( # pylint: disable=assignment-from-none
            osutil.BigIpOSUtil(), None
        )
        self.assertEqual(args[0].call_count, 0)
        self.assertEqual(result, None)


class TestBigIpOSUtil_set_dhcp_hostname(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(os.path, "exists", return_value=False)
    def test_success(self, *args):
        result = osutil.BigIpOSUtil.set_dhcp_hostname( # pylint: disable=assignment-from-none
            osutil.BigIpOSUtil(), None
        )
        self.assertEqual(args[0].call_count, 0)
        self.assertEqual(result, None)


class TestBigIpOSUtil_get_first_if(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(osutil.BigIpOSUtil,
                  '_format_single_interface_name', return_value=b'eth0')
    def test_success(self, *args): # pylint: disable=unused-argument
        ifname, ipaddr = osutil.BigIpOSUtil().get_first_if()
        self.assertTrue(ifname.startswith('eth'))
        self.assertTrue(ipaddr is not None)
        try:
            socket.inet_aton(ipaddr)
        except socket.error:
            self.fail("not a valid ip address")

    @patch.object(osutil.BigIpOSUtil,
                  '_format_single_interface_name', return_value=b'loenp0s3')
    def test_success(self, *args): # pylint: disable=unused-argument,function-redefined
        ifname, ipaddr = osutil.BigIpOSUtil().get_first_if()
        self.assertFalse(ifname.startswith('eth'))
        self.assertTrue(ipaddr is not None)
        try:
            socket.inet_aton(ipaddr)
        except socket.error:
            self.fail("not a valid ip address")


class TestBigIpOSUtil_mount_dvd(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(shellutil, "run", return_value=0)
    @patch.object(time, "sleep", return_value=None)
    @patch.object(osutil.BigIpOSUtil,
                  '_wait_until_mcpd_is_initialized', return_value=None)
    @patch.object(default.DefaultOSUtil, 'mount_dvd', return_value=None)
    def test_success(self, *args):
        osutil.BigIpOSUtil.mount_dvd(
            osutil.BigIpOSUtil(), max_retry=6, chk_err=True
        )
        self.assertEqual(args[0].call_count, 1)
        self.assertEqual(args[1].call_count, 1)


class TestBigIpOSUtil_route_add(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(shellutil, "run", return_value=0)
    def test_success(self, *args):
        osutil.BigIpOSUtil.route_add(
            osutil.BigIpOSUtil(), '10.10.10.0', '255.255.255.0', '10.10.10.1'
        )
        self.assertEqual(args[0].call_count, 1)


class TestBigIpOSUtil_device_for_ide_port(AgentTestCase): # pylint: disable=invalid-name

    @patch.object(time, "sleep", return_value=None)
    @patch.object(os.path, "exists", return_value=False)
    @patch.object(default.DefaultOSUtil,
                  'device_for_ide_port', return_value=None)
    def test_success_waiting(self, *args):
        osutil.BigIpOSUtil.device_for_ide_port(
            osutil.BigIpOSUtil(), '5'
        )
        self.assertEqual(args[0].call_count, 1)
        self.assertEqual(args[1].call_count, 99)
        self.assertEqual(args[2].call_count, 99)

    @patch.object(time, "sleep", return_value=None)
    @patch.object(os.path, "exists", return_value=True)
    @patch.object(default.DefaultOSUtil,
                  'device_for_ide_port', return_value=None)
    def test_success_immediate(self, *args):
        osutil.BigIpOSUtil.device_for_ide_port(
            osutil.BigIpOSUtil(), '5'
        )
        self.assertEqual(args[0].call_count, 1)
        self.assertEqual(args[1].call_count, 1)
        self.assertEqual(args[2].call_count, 0)


class TestBigIpOSUtil(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

    def tearDown(self):
        AgentTestCase.tearDown(self)

    def test_get_dhcp_pid_should_return_a_list_of_pids(self):
        osutil_get_dhcp_pid_should_return_a_list_of_pids(self, BigIpOSUtil())


if __name__ == '__main__':
    unittest.main()