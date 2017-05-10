# Copyright 2014 Microsoft Corporation
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

import socket
import glob
import mock

import azurelinuxagent.common.osutil.default as osutil
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil
from tests.tools import *


class TestOSUtil(AgentTestCase):
    def test_restart(self):
        # setup
        retries = 3
        ifname = 'dummy'
        with patch.object(shellutil, "run") as run_patch:
            run_patch.return_value = 1

            # execute
            osutil.DefaultOSUtil.restart_if(osutil.DefaultOSUtil(), ifname=ifname, retries=retries, wait=0)

            # assert
            self.assertEqual(run_patch.call_count, retries)
            self.assertEqual(run_patch.call_args_list[0][0][0], 'ifdown {0} && ifup {0}'.format(ifname))

    def test_get_dvd_device_success(self):
        with patch.object(os, 'listdir', return_value=['cpu', 'cdrom0']):
            osutil.DefaultOSUtil().get_dvd_device()

    def test_get_dvd_device_failure(self):
        with patch.object(os, 'listdir', return_value=['cpu', 'notmatching']):
            try:
                osutil.DefaultOSUtil().get_dvd_device()
                self.fail('OSUtilError was not raised')
            except OSUtilError as ose:
                self.assertTrue('notmatching' in ustr(ose))

    @patch('time.sleep')
    def test_mount_dvd_success(self, _):
        msg = 'message'
        with patch.object(osutil.DefaultOSUtil,
                          'get_dvd_device',
                          return_value='/dev/cdrom'):
            with patch.object(shellutil,
                              'run_get_output',
                              return_value=(0, msg)) as patch_run:
                with patch.object(os, 'makedirs'):
                    try:
                        osutil.DefaultOSUtil().mount_dvd()
                    except OSUtilError:
                        self.fail("mounting failed")

    @patch('time.sleep')
    def test_mount_dvd_failure(self, _):
        msg = 'message'
        with patch.object(osutil.DefaultOSUtil,
                          'get_dvd_device',
                          return_value='/dev/cdrom'):
            with patch.object(shellutil,
                              'run_get_output',
                              return_value=(1, msg)) as patch_run:
                with patch.object(os, 'makedirs'):
                    try:
                        osutil.DefaultOSUtil().mount_dvd()
                        self.fail('OSUtilError was not raised')
                    except OSUtilError as ose:
                        self.assertTrue(msg in ustr(ose))
                        self.assertTrue(patch_run.call_count == 6)

    def test_get_first_if(self):
        ifname, ipaddr = osutil.DefaultOSUtil().get_first_if()
        self.assertTrue(ifname.startswith('eth'))
        self.assertTrue(ipaddr is not None)
        try:
            socket.inet_aton(ipaddr)
        except socket.error:
            self.fail("not a valid ip address")

    def test_isloopback(self):
        self.assertTrue(osutil.DefaultOSUtil().is_loopback(b'lo'))
        self.assertFalse(osutil.DefaultOSUtil().is_loopback(b'eth0'))

    def test_isprimary(self):
        routing_table = "\
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT \n\
        eth0	00000000	01345B0A	0003	0	    0	5	00000000	0	0	0   \n\
        eth0	00345B0A	00000000	0001	0	    0	5	00000000	0	0	0   \n\
        lo	    00000000	01345B0A	0003	0	    0	1	00FCFFFF	0	0	0   \n"

        mo = mock.mock_open(read_data=routing_table)
        with patch(open_patch(), mo):
            self.assertFalse(osutil.DefaultOSUtil().is_primary_interface('lo'))
            self.assertTrue(osutil.DefaultOSUtil().is_primary_interface('eth0'))

    def test_multiple_default_routes(self):
        routing_table = "\
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT \n\
        high	00000000	01345B0A	0003	0	    0	5	00000000	0	0	0   \n\
        low1	00000000	01345B0A	0003	0	    0	1	00FCFFFF	0	0	0   \n"

        mo = mock.mock_open(read_data=routing_table)
        with patch(open_patch(), mo):
            self.assertTrue(osutil.DefaultOSUtil().is_primary_interface('low1'))

    def test_multiple_interfaces(self):
        routing_table = "\
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT \n\
        first	00000000	01345B0A	0003	0	    0	1	00000000	0	0	0   \n\
        secnd	00000000	01345B0A	0003	0	    0	1	00FCFFFF	0	0	0   \n"

        mo = mock.mock_open(read_data=routing_table)
        with patch(open_patch(), mo):
            self.assertTrue(osutil.DefaultOSUtil().is_primary_interface('first'))

    def test_interface_flags(self):
        routing_table = "\
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT \n\
        nflg	00000000	01345B0A	0001	0	    0	1	00000000	0	0	0   \n\
        flgs	00000000	01345B0A	0003	0	    0	1	00FCFFFF	0	0	0   \n"

        mo = mock.mock_open(read_data=routing_table)
        with patch(open_patch(), mo):
            self.assertTrue(osutil.DefaultOSUtil().is_primary_interface('flgs'))

    def test_no_interface(self):
        routing_table = "\
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT \n\
        ndst	00000001	01345B0A	0003	0	    0	1	00000000	0	0	0   \n\
        nflg	00000000	01345B0A	0001	0	    0	1	00FCFFFF	0	0	0   \n"

        mo = mock.mock_open(read_data=routing_table)
        with patch(open_patch(), mo):
            self.assertFalse(osutil.DefaultOSUtil().is_primary_interface('ndst'))
            self.assertFalse(osutil.DefaultOSUtil().is_primary_interface('nflg'))
            self.assertFalse(osutil.DefaultOSUtil().is_primary_interface('invalid'))

    def test_no_primary_does_not_throw(self):
        with patch.object(osutil.DefaultOSUtil, 'get_primary_interface') \
                as patch_primary:
            exception = False
            patch_primary.return_value = ''
            try:
                osutil.DefaultOSUtil().get_first_if()[0]
            except Exception as e:
                exception = True
            self.assertFalse(exception)

    def test_dhcp_lease_default(self):
        self.assertTrue(osutil.DefaultOSUtil().get_dhcp_lease_endpoint() is None)

    def test_dhcp_lease_ubuntu(self):
        with patch.object(glob, "glob", return_value=['/var/lib/dhcp/dhclient.eth0.leases']):
            with patch(open_patch(), mock.mock_open(read_data=load_data("dhcp.leases"))):
                endpoint = get_osutil(distro_name='ubuntu', distro_version='12.04').get_dhcp_lease_endpoint()
                self.assertTrue(endpoint is not None)
                self.assertEqual(endpoint, "168.63.129.16")

                endpoint = get_osutil(distro_name='ubuntu', distro_version='12.04').get_dhcp_lease_endpoint()
                self.assertTrue(endpoint is not None)
                self.assertEqual(endpoint, "168.63.129.16")

                endpoint = get_osutil(distro_name='ubuntu', distro_version='14.04').get_dhcp_lease_endpoint()
                self.assertTrue(endpoint is not None)
                self.assertEqual(endpoint, "168.63.129.16")

    def test_dhcp_lease_multi(self):
        with patch.object(glob, "glob", return_value=['/var/lib/dhcp/dhclient.eth0.leases']):
            with patch(open_patch(), mock.mock_open(read_data=load_data("dhcp.leases.multi"))):
                endpoint = get_osutil(distro_name='ubuntu', distro_version='12.04').get_dhcp_lease_endpoint()
                self.assertTrue(endpoint is not None)
                self.assertEqual(endpoint, "second")

    def test_get_total_mem(self):
        """
        Validate the returned value matches to the one retrieved by invoking shell command
        """
        cmd = "grep MemTotal /proc/meminfo |awk '{print $2}'"
        ret = shellutil.run_get_output(cmd)
        if ret[0] == 0:
            self.assertEqual(int(ret[1]) / 1024, get_osutil().get_total_mem())
        else:
            self.fail("Cannot retrieve total memory using shell command.")

    def test_get_processor_cores(self):
        """
        Validate the returned value matches to the one retrieved by invoking shell command
        """
        cmd = "grep 'processor.*:' /proc/cpuinfo |wc -l"
        ret = shellutil.run_get_output(cmd)
        if ret[0] == 0:
            self.assertEqual(int(ret[1]), get_osutil().get_processor_cores())
        else:
            self.fail("Cannot retrieve number of process cores using shell command.")

    def test_conf_sshd(self):
        new_file = "\
Port 22\n\
Protocol 2\n\
ChallengeResponseAuthentication yes\n\
#PasswordAuthentication yes\n\
UsePAM yes\n\
"
        expected_output = "\
Port 22\n\
Protocol 2\n\
ChallengeResponseAuthentication no\n\
#PasswordAuthentication yes\n\
UsePAM yes\n\
PasswordAuthentication no\n\
ClientAliveInterval 180\n\
"

        with patch.object(fileutil, 'write_file') as patch_write:
            with patch.object(fileutil, 'read_file', return_value=new_file):
                osutil.DefaultOSUtil().conf_sshd(disable_password=True)
                patch_write.assert_called_once_with(
                    conf.get_sshd_conf_file_path(),
                    expected_output)

    def test_conf_sshd_with_match(self):
        new_file = "\
Port 22\n\
ChallengeResponseAuthentication yes\n\
Match host 192.168.1.1\n\
  ChallengeResponseAuthentication yes\n\
"
        expected_output = "\
Port 22\n\
ChallengeResponseAuthentication no\n\
PasswordAuthentication no\n\
ClientAliveInterval 180\n\
Match host 192.168.1.1\n\
  ChallengeResponseAuthentication yes\n\
"

        with patch.object(fileutil, 'write_file') as patch_write:
            with patch.object(fileutil, 'read_file', return_value=new_file):
                osutil.DefaultOSUtil().conf_sshd(disable_password=True)
                patch_write.assert_called_once_with(
                    conf.get_sshd_conf_file_path(),
                    expected_output)

    def test_conf_sshd_with_match_last(self):
        new_file = "\
Port 22\n\
Match host 192.168.1.1\n\
  ChallengeResponseAuthentication yes\n\
"
        expected_output = "\
Port 22\n\
PasswordAuthentication no\n\
ChallengeResponseAuthentication no\n\
ClientAliveInterval 180\n\
Match host 192.168.1.1\n\
  ChallengeResponseAuthentication yes\n\
"

        with patch.object(fileutil, 'write_file') as patch_write:
            with patch.object(fileutil, 'read_file', return_value=new_file):
                osutil.DefaultOSUtil().conf_sshd(disable_password=True)
                patch_write.assert_called_once_with(
                    conf.get_sshd_conf_file_path(),
                    expected_output)

    def test_conf_sshd_with_match_middle(self):
        new_file = "\
Port 22\n\
match host 192.168.1.1\n\
  ChallengeResponseAuthentication yes\n\
match all\n\
#Other config\n\
"
        expected_output = "\
Port 22\n\
match host 192.168.1.1\n\
  ChallengeResponseAuthentication yes\n\
match all\n\
#Other config\n\
PasswordAuthentication no\n\
ChallengeResponseAuthentication no\n\
ClientAliveInterval 180\n\
"

        with patch.object(fileutil, 'write_file') as patch_write:
            with patch.object(fileutil, 'read_file', return_value=new_file):
                osutil.DefaultOSUtil().conf_sshd(disable_password=True)
                patch_write.assert_called_once_with(
                    conf.get_sshd_conf_file_path(),
                    expected_output)

    def test_conf_sshd_with_match_multiple(self):
        new_file = "\
Port 22\n\
Match host 192.168.1.1\n\
  ChallengeResponseAuthentication yes\n\
Match host 192.168.1.2\n\
  ChallengeResponseAuthentication yes\n\
Match all\n\
#Other config\n\
"
        expected_output = "\
Port 22\n\
Match host 192.168.1.1\n\
  ChallengeResponseAuthentication yes\n\
Match host 192.168.1.2\n\
  ChallengeResponseAuthentication yes\n\
Match all\n\
#Other config\n\
PasswordAuthentication no\n\
ChallengeResponseAuthentication no\n\
ClientAliveInterval 180\n\
"

        with patch.object(fileutil, 'write_file') as patch_write:
            with patch.object(fileutil, 'read_file', return_value=new_file):
                osutil.DefaultOSUtil().conf_sshd(disable_password=True)
                patch_write.assert_called_once_with(
                    conf.get_sshd_conf_file_path(),
                    expected_output)

    def test_conf_sshd_with_match_multiple_first_last(self):
        new_file = "\
Match host 192.168.1.1\n\
  ChallengeResponseAuthentication yes\n\
Match host 192.168.1.2\n\
  ChallengeResponseAuthentication yes\n\
"
        expected_output = "\
PasswordAuthentication no\n\
ChallengeResponseAuthentication no\n\
ClientAliveInterval 180\n\
Match host 192.168.1.1\n\
  ChallengeResponseAuthentication yes\n\
Match host 192.168.1.2\n\
  ChallengeResponseAuthentication yes\n\
"

        with patch.object(fileutil, 'write_file') as patch_write:
            with patch.object(fileutil, 'read_file', return_value=new_file):
                osutil.DefaultOSUtil().conf_sshd(disable_password=True)
                patch_write.assert_called_once_with(
                    conf.get_sshd_conf_file_path(),
                    expected_output)

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="B9F3C233-9913-9F42-8EB3-BA656DF32502")
    def test_get_instance_id_from_file(self, mock_read, mock_isfile):
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502",
            util.get_instance_id())

    @patch('os.path.isfile', return_value=False)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output',
            return_value=[0, 'B9F3C233-9913-9F42-8EB3-BA656DF32502'])
    def test_get_instance_id_from_dmidecode(self, mock_shell, mock_isfile):
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502",
            util.get_instance_id())

    @patch('os.path.isfile', return_value=False)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output',
            return_value=[1, 'Error Value'])
    def test_get_instance_id_missing(self, mock_shell, mock_isfile):
        util = osutil.DefaultOSUtil()
        self.assertEqual("", util.get_instance_id())

    @patch('os.path.isfile', return_value=False)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output',
            return_value=[0, 'Unexpected Value'])
    def test_get_instance_id_unexpected(self, mock_shell, mock_isfile):
        util = osutil.DefaultOSUtil()
        self.assertEqual("", util.get_instance_id())

if __name__ == '__main__':
    unittest.main()
