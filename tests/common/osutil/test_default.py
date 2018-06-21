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
# Requires Python 2.6+ and Openssl 1.0+
#

import socket
import glob
import mock
import traceback

import azurelinuxagent.common.osutil.default as osutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from tests.tools import *


actual_get_proc_net_route = 'azurelinuxagent.common.osutil.default.DefaultOSUtil._get_proc_net_route'

def fake_is_loopback(_, iface):
    return iface.startswith('lo')


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

    def test_empty_proc_net_route(self):
        routing_table = ""

        mo = mock.mock_open(read_data=routing_table)
        with patch(open_patch(), mo):
            self.assertEqual(len(osutil.DefaultOSUtil().read_route_table()), 0)

    def test_no_routes(self):
        routing_table = 'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT        \n'

        mo = mock.mock_open(read_data=routing_table)
        with patch(open_patch(), mo):
            raw_route_list = osutil.DefaultOSUtil().read_route_table()

        self.assertEqual(len(osutil.DefaultOSUtil().get_list_of_routes(raw_route_list)), 0)

    def test_bogus_proc_net_route(self):
        routing_table = 'Iface\tDestination\tGateway \tFlags\t\tUse\tMetric\t\neth0\t00000000\t00000000\t0001\t\t0\t0\n'

        mo = mock.mock_open(read_data=routing_table)
        with patch(open_patch(), mo):
            raw_route_list = osutil.DefaultOSUtil().read_route_table()

        self.assertEqual(len(osutil.DefaultOSUtil().get_list_of_routes(raw_route_list)), 0)

    def test_valid_routes(self):
        routing_table = \
            'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT   \n' \
            'eth0\t00000000\tC1BB910A\t0003\t0\t0\t0\t00000000\t0\t0\t0    \n' \
            'eth0\tC0BB910A\t00000000\t0001\t0\t0\t0\tC0FFFFFF\t0\t0\t0    \n' \
            'eth0\t10813FA8\tC1BB910A\t000F\t0\t0\t0\tFFFFFFFF\t0\t0\t0    \n' \
            'eth0\tFEA9FEA9\tC1BB910A\t0007\t0\t0\t0\tFFFFFFFF\t0\t0\t0    \n' \
            'docker0\t002BA8C0\t00000000\t0001\t0\t0\t10\t00FFFFFF\t0\t0\t0    \n'
        known_sha1_hash = b'\x1e\xd1k\xae[\xf8\x9b\x1a\x13\xd0\xbbT\xa4\xe3Y\xa3\xdd\x0b\xbd\xa9'

        mo = mock.mock_open(read_data=routing_table)
        with patch(open_patch(), mo):
            raw_route_list = osutil.DefaultOSUtil().read_route_table()

        self.assertEqual(len(raw_route_list), 6)
        self.assertEqual(textutil.hash_strings(raw_route_list), known_sha1_hash)

        route_list = osutil.DefaultOSUtil().get_list_of_routes(raw_route_list)

        self.assertEqual(len(route_list), 5)
        self.assertEqual(route_list[0].gateway_quad(), '10.145.187.193')
        self.assertEqual(route_list[1].gateway_quad(), '0.0.0.0')
        self.assertEqual(route_list[1].mask_quad(), '255.255.255.192')
        self.assertEqual(route_list[2].destination_quad(), '168.63.129.16')
        self.assertEqual(route_list[1].flags, 1)
        self.assertEqual(route_list[2].flags, 15)
        self.assertEqual(route_list[3].flags, 7)
        self.assertEqual(route_list[3].metric, 0)
        self.assertEqual(route_list[4].metric, 10)
        self.assertEqual(route_list[0].interface, 'eth0')
        self.assertEqual(route_list[4].interface, 'docker0')

    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil.get_primary_interface', return_value='eth0')
    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil._get_all_interfaces', return_value={'eth0':'10.0.0.1'})
    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil.is_loopback', fake_is_loopback)
    def test_get_first_if(self, get_all_interfaces_mock, get_primary_interface_mock):
        """
        Validate that the agent can find the first active non-loopback
        interface.

        This test case used to run live, but not all developers have an eth*
        interface. It is perfectly valid to have a br*, but this test does not
        account for that.
        """
        ifname, ipaddr = osutil.DefaultOSUtil().get_first_if()
        self.assertEqual(ifname, 'eth0')
        self.assertEqual(ipaddr, '10.0.0.1')

    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil.get_primary_interface', return_value='bogus0')
    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil._get_all_interfaces', return_value={'eth0':'10.0.0.1', 'lo': '127.0.0.1'})
    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil.is_loopback', fake_is_loopback)
    def test_get_first_if_nosuchprimary(self, get_all_interfaces_mock, get_primary_interface_mock):
        ifname, ipaddr = osutil.DefaultOSUtil().get_first_if()
        self.assertTrue(ifname.startswith('eth'))
        self.assertTrue(ipaddr is not None)
        try:
            socket.inet_aton(ipaddr)
        except socket.error:
            self.fail("not a valid ip address")

    def test_get_first_if_all_loopback(self):
        fake_ifaces = {'lo':'127.0.0.1'}
        with patch.object(osutil.DefaultOSUtil, 'get_primary_interface', return_value='bogus0'):
            with patch.object(osutil.DefaultOSUtil, '_get_all_interfaces', return_value=fake_ifaces):
                self.assertEqual(('', ''), osutil.DefaultOSUtil().get_first_if())

    def test_isloopback(self):
        self.assertTrue(osutil.DefaultOSUtil().is_loopback('lo'))
        self.assertFalse(osutil.DefaultOSUtil().is_loopback('eth0'))

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

    def test_sriov(self):
        routing_table = "\
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT \n" \
        "bond0	00000000	0100000A	0003	0	    0	0	00000000	0	0	0   \n" \
        "bond0	0000000A	00000000	0001	0	    0	0	00000000	0	0	0   \n" \
        "eth0	0000000A	00000000	0001	0	    0	0	00000000	0	0	0   \n" \
        "bond0	10813FA8	0100000A	0007	0	    0	0	00000000	0	0	0   \n" \
        "bond0	FEA9FEA9	0100000A	0007	0	    0	0	00000000	0	0	0   \n"

        mo = mock.mock_open(read_data=routing_table)
        with patch(open_patch(), mo):
            self.assertFalse(osutil.DefaultOSUtil().is_primary_interface('eth0'))
            self.assertTrue(osutil.DefaultOSUtil().is_primary_interface('bond0'))


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
                print(traceback.format_exc())
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

    def test_correct_instance_id(self):
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            "12345678-1234-1234-1234-123456789012",
            util._correct_instance_id("78563412-3412-3412-1234-123456789012"))
        self.assertEqual(
            "D0DF4C54-4ECB-4A4B-9954-5BDF3ED5C3B8",
            util._correct_instance_id("544CDFD0-CB4E-4B4A-9954-5BDF3ED5C3B8"))

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="33C2F3B9-1399-429F-8EB3-BA656DF32502")
    def test_get_instance_id_from_file(self, mock_read, mock_isfile):
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            util.get_instance_id(),
            "B9F3C233-9913-9F42-8EB3-BA656DF32502")

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="")
    def test_get_instance_id_empty_from_file(self, mock_read, mock_isfile):
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            "",
            util.get_instance_id())

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="Value")
    def test_get_instance_id_malformed_from_file(self, mock_read, mock_isfile):
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            "Value",
            util.get_instance_id())

    @patch('os.path.isfile', return_value=False)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output',
            return_value=[0, '33C2F3B9-1399-429F-8EB3-BA656DF32502'])
    def test_get_instance_id_from_dmidecode(self, mock_shell, mock_isfile):
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            util.get_instance_id(),
            "B9F3C233-9913-9F42-8EB3-BA656DF32502")

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

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file')
    def test_is_current_instance_id_from_file(self, mock_read, mock_isfile):
        util = osutil.DefaultOSUtil()

        mock_read.return_value = "B9F3C233-9913-9F42-8EB3-BA656DF32502"
        self.assertTrue(util.is_current_instance_id(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502"))

        mock_read.return_value = "33C2F3B9-1399-429F-8EB3-BA656DF32502"
        self.assertTrue(util.is_current_instance_id(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502"))

    @patch('os.path.isfile', return_value=False)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    def test_is_current_instance_id_from_dmidecode(self, mock_shell, mock_isfile):
        util = osutil.DefaultOSUtil()

        mock_shell.return_value = [0, 'B9F3C233-9913-9F42-8EB3-BA656DF32502']
        self.assertTrue(util.is_current_instance_id(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502"))

        mock_shell.return_value = [0, '33C2F3B9-1399-429F-8EB3-BA656DF32502']
        self.assertTrue(util.is_current_instance_id(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502"))

    @patch('azurelinuxagent.common.conf.get_sudoers_dir')
    def test_conf_sudoer(self, mock_dir):
        tmp_dir = tempfile.mkdtemp()
        mock_dir.return_value = tmp_dir

        util = osutil.DefaultOSUtil()

        # Assert the sudoer line is added if missing
        util.conf_sudoer("FooBar")
        waagent_sudoers = os.path.join(tmp_dir, 'waagent')
        self.assertTrue(os.path.isfile(waagent_sudoers))

        count = -1
        with open(waagent_sudoers, 'r') as f:
            count = len(f.readlines())
        self.assertEqual(1, count)

        # Assert the line does not get added a second time
        util.conf_sudoer("FooBar")

        count = -1
        with open(waagent_sudoers, 'r') as f:
            count = len(f.readlines())
        print("WRITING TO {0}".format(waagent_sudoers))
        self.assertEqual(1, count)

    def test_get_firewall_dropped_packets_returns_zero_if_firewall_disabled(self):
        osutil._enable_firewall = False
        util = osutil.DefaultOSUtil()

        self.assertEqual(0, util.get_firewall_dropped_packets("not used"))

    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    def test_get_firewall_dropped_packets_returns_negative_if_error(self, mock_output):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        mock_output.side_effect = [
            (0, "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)),
            (1, "not used")]
        self.assertEqual(-1, util.get_firewall_dropped_packets("not used"))

    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    def test_get_firewall_dropped_packets_returns_negative_if_exception(self, mock_output):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        mock_output.side_effect = [
            (0, "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)),
            (1, Exception)]
        self.assertEqual(-1, util.get_firewall_dropped_packets("not used"))

    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    def test_get_firewall_dropped_packets_transient_error_ignored(self, mock_output):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        mock_output.side_effect = [
            (0, "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)),
            (3, "can't initialize iptables table `security': iptables who? (do you need to insmod?)")]
        self.assertEqual(0, util.get_firewall_dropped_packets("not used"))

    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    def test_get_firewall_dropped_packets(self, mock_output):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        mock_output.side_effect = [
            (0, "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)),
            (0,
'''

Chain OUTPUT (policy ACCEPT 104 packets, 43628 bytes)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 ACCEPT     tcp  --  any    any     anywhere             168.63.129.16        owner UID match daemon
      32     1920 DROP       tcp  --  any    any     anywhere             168.63.129.16

''')]
        dst = '168.63.129.16'

        self.assertEqual(32, util.get_firewall_dropped_packets(dst))

    @patch('os.getuid', return_value=42)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    @patch('azurelinuxagent.common.utils.shellutil.run')
    def test_enable_firewall(self, mock_run, mock_output, mock_uid):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        dst = '1.2.3.4'
        uid = 42
        version = "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)
        wait = "-w"

        mock_run.side_effect = [1, 0, 0]
        mock_output.side_effect = [(0, version), (0, "Output")]
        self.assertTrue(util.enable_firewall(dst_ip=dst, uid=uid))

        mock_run.assert_has_calls([
            call(osutil.FIREWALL_DROP.format(wait, "C", dst), chk_err=False),
            call(osutil.FIREWALL_ACCEPT.format(wait, "A", dst, uid)),
            call(osutil.FIREWALL_DROP.format(wait, "A", dst))
        ])
        mock_output.assert_has_calls([
            call(osutil.IPTABLES_VERSION),
            call(osutil.FIREWALL_LIST.format(wait))
        ])
        self.assertTrue(osutil._enable_firewall)

    @patch('os.getuid', return_value=42)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    @patch('azurelinuxagent.common.utils.shellutil.run')
    def test_enable_firewall_no_wait(self, mock_run, mock_output, mock_uid):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        dst = '1.2.3.4'
        uid = 42
        version = "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION-1)
        wait = ""

        mock_run.side_effect = [1, 0, 0]
        mock_output.side_effect = [(0, version), (0, "Output")]
        self.assertTrue(util.enable_firewall(dst_ip=dst, uid=uid))

        mock_run.assert_has_calls([
            call(osutil.FIREWALL_DROP.format(wait, "C", dst), chk_err=False),
            call(osutil.FIREWALL_ACCEPT.format(wait, "A", dst, uid)),
            call(osutil.FIREWALL_DROP.format(wait, "A", dst))
        ])
        mock_output.assert_has_calls([
            call(osutil.IPTABLES_VERSION),
            call(osutil.FIREWALL_LIST.format(wait))
        ])
        self.assertTrue(osutil._enable_firewall)

    @patch('os.getuid', return_value=42)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    @patch('azurelinuxagent.common.utils.shellutil.run')
    def test_enable_firewall_skips_if_drop_exists(self, mock_run, mock_output, mock_uid):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        dst = '1.2.3.4'
        uid = 42
        version = "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)
        wait = "-w"

        mock_run.side_effect = [0, 0, 0]
        mock_output.return_value = (0, version)
        self.assertTrue(util.enable_firewall(dst_ip=dst, uid=uid))

        mock_run.assert_has_calls([
            call(osutil.FIREWALL_DROP.format(wait, "C", dst), chk_err=False),
        ])
        mock_output.assert_has_calls([
            call(osutil.IPTABLES_VERSION)
        ])
        self.assertTrue(osutil._enable_firewall)

    @patch('os.getuid', return_value=42)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    @patch('azurelinuxagent.common.utils.shellutil.run')
    def test_enable_firewall_ignores_exceptions(self, mock_run, mock_output, mock_uid):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        dst = '1.2.3.4'
        uid = 42
        version = "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)
        wait = "-w"

        mock_run.side_effect = [1, Exception]
        mock_output.return_value = (0, version)
        self.assertFalse(util.enable_firewall(dst_ip=dst, uid=uid))

        mock_run.assert_has_calls([
            call(osutil.FIREWALL_DROP.format(wait, "C", dst), chk_err=False),
            call(osutil.FIREWALL_ACCEPT.format(wait, "A", dst, uid))
        ])
        mock_output.assert_has_calls([
            call(osutil.IPTABLES_VERSION)
        ])
        self.assertFalse(osutil._enable_firewall)

    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    @patch('azurelinuxagent.common.utils.shellutil.run')
    def test_enable_firewall_checks_for_invalid_iptables_options(self, mock_run, mock_output):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        dst = '1.2.3.4'
        version = "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)
        wait = "-w"

        # iptables uses the following exit codes
        #  0 - correct function
        #  1 - other errors
        #  2 - errors which appear to be caused by invalid or abused command
        #      line parameters
        mock_run.side_effect = [2]
        mock_output.return_value = (0, version)

        self.assertFalse(util.enable_firewall(dst_ip='1.2.3.4', uid=42))
        self.assertFalse(osutil._enable_firewall)

        mock_run.assert_has_calls([
            call(osutil.FIREWALL_DROP.format(wait, "C", dst), chk_err=False),
        ])
        mock_output.assert_has_calls([
            call(osutil.IPTABLES_VERSION)
        ])

    @patch('os.getuid', return_value=42)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    @patch('azurelinuxagent.common.utils.shellutil.run')
    def test_enable_firewall_skips_if_disabled(self, mock_run, mock_output, mock_uid):
        osutil._enable_firewall = False
        util = osutil.DefaultOSUtil()

        dst = '1.2.3.4'
        uid = 42
        version = "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)

        mock_run.side_effect = [1, 0, 0]
        mock_output.side_effect = [(0, version), (0, "Output")]
        self.assertFalse(util.enable_firewall(dst_ip=dst, uid=uid))

        mock_run.assert_not_called()
        mock_output.assert_not_called()
        mock_uid.assert_not_called()
        self.assertFalse(osutil._enable_firewall)

    @patch('os.getuid', return_value=42)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    @patch('azurelinuxagent.common.utils.shellutil.run')
    def test_remove_firewall(self, mock_run, mock_output, mock_uid):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        dst = '1.2.3.4'
        uid = 42
        version = "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)
        wait = "-w"

        mock_run.side_effect = [0, 1, 0, 1, 0, 1]
        mock_output.side_effect = [(0, version), (0, "Output")]
        self.assertTrue(util.remove_firewall(dst, uid))

        mock_run.assert_has_calls([
            # delete rules < 2.2.26
            call(osutil.FIREWALL_DELETE_CONNTRACK_ACCEPT.format(wait, dst), chk_err=False),
            call(osutil.FIREWALL_DELETE_CONNTRACK_ACCEPT.format(wait, dst), chk_err=False),
            call(osutil.FIREWALL_DELETE_OWNER_ACCEPT.format(wait, dst, uid), chk_err=False),
            call(osutil.FIREWALL_DELETE_OWNER_ACCEPT.format(wait, dst, uid), chk_err=False),

            # delete rules >= 2.2.26
            call(osutil.FIREWALL_DELETE_CONNTRACK_DROP.format(wait, dst), chk_err=False),
            call(osutil.FIREWALL_DELETE_CONNTRACK_DROP.format(wait, dst), chk_err=False),
        ])
        mock_output.assert_has_calls([
            call(osutil.IPTABLES_VERSION)
        ])
        self.assertTrue(osutil._enable_firewall)

    @patch('os.getuid', return_value=42)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    @patch('azurelinuxagent.common.utils.shellutil.run')
    def test_remove_firewall_does_not_repeat(self, mock_run, mock_output, _):
        osutil._enable_firewall = True
        util = osutil.DefaultOSUtil()

        dst_ip='1.2.3.4'
        uid=42
        version = "iptables v{0}".format(osutil.IPTABLES_LOCKING_VERSION)
        wait = "-w"

        mock_run.side_effect = [2]
        mock_output.side_effect = [(0, version), (1, "Output")]
        self.assertFalse(util.remove_firewall(dst_ip, uid))

        mock_run.assert_has_calls([
            call(osutil.FIREWALL_DELETE_CONNTRACK_ACCEPT.format(wait, dst_ip), chk_err=False),
        ])
        mock_output.assert_has_calls([
            call(osutil.IPTABLES_VERSION)
        ])
        self.assertFalse(osutil._enable_firewall)

        self.assertTrue(mock_run.call_count == 1)
        self.assertTrue(mock_output.call_count == 1)

        self.assertFalse(util.remove_firewall())
        self.assertFalse(util.remove_firewall())

        self.assertTrue(mock_run.call_count == 1)
        self.assertTrue(mock_output.call_count == 1)


if __name__ == '__main__':
    unittest.main()
