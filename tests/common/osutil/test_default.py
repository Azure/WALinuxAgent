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
import contextlib
import glob
import os
import socket
import subprocess
import tempfile
import unittest

import mock

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.osutil.default as osutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.networkutil import AddFirewallRules
from tests.lib.mock_environment import MockEnvironment
from tests.lib.tools import AgentTestCase, patch, open_patch, load_data, data_dir, is_python_version_26_or_34, skip_if_predicate_true

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
            with patch.object(shellutil, 'run_command', return_value=msg):
                with patch.object(os, 'makedirs'):
                    try:
                        osutil.DefaultOSUtil().mount_dvd()
                    except OSUtilError:
                        self.fail("mounting failed")

    @patch('time.sleep')
    def test_mount_dvd_failure(self, _):
        
        msg = 'message'
        exception = shellutil.CommandError("mount dvd", 1, "", msg)
        
        with patch.object(osutil.DefaultOSUtil,
                          'get_dvd_device',
                          return_value='/dev/cdrom'):
            with patch.object(shellutil, 'run_command',
                side_effect=exception) as patch_run:
                with patch.object(os, 'makedirs'):
                    try:
                        osutil.DefaultOSUtil().mount_dvd()
                        self.fail('OSUtilError was not raised')
                    except OSUtilError as ose:
                        self.assertTrue(msg in ustr(ose))
                        self.assertEqual(patch_run.call_count, 5)

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
    def test_get_first_if(self, get_all_interfaces_mock, get_primary_interface_mock):  # pylint: disable=unused-argument
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
    def test_get_first_if_nosuchprimary(self, get_all_interfaces_mock, get_primary_interface_mock):  # pylint: disable=unused-argument
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

    def test_get_all_interfaces(self):
        loopback_count = 0
        non_loopback_count = 0

        for iface in osutil.DefaultOSUtil()._get_all_interfaces():
            if iface == 'lo':
                loopback_count += 1
            else:
                non_loopback_count += 1

        self.assertEqual(loopback_count, 1, 'Exactly 1 loopback network interface should exist')
        self.assertGreater(loopback_count, 0, 'At least 1 non-loopback network interface should exist')

    def test_isloopback(self):
        for iface in osutil.DefaultOSUtil()._get_all_interfaces():
            if iface == 'lo':
                self.assertTrue(osutil.DefaultOSUtil().is_loopback(iface))
            else:
                self.assertFalse(osutil.DefaultOSUtil().is_loopback(iface))

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
            except Exception as e:  # pylint: disable=unused-variable
                print(textutil.format_exception(e))
                exception = True
            self.assertFalse(exception)

    def test_dhcp_lease_default(self):
        self.assertTrue(osutil.DefaultOSUtil().get_dhcp_lease_endpoint() is None)

    def test_dhcp_lease_ubuntu(self):
        with patch.object(glob, "glob", return_value=['/var/lib/dhcp/dhclient.eth0.leases']):
            with patch(open_patch(), mock.mock_open(read_data=load_data("dhcp.leases"))):
                endpoint = get_osutil(distro_name='ubuntu', distro_version='12.04').get_dhcp_lease_endpoint()  # pylint: disable=assignment-from-none
                self.assertTrue(endpoint is not None)
                self.assertEqual(endpoint, "168.63.129.16")

                endpoint = get_osutil(distro_name='ubuntu', distro_version='12.04').get_dhcp_lease_endpoint()  # pylint: disable=assignment-from-none
                self.assertTrue(endpoint is not None)
                self.assertEqual(endpoint, "168.63.129.16")

                endpoint = get_osutil(distro_name='ubuntu', distro_version='14.04').get_dhcp_lease_endpoint()  # pylint: disable=assignment-from-none
                self.assertTrue(endpoint is not None)
                self.assertEqual(endpoint, "168.63.129.16")

    def test_dhcp_lease_custom_dns(self):
        """
        Validate that the wireserver address is coming from option 245
        (on default configurations the address is also available in the domain-name-servers option, but users
         may set up a custom dns server on their vnet)
        """
        with patch.object(glob, "glob", return_value=['/var/lib/dhcp/dhclient.eth0.leases']):
            with patch(open_patch(), mock.mock_open(read_data=load_data("dhcp.leases.custom.dns"))):
                endpoint = get_osutil(distro_name='ubuntu', distro_version='14.04').get_dhcp_lease_endpoint()  # pylint: disable=assignment-from-none
                self.assertEqual(endpoint, "168.63.129.16")

    def test_dhcp_lease_multi(self):
        with patch.object(glob, "glob", return_value=['/var/lib/dhcp/dhclient.eth0.leases']):
            with patch(open_patch(), mock.mock_open(read_data=load_data("dhcp.leases.multi"))):
                endpoint = get_osutil(distro_name='ubuntu', distro_version='12.04').get_dhcp_lease_endpoint()  # pylint: disable=assignment-from-none
                self.assertTrue(endpoint is not None)
                self.assertEqual(endpoint, "168.63.129.2")

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
        self.assertEqual(
            "d0df4c54-4ecb-4a4b-9954-5bdf3ed5c3b8",
            util._correct_instance_id("544cdfd0-cb4e-4b4a-9954-5bdf3ed5c3b8"))

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="33C2F3B9-1399-429F-8EB3-BA656DF32502")
    def test_get_instance_id_from_file(self, mock_read, mock_isfile):  # pylint: disable=unused-argument
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            util.get_instance_id(),
            "B9F3C233-9913-9F42-8EB3-BA656DF32502")

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="")
    def test_get_instance_id_empty_from_file(self, mock_read, mock_isfile):  # pylint: disable=unused-argument
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            "",
            util.get_instance_id())

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file',
            return_value="Value")
    def test_get_instance_id_malformed_from_file(self, mock_read, mock_isfile):  # pylint: disable=unused-argument
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            "Value",
            util.get_instance_id())

    @patch('os.path.isfile', return_value=False)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output',
            return_value=[0, '33C2F3B9-1399-429F-8EB3-BA656DF32502'])
    def test_get_instance_id_from_dmidecode(self, mock_shell, mock_isfile):  # pylint: disable=unused-argument
        util = osutil.DefaultOSUtil()
        self.assertEqual(
            util.get_instance_id(),
            "B9F3C233-9913-9F42-8EB3-BA656DF32502")

    @patch('os.path.isfile', return_value=False)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output',
            return_value=[1, 'Error Value'])
    def test_get_instance_id_missing(self, mock_shell, mock_isfile):  # pylint: disable=unused-argument
        util = osutil.DefaultOSUtil()
        self.assertEqual("", util.get_instance_id())

    @patch('os.path.isfile', return_value=False)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output',
            return_value=[0, 'Unexpected Value'])
    def test_get_instance_id_unexpected(self, mock_shell, mock_isfile):  # pylint: disable=unused-argument
        util = osutil.DefaultOSUtil()
        self.assertEqual("", util.get_instance_id())

    @patch('os.path.isfile', return_value=True)
    @patch('azurelinuxagent.common.utils.fileutil.read_file')
    def test_is_current_instance_id_from_file(self, mock_read, mock_isfile):  # pylint: disable=unused-argument
        util = osutil.DefaultOSUtil()

        mock_read.return_value = "11111111-2222-3333-4444-556677889900"
        self.assertFalse(util.is_current_instance_id(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502"))

        mock_read.return_value = "B9F3C233-9913-9F42-8EB3-BA656DF32502"
        self.assertTrue(util.is_current_instance_id(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502"))

        mock_read.return_value = "33C2F3B9-1399-429F-8EB3-BA656DF32502"
        self.assertTrue(util.is_current_instance_id(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502"))

        mock_read.return_value = "b9f3c233-9913-9f42-8eb3-ba656df32502"
        self.assertTrue(util.is_current_instance_id(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502"))

        mock_read.return_value = "33c2f3b9-1399-429f-8eb3-ba656df32502"
        self.assertTrue(util.is_current_instance_id(
            "B9F3C233-9913-9F42-8EB3-BA656DF32502"))

    @patch('os.path.isfile', return_value=False)
    @patch('azurelinuxagent.common.utils.shellutil.run_get_output')
    def test_is_current_instance_id_from_dmidecode(self, mock_shell, mock_isfile):  # pylint: disable=unused-argument
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

    @staticmethod
    def _command_to_string(command):
        return " ".join(command) if isinstance(command, list) else command

    @staticmethod
    @contextlib.contextmanager
    def _mock_iptables(version=osutil._IPTABLES_LOCKING_VERSION, destination='168.63.129.16'):
        """
        Mock for the iptable commands used to set up the firewall.

        Returns a patch of subprocess.Popen augmented with these properties:

            * wait - True if the iptable commands use the -w option
            * destination - The target IP address
            * uid - The uid used for the -owner option
            * command_calls - A list of the iptable commands executed by the mock (the --version and -L commands are omitted)
            * set_command - By default all the mocked commands succeed and produce no output; this method can be used to override
                  the return value and output of these commands (or to add other commands)
        """
        mocked_commands = {}

        def set_command(command, output='', exit_code=0):
            command_string = TestOSUtil._command_to_string(command)
            mocked_commands[command_string] = (output.replace("'", "'\"'\"'"), exit_code)
            return command_string

        wait = "-w" if FlexibleVersion(version) >= osutil._IPTABLES_LOCKING_VERSION else ""
        uid = 42

        version_command = set_command(osutil.get_iptables_version_command(), output=str(version))
        list_command = set_command(osutil.get_firewall_list_command(wait), output="Mock Output")
        set_command(osutil.get_firewall_packets_command(wait))
        set_command(AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND, destination, wait=wait))
        set_command(AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.APPEND_COMMAND, destination, wait=wait))
        set_command(AddFirewallRules.get_wire_root_accept_rule(AddFirewallRules.CHECK_COMMAND, destination, uid, wait=wait))
        set_command(AddFirewallRules.get_wire_root_accept_rule(AddFirewallRules.APPEND_COMMAND, destination, uid, wait=wait))
        set_command(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.APPEND_COMMAND, destination, wait=wait))
        set_command(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.INSERT_COMMAND, destination, wait=wait))
        set_command(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND, destination, wait=wait))
        # the agent assumes the rules have been deleted when these commands return 1
        set_command(osutil.get_firewall_delete_conntrack_accept_command(wait, destination), exit_code=1)
        set_command(osutil.get_delete_accept_tcp_rule(wait, destination), exit_code=1)
        set_command(osutil.get_firewall_delete_owner_accept_command(wait, destination, uid), exit_code=1)
        set_command(osutil.get_firewall_delete_conntrack_drop_command(wait, destination), exit_code=1)

        command_calls = []

        def mock_popen(command, *args, **kwargs):
            command_string = TestOSUtil._command_to_string(command)
            if command_string in mocked_commands:
                if command_string != version_command and command_string != list_command:
                    command_calls.append(command_string)
                output, exit_code = mocked_commands[command_string]
                command = "echo '{0}' && exit {1}".format(output, exit_code)
                kwargs["shell"] = True
            return mock_popen.original(command, *args, **kwargs)
        mock_popen.original = subprocess.Popen

        with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", side_effect=mock_popen) as popen_patcher:
            with patch('os.getuid', return_value=uid):
                popen_patcher.wait = wait
                popen_patcher.destination = destination
                popen_patcher.uid = uid
                popen_patcher.set_command = set_command
                popen_patcher.command_calls = command_calls

                yield popen_patcher

    def test_get_firewall_dropped_packets_returns_zero_if_firewall_disabled(self):
        with patch.object(osutil, '_enable_firewall', False):
            util = osutil.DefaultOSUtil()

            self.assertEqual(0, util.get_firewall_dropped_packets("not used"))

    def test_get_firewall_dropped_packets_returns_negative_if_error(self):
        with TestOSUtil._mock_iptables() as mock_iptables:
            with patch.object(osutil, '_enable_firewall', True):
                mock_iptables.set_command(osutil.get_firewall_packets_command(mock_iptables.wait), exit_code=1)
                self.assertEqual(-1, osutil.DefaultOSUtil().get_firewall_dropped_packets())

    def test_get_firewall_dropped_packets_should_ignore_transient_errors(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with patch.object(osutil, '_enable_firewall', True):
                mock_iptables.set_command(osutil.get_firewall_packets_command(mock_iptables.wait), exit_code=3, output="can't initialize iptables table `security': iptables who? (do you need to insmod?)")
                self.assertEqual(0, osutil.DefaultOSUtil().get_firewall_dropped_packets())

    def test_get_firewall_dropped_packets_should_ignore_returncode_4(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with patch.object(osutil, '_enable_firewall', True):
                mock_iptables.set_command(osutil.get_firewall_packets_command(mock_iptables.wait), exit_code=4, output="iptables v1.8.2 (nf_tables): RULE_REPLACE failed (Invalid argument): rule in chain OUTPUT")
                self.assertEqual(0, osutil.DefaultOSUtil().get_firewall_dropped_packets())

    def test_get_firewall_dropped_packets(self):

        destination = '168.63.129.16'

        with TestOSUtil._mock_iptables() as mock_iptables:
            with patch.object(osutil, '_enable_firewall', True):

                mock_iptables.set_command(osutil.get_firewall_packets_command(mock_iptables.wait), output='''
    
    Chain OUTPUT (policy ACCEPT 104 packets, 43628 bytes)
        pkts      bytes target     prot opt in     out     source               destination
           0        0 ACCEPT     tcp  --  any    any     anywhere             168.63.129.16        owner UID match daemon
          32     1920 DROP       tcp  --  any    any     anywhere             168.63.129.16
    
    ''')
                self.assertEqual(32, osutil.DefaultOSUtil().get_firewall_dropped_packets(destination))

    def test_enable_firewall_should_set_up_the_firewall(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with patch.object(osutil, '_enable_firewall', True):
                # fail the rule check to force enable of the firewall
                mock_iptables.set_command(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination,
                                                                               wait=mock_iptables.wait), exit_code=0)
                mock_iptables.set_command(AddFirewallRules.get_wire_root_accept_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination, mock_iptables.uid,
                                                                                     wait=mock_iptables.wait), exit_code=0)
                mock_iptables.set_command(AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination,
                                                                                       wait=mock_iptables.wait), exit_code=1)

                success, _ = osutil.DefaultOSUtil().enable_firewall(dst_ip=mock_iptables.destination, uid=mock_iptables.uid)

                tcp_check_command = TestOSUtil._command_to_string(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination,
                                                                               wait=mock_iptables.wait))
                accept_check_command = TestOSUtil._command_to_string(AddFirewallRules.get_wire_root_accept_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination, mock_iptables.uid,
                                                                                                                wait=mock_iptables.wait))
                drop_check_command = TestOSUtil._command_to_string(AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination,
                                                                                                                wait=mock_iptables.wait))
                delete_conntrack_accept_command = TestOSUtil._command_to_string(osutil.get_firewall_delete_conntrack_accept_command(mock_iptables.wait, mock_iptables.destination))
                delete_accept_tcp_rule = TestOSUtil._command_to_string(osutil.get_delete_accept_tcp_rule(mock_iptables.wait, mock_iptables.destination))
                delete_owner_accept_command = TestOSUtil._command_to_string(osutil.get_firewall_delete_owner_accept_command(mock_iptables.wait, mock_iptables.destination, mock_iptables.uid))
                delete_conntrack_drop_command = TestOSUtil._command_to_string(osutil.get_firewall_delete_conntrack_drop_command(mock_iptables.wait, mock_iptables.destination))
                accept_tcp_command = TestOSUtil._command_to_string(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.APPEND_COMMAND, mock_iptables.destination, wait=mock_iptables.wait))
                accept_command = TestOSUtil._command_to_string(AddFirewallRules.get_wire_root_accept_rule(AddFirewallRules.APPEND_COMMAND, mock_iptables.destination, mock_iptables.uid, wait=mock_iptables.wait))
                drop_add_command = TestOSUtil._command_to_string(AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.APPEND_COMMAND, mock_iptables.destination, wait=mock_iptables.wait))

                self.assertTrue(success, "Enabling the firewall was not successful")
                # Exactly 10 calls have to be made.
                # First is the check rule check which was mocked to fail, and delete call and then append calls
                self.assertEqual(len(mock_iptables.command_calls), 10, "Incorrect number of calls to iptables: [{0}]". format(mock_iptables.command_calls))
                self.assertEqual(mock_iptables.command_calls[0], tcp_check_command, "The first command should check the tcp rule")
                self.assertEqual(mock_iptables.command_calls[1], accept_check_command, "The second command should check the accept rule")
                self.assertEqual(mock_iptables.command_calls[2], drop_check_command, "The third command should check the drop rule")
                self.assertEqual(mock_iptables.command_calls[3], delete_conntrack_accept_command,
                                 "The fourth command should delete the conntrack accept rule: {0}".format(
                                     mock_iptables.command_calls[3]))
                self.assertEqual(mock_iptables.command_calls[4], delete_accept_tcp_rule,
                                 "The fifth command should delete the dns tcp accept rule: {0}".format(
                                     mock_iptables.command_calls[4]))
                self.assertEqual(mock_iptables.command_calls[5], delete_owner_accept_command,
                                 "The sixth command should delete the owner accept rule: {0}".format(
                                     mock_iptables.command_calls[5]))
                self.assertEqual(mock_iptables.command_calls[6], delete_conntrack_drop_command,
                                 "The seventh command should delete the conntrack accept rule : {0}".format(
                                     mock_iptables.command_calls[6]))
                self.assertEqual(mock_iptables.command_calls[7], accept_tcp_command,
                                "The eighth command should add the dns tcp accept rule")
                self.assertEqual(mock_iptables.command_calls[8], accept_command, "The ninth command should add the accept rule")
                self.assertEqual(mock_iptables.command_calls[9], drop_add_command, "The tenth command should add the drop rule")

                self.assertTrue(osutil._enable_firewall, "The firewall should not have been disabled")

    def test_enable_firewall_should_not_use_wait_when_iptables_does_not_support_it(self):
        with TestOSUtil._mock_iptables(version=osutil._IPTABLES_LOCKING_VERSION - 1) as mock_iptables:
            with patch.object(osutil, '_enable_firewall', True):
                # fail the rule check to force enable of the firewall
                mock_iptables.set_command(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination,
                                                                               wait=mock_iptables.wait), exit_code=1)
                mock_iptables.set_command(AddFirewallRules.get_wire_root_accept_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination, mock_iptables.uid,
                                                                                     wait=mock_iptables.wait), exit_code=1)
                mock_iptables.set_command(AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination,
                                                                                       wait=mock_iptables.wait), exit_code=1)

                success, _ = osutil.DefaultOSUtil().enable_firewall(dst_ip=mock_iptables.destination, uid=mock_iptables.uid)

                self.assertTrue(success, "Enabling the firewall was not successful")
                # Exactly 8 calls have to be made.
                # First check rule, delete 4 rules,
                # and Append the IPTable 3 rules.
                self.assertEqual(len(mock_iptables.command_calls), 8,
                                 "Incorrect number of calls to iptables: [{0}]".format(mock_iptables.command_calls))
                for command in mock_iptables.command_calls:
                    self.assertNotIn("-w", command, "The -w option should have been used in {0}".format(command))

                self.assertTrue(osutil._enable_firewall, "The firewall should not have been disabled")

    def test_enable_firewall_should_not_set_firewall_if_the_all_the_rules_exists(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with patch.object(osutil, '_enable_firewall', True):
                tcp_check_command = mock_iptables.set_command(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination,
                                                                               wait=mock_iptables.wait), exit_code=0)
                accept_check_command = mock_iptables.set_command(AddFirewallRules.get_wire_root_accept_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination, mock_iptables.uid,
                                                                                                            wait=mock_iptables.wait), exit_code=0)
                drop_check_command = mock_iptables.set_command(AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination,
                                                                                                            wait=mock_iptables.wait), exit_code=0)

                success, _ = osutil.DefaultOSUtil().enable_firewall(dst_ip=mock_iptables.destination, uid=mock_iptables.uid)

                self.assertTrue(success, "Enabling the firewall was not successful")
                self.assertEqual(len(mock_iptables.command_calls), 3, "Incorrect number of calls to iptables: [{0}]". format(mock_iptables.command_calls))
                self.assertEqual(mock_iptables.command_calls[0], tcp_check_command, "Unexpected command: {0}".format(mock_iptables.command_calls[0]))
                self.assertEqual(mock_iptables.command_calls[1], accept_check_command, "Unexpected command: {0}".format(mock_iptables.command_calls[1]))
                self.assertEqual(mock_iptables.command_calls[2], drop_check_command, "Unexpected command: {0}".format(mock_iptables.command_calls[2]))

                self.assertTrue(osutil._enable_firewall)

    def test_enable_firewall_should_check_for_invalid_iptables_options(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with patch.object(osutil, '_enable_firewall', True):
                # iptables uses the following exit codes
                #  0 - correct function
                #  1 - other errors
                #  2 - errors which appear to be caused by invalid or abused command
                #      line parameters
                tcp_check_command = mock_iptables.set_command(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination,
                                                                               wait=mock_iptables.wait), exit_code=0)
                accept_check_command = mock_iptables.set_command(AddFirewallRules.get_wire_root_accept_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination, mock_iptables.uid,
                                                                                                            wait=mock_iptables.wait), exit_code=0)
                drop_check_command = mock_iptables.set_command(AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND, mock_iptables.destination,
                                                                                                            wait=mock_iptables.wait), exit_code=2)

                success, _ = osutil.DefaultOSUtil().enable_firewall(dst_ip=mock_iptables.destination, uid=mock_iptables.uid)

                delete_conntrack_accept_command = TestOSUtil._command_to_string(osutil.get_firewall_delete_conntrack_accept_command(mock_iptables.wait, mock_iptables.destination))
                delete_accept_tcp_rule = TestOSUtil._command_to_string(osutil.get_delete_accept_tcp_rule(mock_iptables.wait, mock_iptables.destination))
                delete_owner_accept_command = TestOSUtil._command_to_string(osutil.get_firewall_delete_owner_accept_command(mock_iptables.wait, mock_iptables.destination, mock_iptables.uid))
                delete_conntrack_drop_command = TestOSUtil._command_to_string(osutil.get_firewall_delete_conntrack_drop_command(mock_iptables.wait, mock_iptables.destination))

                self.assertFalse(success, "Enable firewall should have failed")
                self.assertEqual(len(mock_iptables.command_calls), 7, "Incorrect number of calls to iptables: [{0}]". format(mock_iptables.command_calls))
                self.assertEqual(mock_iptables.command_calls[0], tcp_check_command, "The first command should check the tcp rule: {0}".format(mock_iptables.command_calls[0]))
                self.assertEqual(mock_iptables.command_calls[1], accept_check_command, "The second command should check the accept rule: {0}".format(mock_iptables.command_calls[1]))
                self.assertEqual(mock_iptables.command_calls[2], drop_check_command, "The third command should check the drop rule: {0}".format(mock_iptables.command_calls[2]))
                self.assertEqual(mock_iptables.command_calls[3], delete_conntrack_accept_command, "The fourth command should delete the conntrack accept rule: {0}".format(mock_iptables.command_calls[3]))
                self.assertEqual(mock_iptables.command_calls[4], delete_accept_tcp_rule,
                                 "The fifth command should delete the dns tcp accept rule: {0}".format(
                                     mock_iptables.command_calls[4]))
                self.assertEqual(mock_iptables.command_calls[5], delete_owner_accept_command, "The sixth command should delete the owner accept rule: {0}".format(mock_iptables.command_calls[5]))
                self.assertEqual(mock_iptables.command_calls[6], delete_conntrack_drop_command, "The seventh command should delete the conntrack accept rule : {0}".format(mock_iptables.command_calls[6]))

                self.assertFalse(osutil._enable_firewall)

    def test_enable_firewall_skips_if_disabled(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with patch.object(osutil, '_enable_firewall', False):
                success, _ = osutil.DefaultOSUtil().enable_firewall(dst_ip=mock_iptables.destination, uid=mock_iptables.uid)

                self.assertFalse(success, "The firewall should not have been disabled")
                self.assertEqual(len(mock_iptables.command_calls), 0, "iptables should not have been invoked: [{0}]". format(mock_iptables.command_calls))

                self.assertFalse(osutil._enable_firewall)

    def test_remove_firewall(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with patch.object(osutil, '_enable_firewall', True):
                delete_commands = {}

                def mock_popen(command, *args, **kwargs):
                    command_string = TestOSUtil._command_to_string(command)
                    if AddFirewallRules.DELETE_COMMAND in command_string:
                        # The agent invokes the delete commands continuously until they return 1 to indicate the rules has been removed
                        # The mock returns 0 (success) the first time it is invoked and 1 (rule does not exist) thereafter
                        if command_string not in delete_commands:
                            exit_code = 0
                            delete_commands[command_string] = 1
                        else:
                            exit_code = 1
                            delete_commands[command_string] += 1

                        command = "echo '' && exit {0}".format(exit_code)
                        kwargs["shell"] = True
                    return mock_popen.original(command, *args, **kwargs)
                mock_popen.original = subprocess.Popen

                with patch("azurelinuxagent.ga.cgroupapi.subprocess.Popen", side_effect=mock_popen):
                    success = osutil.DefaultOSUtil().remove_firewall(mock_iptables.destination, mock_iptables.uid, mock_iptables.wait)

                    delete_conntrack_accept_command = TestOSUtil._command_to_string(osutil.get_firewall_delete_conntrack_accept_command(mock_iptables.wait, mock_iptables.destination))
                    delete_accept_tcp_rule = TestOSUtil._command_to_string(
                        osutil.get_delete_accept_tcp_rule(mock_iptables.wait, mock_iptables.destination))
                    delete_owner_accept_command = TestOSUtil._command_to_string(osutil.get_firewall_delete_owner_accept_command(mock_iptables.wait, mock_iptables.destination, mock_iptables.uid))
                    delete_conntrack_drop_command = TestOSUtil._command_to_string(osutil.get_firewall_delete_conntrack_drop_command(mock_iptables.wait, mock_iptables.destination))

                    self.assertTrue(success, "Removing the firewall should have succeeded")
                    self.assertEqual(len(delete_commands), 4, "Expected 4 delete commands: [{0}]".format(delete_commands))
                    # delete rules < 2.2.26
                    self.assertIn(delete_accept_tcp_rule, delete_commands, "The delete dns tcp accept command was not executed")
                    self.assertEqual(delete_commands[delete_accept_tcp_rule], 2, "The delete dns tcp accept command should have been executed twice")
                    self.assertIn(delete_conntrack_accept_command, delete_commands, "The delete conntrack accept command was not executed")
                    self.assertEqual(delete_commands[delete_conntrack_accept_command], 2, "The delete conntrack accept command should have been executed twice")
                    self.assertIn(delete_owner_accept_command, delete_commands, "The delete owner accept command was not executed")
                    self.assertEqual(delete_commands[delete_owner_accept_command], 2, "The delete owner accept command should have been executed twice")
                    # delete rules >= 2.2.26
                    self.assertIn(delete_conntrack_drop_command, delete_commands, "The delete conntrack drop command was not executed")
                    self.assertEqual(delete_commands[delete_conntrack_drop_command], 2, "The delete conntrack drop command should have been executed twice")

                    self.assertTrue(osutil._enable_firewall)

    def test_remove_firewall_should_not_retry_invalid_rule(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with patch.object(osutil, '_enable_firewall', True):
                command = osutil.get_firewall_delete_conntrack_accept_command(mock_iptables.wait, mock_iptables.destination)
                # Note that the command is actually a valid rule, but we use the mock to report it as invalid (exit code 2)
                delete_conntrack_accept_command = mock_iptables.set_command(command, exit_code=2)

                success = osutil.DefaultOSUtil().remove_firewall(mock_iptables.destination, mock_iptables.uid, mock_iptables.wait)

                self.assertFalse(success, "Removing the firewall should not have succeeded")
                self.assertEqual(len(mock_iptables.command_calls), 1, "Expected a single call to iptables: [{0}]". format(mock_iptables.command_calls))
                self.assertEqual(mock_iptables.command_calls[0], delete_conntrack_accept_command, "Expected call to delete conntrack accept command: {0}".format(mock_iptables.command_calls[0]))

                self.assertFalse(osutil._enable_firewall)

    @skip_if_predicate_true(is_python_version_26_or_34, "Disabled on Python 2.6 and 3.4 for now. Need to revisit to fix it")
    def test_get_nic_state(self):
        state = osutil.DefaultOSUtil().get_nic_state()
        self.assertNotEqual(state, {})
        self.assertGreater(len(state.keys()), 1)

        another_state = osutil.DefaultOSUtil().get_nic_state()
        name = list(another_state.keys())[0]
        another_state[name].add_ipv4("xyzzy")
        self.assertNotEqual(state, another_state)

        as_string = osutil.DefaultOSUtil().get_nic_state(as_string=True)
        self.assertNotEqual(as_string, '')

    def test_get_used_and_available_system_memory(self):
        memory_table = "\
              total        used        free      shared  buff/cache   available \n\
Mem:     8340144128   619352064  5236809728     1499136  2483982336  7426314240   \n\
Swap:             0           0           0   \n"
        with patch.object(shellutil, 'run_command', return_value=memory_table):
            used_mem, available_mem = osutil.DefaultOSUtil().get_used_and_available_system_memory()

        self.assertEqual(used_mem, 619352064/(1024**2), "The value didn't match")
        self.assertEqual(available_mem, 7426314240/(1024**2), "The value didn't match")

    def test_get_used_and_available_system_memory_error(self):
        msg = 'message'
        exception = shellutil.CommandError("free -d", 1, "", msg)

        with patch.object(shellutil, 'run_command',
                          side_effect=exception) as patch_run:
            with self.assertRaises(shellutil.CommandError) as context_manager:
                osutil.DefaultOSUtil().get_used_and_available_system_memory()
            self.assertEqual(patch_run.call_count, 1)
            self.assertEqual(context_manager.exception.returncode, 1)

    def test_get_dhcp_pid_should_return_a_list_of_pids(self):
        osutil_get_dhcp_pid_should_return_a_list_of_pids(self, osutil.DefaultOSUtil())

    def test_get_dhcp_pid_should_return_an_empty_list_when_the_dhcp_client_is_not_running(self):
        original_run_command = shellutil.run_command

        def mock_run_command(cmd):  # pylint: disable=unused-argument
            return original_run_command(["pidof", "non-existing-process"])

        with patch("azurelinuxagent.common.utils.shellutil.run_command", side_effect=mock_run_command):
            pid_list = osutil.DefaultOSUtil().get_dhcp_pid()

        self.assertTrue(len(pid_list) == 0, "the return value is not an empty list: {0}".format(pid_list))

    @patch('os.walk', return_value=[('host3/target3:0:1/3:0:1:0/block', ['sdb'], [])])
    @patch('azurelinuxagent.common.utils.fileutil.read_file', return_value='{00000000-0001-8899-0000-000000000000}')
    @patch('os.listdir', return_value=['00000000-0001-8899-0000-000000000000'])
    @patch('os.path.exists', return_value=True)
    def test_device_for_ide_port_gen1_success(
            self,
            os_path_exists,  # pylint: disable=unused-argument
            os_listdir,  # pylint: disable=unused-argument
            fileutil_read_file,  # pylint: disable=unused-argument
            os_walk):  # pylint: disable=unused-argument
        dev = osutil.DefaultOSUtil().device_for_ide_port(1)
        self.assertEqual(dev, 'sdb', 'The returned device should be the resource disk')

    @patch('os.walk', return_value=[('host0/target0:0:0/0:0:0:1/block', ['sdb'], [])])
    @patch('azurelinuxagent.common.utils.fileutil.read_file', return_value='{f8b3781a-1e82-4818-a1c3-63d806ec15bb}')
    @patch('os.listdir', return_value=['f8b3781a-1e82-4818-a1c3-63d806ec15bb'])
    @patch('os.path.exists', return_value=True)
    def test_device_for_ide_port_gen2_success(
            self,
            os_path_exists,  # pylint: disable=unused-argument
            os_listdir,  # pylint: disable=unused-argument
            fileutil_read_file,  # pylint: disable=unused-argument
            os_walk):  # pylint: disable=unused-argument
        dev = osutil.DefaultOSUtil().device_for_ide_port(1)
        self.assertEqual(dev, 'sdb', 'The returned device should be the resource disk')

    @patch('os.listdir', return_value=['00000000-0000-0000-0000-000000000000'])
    @patch('os.path.exists', return_value=True)
    def test_device_for_ide_port_none(
            self,
            os_path_exists,  # pylint: disable=unused-argument
            os_listdir):  # pylint: disable=unused-argument
        dev = osutil.DefaultOSUtil().device_for_ide_port(1)
        self.assertIsNone(dev, 'None should be returned if no resource disk found')


def osutil_get_dhcp_pid_should_return_a_list_of_pids(test_instance, osutil_instance):
    """
    This is a very basic test for osutil.get_dhcp_pid. It is simply meant to exercise the implementation of that method
    in case there are any basic errors, such as a typos, etc. The test does not verify that the implementation returns
    the PID for the actual dhcp client; in fact, it uses a mock that invokes pidof to return the PID of an arbitrary
    process (the pidof process itself). Most implementations of get_dhcp_pid use pidof with the appropriate name for
    the dhcp client.
    The test is defined as a global function to make it easily accessible from the test suites for each distro.
    """
    original_run_command = shellutil.run_command

    def mock_run_command(cmd):  # pylint: disable=unused-argument
        return original_run_command(["pidof", "pidof"])

    with patch("azurelinuxagent.common.utils.shellutil.run_command", side_effect=mock_run_command):
        pid = osutil_instance.get_dhcp_pid()

    test_instance.assertTrue(len(pid) != 0, "get_dhcp_pid did not return a PID")


class TestGetPublishedHostname(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.__published_hostname = os.path.join(self.tmp_dir, "published_hostname")
        self.__patcher = patch('azurelinuxagent.common.osutil.default.conf.get_published_hostname', return_value=self.__published_hostname)
        self.__patcher.start()

    def tearDown(self):
        self.__patcher.stop()
        AgentTestCase.tearDown(self)

    def __get_published_hostname_contents(self):
        with open(self.__published_hostname, "r") as file_:
            return file_.read()

    def test_get_hostname_record_should_create_published_hostname(self):
        actual = osutil.DefaultOSUtil().get_hostname_record()

        expected = socket.gethostname()
        self.assertEqual(expected, actual, "get_hostname_record returned an incorrect hostname")
        self.assertTrue(os.path.exists(self.__published_hostname), "The published_hostname file was not created")
        self.assertEqual(expected, self.__get_published_hostname_contents(), "get_hostname_record returned an incorrect hostname")

    def test_get_hostname_record_should_use_existing_published_hostname(self):
        expected = "a-sample-hostname-used-for-testing"
        with open(self.__published_hostname, "w") as file_:
            file_.write(expected)

        actual = osutil.DefaultOSUtil().get_hostname_record()

        self.assertEqual(expected, actual, "get_hostname_record returned an incorrect hostname")
        self.assertEqual(expected, self.__get_published_hostname_contents(), "get_hostname_record returned an incorrect hostname")

    def test_get_hostname_record_should_initialize_the_host_name_using_cloud_init_info(self):
        with MockEnvironment(self.tmp_dir, files=[('/var/lib/cloud/data/set-hostname', os.path.join(data_dir, "cloud-init", "set-hostname"))]):
            actual = osutil.DefaultOSUtil().get_hostname_record()

        expected = "a-sample-set-hostname"
        self.assertEqual(expected, actual, "get_hostname_record returned an incorrect hostname")
        self.assertEqual(expected, self.__get_published_hostname_contents(), "get_hostname_record returned an incorrect hostname")


if __name__ == '__main__':
    unittest.main()
