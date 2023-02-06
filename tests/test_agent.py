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

import os.path

from azurelinuxagent.agent import parse_args, Agent, usage, AgentCommands
from azurelinuxagent.common import cgroupconfigurator, conf, logcollector
from azurelinuxagent.common.cgroupapi import SystemdCgroupsApi
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.ga.collect_logs import CollectLogsHandler
from tests.tools import AgentTestCase, data_dir, Mock, patch

EXPECTED_CONFIGURATION = \
"""AutoUpdate.Enabled = True
AutoUpdate.GAFamily = Prod
Autoupdate.Frequency = 3600
DVD.MountPoint = /mnt/cdrom/secure
Debug.AgentCpuQuota = 50
Debug.AgentCpuThrottledTimeThreshold = 120
Debug.AgentMemoryQuota = 31457280
Debug.AutoUpdateHotfixFrequency = 14400
Debug.AutoUpdateNormalFrequency = 86400
Debug.CgroupCheckPeriod = 300
Debug.CgroupDisableOnProcessCheckFailure = True
Debug.CgroupDisableOnQuotaCheckFailure = True
Debug.CgroupLogMetrics = False
Debug.CgroupMonitorExpiryTime = 2022-03-31
Debug.CgroupMonitorExtensionName = Microsoft.Azure.Monitor.AzureMonitorLinuxAgent
Debug.EnableAgentMemoryUsageCheck = False
Debug.EnableFastTrack = True
Debug.EnableGAVersioning = False
Debug.EtpCollectionPeriod = 300
Debug.FirewallRulesLogPeriod = 86400
DetectScvmmEnv = False
EnableOverProvisioning = True
Extension.LogDir = /var/log/azure
Extensions.Enabled = True
Extensions.GoalStatePeriod = 6
Extensions.InitialGoalStatePeriod = 6
GAUpdates.Enabled = True
HttpProxy.Host = None
HttpProxy.Port = None
Lib.Dir = /var/lib/waagent
Logs.Collect = True
Logs.CollectPeriod = 3600
Logs.Console = True
Logs.Verbose = False
OS.AllowHTTP = False
OS.CheckRdmaDriver = False
OS.EnableFIPS = True
OS.EnableFirewall = False
OS.EnableFirewallPeriod = 300
OS.EnableRDMA = False
OS.HomeDir = /home
OS.MonitorDhcpClientRestartPeriod = 30
OS.OpensslPath = /usr/bin/openssl
OS.PasswordPath = /etc/shadow
OS.RemovePersistentNetRulesPeriod = 30
OS.RootDeviceScsiTimeout = 300
OS.RootDeviceScsiTimeoutPeriod = 30
OS.SshClientAliveInterval = 42
OS.SshDir = /notareal/path
OS.SudoersDir = /etc/sudoers.d
OS.UpdateRdmaDriver = False
Pid.File = /var/run/waagent.pid
Provisioning.Agent = auto
Provisioning.AllowResetSysUser = False
Provisioning.DecodeCustomData = False
Provisioning.DeleteRootPassword = True
Provisioning.ExecuteCustomData = False
Provisioning.MonitorHostName = True
Provisioning.MonitorHostNamePeriod = 30
Provisioning.PasswordCryptId = 6
Provisioning.PasswordCryptSaltLength = 10
Provisioning.RegenerateSshHostKeyPair = True
Provisioning.SshHostKeyPairType = rsa
ResourceDisk.EnableSwap = False
ResourceDisk.EnableSwapEncryption = False
ResourceDisk.Filesystem = ext4
ResourceDisk.Format = True
ResourceDisk.MountOptions = None
ResourceDisk.MountPoint = /mnt/resource
ResourceDisk.SwapSizeMB = 0""".split('\n')


class TestAgent(AgentTestCase):

    def test_accepts_configuration_path(self):
        conf_path = os.path.join(data_dir, "test_waagent.conf")
        c, f, v, d, cfp, lcm, _ = parse_args(["-configuration-path:" + conf_path])  # pylint: disable=unused-variable
        self.assertEqual(cfp, conf_path)

    @patch("os.path.exists", return_value=True)
    def test_checks_configuration_path(self, mock_exists):
        conf_path = "/foo/bar-baz/something.conf"
        c, f, v, d, cfp, lcm, _ = parse_args(["-configuration-path:"+conf_path])  # pylint: disable=unused-variable
        self.assertEqual(cfp, conf_path)
        self.assertEqual(mock_exists.call_count, 1)

    @patch("sys.stderr")
    @patch("os.path.exists", return_value=False)
    @patch("sys.exit", side_effect=Exception)
    def test_rejects_missing_configuration_path(self, mock_exit, mock_exists, mock_stderr):  # pylint: disable=unused-argument
        try:
            c, f, v, d, cfp, lcm, _ = parse_args(["-configuration-path:/foo/bar.conf"])  # pylint: disable=unused-variable
        except Exception:
            self.assertEqual(mock_exit.call_count, 1)

    def test_configuration_path_defaults_to_none(self):
        c, f, v, d, cfp, lcm, _ = parse_args([])  # pylint: disable=unused-variable
        self.assertEqual(cfp, None)

    def test_agent_accepts_configuration_path(self):
        Agent(False, conf_file_path=os.path.join(data_dir, "test_waagent.conf"))
        self.assertTrue(conf.get_fips_enabled())

    @patch("azurelinuxagent.common.conf.load_conf_from_file")
    def test_agent_uses_default_configuration_path(self, mock_load):
        Agent(False)
        mock_load.assert_called_once_with("/etc/waagent.conf")

    @patch("azurelinuxagent.daemon.get_daemon_handler")
    @patch("azurelinuxagent.common.conf.load_conf_from_file")
    def test_agent_does_not_pass_configuration_path(self,
                mock_load, mock_handler):

        mock_daemon = Mock()
        mock_daemon.run = Mock()
        mock_handler.return_value = mock_daemon

        agent = Agent(False)
        agent.daemon()

        mock_daemon.run.assert_called_once_with(child_args=None)
        self.assertEqual(1, mock_load.call_count)

    @patch("azurelinuxagent.daemon.get_daemon_handler")
    @patch("azurelinuxagent.common.conf.load_conf_from_file")
    def test_agent_passes_configuration_path(self, mock_load, mock_handler):

        mock_daemon = Mock()
        mock_daemon.run = Mock()
        mock_handler.return_value = mock_daemon

        agent = Agent(False, conf_file_path="/foo/bar.conf")
        agent.daemon()

        mock_daemon.run.assert_called_once_with(child_args="-configuration-path:/foo/bar.conf")
        self.assertEqual(1, mock_load.call_count)

    @patch("azurelinuxagent.common.conf.get_ext_log_dir")
    def test_agent_ensures_extension_log_directory(self, mock_dir):
        ext_log_dir = os.path.join(self.tmp_dir, "FauxLogDir")
        mock_dir.return_value = ext_log_dir

        self.assertFalse(os.path.isdir(ext_log_dir))
        agent = Agent(False,  # pylint: disable=unused-variable
                    conf_file_path=os.path.join(data_dir, "test_waagent.conf"))
        self.assertTrue(os.path.isdir(ext_log_dir))

    @patch("azurelinuxagent.common.logger.error")
    @patch("azurelinuxagent.common.conf.get_ext_log_dir")
    def test_agent_logs_if_extension_log_directory_is_a_file(self, mock_dir, mock_log):
        ext_log_dir = os.path.join(self.tmp_dir, "FauxLogDir")
        mock_dir.return_value = ext_log_dir
        fileutil.write_file(ext_log_dir, "Foo")

        self.assertTrue(os.path.isfile(ext_log_dir))
        self.assertFalse(os.path.isdir(ext_log_dir))
        agent = Agent(False,  # pylint: disable=unused-variable
                      conf_file_path=os.path.join(data_dir, "test_waagent.conf"))
        self.assertTrue(os.path.isfile(ext_log_dir))
        self.assertFalse(os.path.isdir(ext_log_dir))
        self.assertEqual(1, mock_log.call_count)

    def test_agent_get_configuration(self):
        Agent(False, conf_file_path=os.path.join(data_dir, "test_waagent.conf"))

        actual_configuration = []
        configuration = conf.get_configuration()
        for k in sorted(configuration.keys()):
            actual_configuration.append("{0} = {1}".format(k, configuration[k]))
        self.assertListEqual(EXPECTED_CONFIGURATION, actual_configuration)

    def test_checks_log_collector_mode(self):
        # Specify full mode
        c, f, v, d, cfp, lcm, _ = parse_args(["-collect-logs", "-full"])  # pylint: disable=unused-variable
        self.assertEqual(c, "collect-logs")
        self.assertEqual(lcm, True)

        # Defaults to None if mode not specified
        c, f, v, d, cfp, lcm, _ = parse_args(["-collect-logs"])  # pylint: disable=unused-variable
        self.assertEqual(c, "collect-logs")
        self.assertEqual(lcm, False)

    @patch("sys.stderr")
    @patch("sys.exit", side_effect=Exception)
    def test_rejects_invalid_log_collector_mode(self, mock_exit, mock_stderr):  # pylint: disable=unused-argument
        try:
            c, f, v, d, cfp, lcm, _ = parse_args(["-collect-logs", "-notvalid"])  # pylint: disable=unused-variable
        except Exception:
            self.assertEqual(mock_exit.call_count, 1)

    @patch("os.path.exists", return_value=True)
    @patch("azurelinuxagent.agent.LogCollector")
    def test_calls_collect_logs_with_proper_mode(self, mock_log_collector, *args):  # pylint: disable=unused-argument
        agent = Agent(False, conf_file_path=os.path.join(data_dir, "test_waagent.conf"))
        mock_log_collector.run = Mock()

        agent.collect_logs(is_full_mode=True)
        full_mode = mock_log_collector.call_args_list[0][0][0]
        self.assertTrue(full_mode)

        agent.collect_logs(is_full_mode=False)
        full_mode = mock_log_collector.call_args_list[1][0][0]
        self.assertFalse(full_mode)

    @patch("azurelinuxagent.agent.LogCollector")
    def test_calls_collect_logs_on_valid_cgroups(self, mock_log_collector):
        try:
            CollectLogsHandler.enable_cgroups_validation()
            mock_log_collector.run = Mock()

            def mock_cgroup_paths(*args, **kwargs):
                if args and args[0] == "self":
                    relative_path = "{0}/{1}".format(cgroupconfigurator.LOGCOLLECTOR_SLICE, logcollector.CGROUPS_UNIT)
                    return (cgroupconfigurator.LOGCOLLECTOR_SLICE, relative_path)
                return SystemdCgroupsApi.get_process_cgroup_relative_paths(*args, **kwargs)

            with patch("azurelinuxagent.agent.SystemdCgroupsApi.get_process_cgroup_paths", side_effect=mock_cgroup_paths):
                agent = Agent(False, conf_file_path=os.path.join(data_dir, "test_waagent.conf"))
                agent.collect_logs(is_full_mode=True)
                
                mock_log_collector.assert_called_once()
        finally:
            CollectLogsHandler.disable_cgroups_validation()

    @patch("azurelinuxagent.agent.LogCollector")
    def test_doesnt_call_collect_logs_on_invalid_cgroups(self, mock_log_collector):
        try:
            CollectLogsHandler.enable_cgroups_validation()
            mock_log_collector.run = Mock()

            def mock_cgroup_paths(*args, **kwargs):
                if args and args[0] == "self":
                    return ("NOT_THE_CORRECT_PATH", "NOT_THE_CORRECT_PATH")
                return SystemdCgroupsApi.get_process_cgroup_relative_paths(*args, **kwargs)

            with patch("azurelinuxagent.agent.SystemdCgroupsApi.get_process_cgroup_paths", side_effect=mock_cgroup_paths):
                agent = Agent(False, conf_file_path=os.path.join(data_dir, "test_waagent.conf"))

                exit_error = RuntimeError("Exiting")
                with patch("sys.exit", return_value=exit_error) as mock_exit:
                    try:
                        agent.collect_logs(is_full_mode=True)
                    except RuntimeError as re:
                        mock_exit.assert_called_once_with(logcollector.INVALID_CGROUPS_ERRCODE)
                        self.assertEqual(exit_error, re)
        finally:
            CollectLogsHandler.disable_cgroups_validation()
        
    def test_it_should_parse_setup_firewall_properly(self):

        test_firewall_meta = {
            "dst_ip": "1.2.3.4",
            "uid": "9999",
            "wait": "-w"
        }
        cmd, _, _, _, _, _, firewall_metadata = parse_args(
            ["-{0}".format(AgentCommands.SetupFirewall), "-dst_ip=1.2.3.4", "-uid=9999", "-w"])

        self.assertEqual(cmd, AgentCommands.SetupFirewall)
        self.assertEqual(firewall_metadata, test_firewall_meta)

        # Defaults to None if command is different
        test_firewall_meta = {
            "dst_ip": None,
            "uid": None,
            "wait": ""
        }
        cmd, _, _, _, _, _, firewall_metadata = parse_args(["-{0}".format(AgentCommands.Help)])
        self.assertEqual(cmd, AgentCommands.Help)
        self.assertEqual(test_firewall_meta, firewall_metadata)

    def test_it_should_ignore_empty_arguments(self):

        test_firewall_meta = {
            "dst_ip": "1.2.3.4",
            "uid": "9999",
            "wait": ""
        }
        cmd, _, _, _, _, _, firewall_metadata = parse_args(
            ["-{0}".format(AgentCommands.SetupFirewall), "-dst_ip=1.2.3.4", "-uid=9999", ""])

        self.assertEqual(cmd, AgentCommands.SetupFirewall)
        self.assertEqual(firewall_metadata, test_firewall_meta)

    def test_agent_usage_message(self):
        message = usage()

        # Python 2.6 does not have assertIn()
        self.assertTrue("-verbose" in message)
        self.assertTrue("-force" in message)
        self.assertTrue("-help" in message)
        self.assertTrue("-configuration-path" in message)
        self.assertTrue("-deprovision" in message)
        self.assertTrue("-register-service" in message)
        self.assertTrue("-version" in message)
        self.assertTrue("-daemon" in message)
        self.assertTrue("-start" in message)
        self.assertTrue("-run-exthandlers" in message)
        self.assertTrue("-show-configuration" in message)
        self.assertTrue("-collect-logs" in message)

        # sanity check
        self.assertFalse("-not-a-valid-option" in message)
