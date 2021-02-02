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
import contextlib
import os
import shutil
import subprocess
import uuid


from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.persist_firewall_rules import PersistFirewallRulesHandler
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.networkutil import AddFirewallRules, FirewallCmdDirectCommands
from tests.tools import AgentTestCase, MagicMock, patch


class TestPersistFirewallRulesHandler(AgentTestCase):

    original_popen = subprocess.Popen

    def __init__(self, *args, **kwargs):
        super(TestPersistFirewallRulesHandler, self).__init__(*args, **kwargs)
        self._expected_service_name = ""
        self._expected_service_name = ""
        self._drop_in_file = ""
        self._network_service_bin_file = ""
        self._network_service_unit_file = ""

    def setUp(self):
        AgentTestCase.setUp(self)
        # Override for mocking Popen, should be of the form - (True/False, cmd-to-execute-if-True)
        self.__replace_popen_cmd = lambda *_: (False, "")
        self.__executed_commands = []
        self.__test_dst_ip = "1.2.3.4"
        self.__test_uid = 9999
        self.__test_wait = "-w"

        self.__systemd_dir = os.path.join(self.tmp_dir, "system")
        fileutil.mkdir(self.__systemd_dir)
        self.__agent_bin_dir = os.path.join(self.tmp_dir, "bin")
        fileutil.mkdir(self.__agent_bin_dir)

    def tearDown(self):
        shutil.rmtree(self.__systemd_dir, ignore_errors=True)
        shutil.rmtree(self.__agent_bin_dir, ignore_errors=True)
        AgentTestCase.tearDown(self)

    def __mock_popen(self, cmd, *args, **kwargs):
        self.__executed_commands.append(cmd)
        replace_cmd, replace_with_command = self.__replace_popen_cmd(cmd)
        if replace_cmd:
            cmd = replace_with_command

        return TestPersistFirewallRulesHandler.original_popen(cmd, *args, **kwargs)

    @contextlib.contextmanager
    def _get_persist_firewall_rules_handler(self, systemd=True):

        osutil = DefaultOSUtil()
        osutil.get_firewall_will_wait = MagicMock(return_value=self.__test_wait)
        osutil.get_agent_bin_path = MagicMock(return_value=self.__agent_bin_dir)
        osutil.get_systemd_unit_file_install_path = MagicMock(return_value=self.__systemd_dir)

        # protected-access<W0212> Disabled: OK to access PersistFirewallRulesHandler._* from unit test for PersistFirewallRuleHandler
        self._expected_service_name = PersistFirewallRulesHandler._AGENT_NETWORK_SETUP_NAME_FORMAT.format(  # pylint: disable=protected-access
            osutil.get_service_name())

        self._network_service_unit_file = os.path.join(self.__systemd_dir, self._expected_service_name)
        self._drop_in_file = os.path.join(self.__systemd_dir, "{0}.d".format(self._expected_service_name),
                                          PersistFirewallRulesHandler._DROP_IN_ENV_FILE_NAME)  # pylint: disable=protected-access
        self._network_service_bin_file = os.path.join(self.__agent_bin_dir,
                                                      PersistFirewallRulesHandler._AGENT_NETWORK_SETUP_BIN_FILE)  # pylint: disable=protected-access

        # Just for these tests, ignoring the mode of mkdir to allow non-sudo tests
        orig_mkdir = fileutil.mkdir
        with patch("azurelinuxagent.common.persist_firewall_rules.fileutil.mkdir",
                   side_effect=lambda path, **mode: orig_mkdir(path)):
            with patch("azurelinuxagent.common.persist_firewall_rules.get_osutil", return_value=osutil):
                with patch('azurelinuxagent.common.cgroupapi.CGroupsApi.is_systemd', return_value=systemd):
                    with patch("azurelinuxagent.common.utils.shellutil.subprocess.Popen", side_effect=self.__mock_popen):
                        yield PersistFirewallRulesHandler(self.__test_dst_ip, self.__test_uid)

    def __assert_firewall_called(self, cmd, validate_command_called=True):
        if validate_command_called:
            self.assertIn(AddFirewallRules.get_firewalld_accept_command(wait=self.__test_wait,
                                                                        command=cmd,
                                                                        destination=self.__test_dst_ip,
                                                                        uid=self.__test_uid),
                          self.__executed_commands, "Firewall {0} command not found".format(cmd))
            self.assertIn(AddFirewallRules.get_firewalld_drop_command(wait=self.__test_wait,
                                                                      command=cmd,
                                                                      destination=self.__test_dst_ip),
                          self.__executed_commands, "Firewall {0} command not found".format(cmd))
        else:
            self.assertNotIn(AddFirewallRules.get_firewalld_accept_command(wait=self.__test_wait,
                                                                           command=cmd,
                                                                           destination=self.__test_dst_ip,
                                                                           uid=self.__test_uid),
                             self.__executed_commands,
                             "Firewall {0} command found".format(cmd))
            self.assertNotIn(AddFirewallRules.get_firewalld_drop_command(wait=self.__test_wait,
                                                                         command=cmd,
                                                                         destination=self.__test_dst_ip),
                             self.__executed_commands, "Firewall {0} command found".format(cmd))

    def __assert_systemctl_called(self, cmd="enable", validate_command_called=True):
        systemctl_command = ["systemctl", cmd, self._expected_service_name]
        if validate_command_called:
            self.assertIn(systemctl_command, self.__executed_commands, "Systemctl command {0} not found".format(cmd))
        else:
            self.assertNotIn(systemctl_command, self.__executed_commands, "Systemctl command {0} found".format(cmd))

    def __assert_firewall_cmd_running_called(self, validate_command_called=True):
        # protected-access<W0212> Disabled: OK to access PersistFirewallRulesHandler._* from unit test for PersistFirewallRuleHandler
        cmd = PersistFirewallRulesHandler._FIREWALLD_RUNNING_CMD    # pylint: disable=protected-access
        if validate_command_called:
            self.assertIn(cmd, self.__executed_commands, "Firewall state not checked")
        else:
            self.assertNotIn(cmd, self.__executed_commands, "Firewall state not checked")

    def __assert_network_service_setup_properly(self):
        self.__assert_systemctl_called(cmd="is-enabled", validate_command_called=True)
        self.__assert_systemctl_called(cmd="enable", validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=False)
        self.assertTrue(os.path.exists(self._network_service_unit_file), "Service unit file should be there")
        self.assertTrue(os.path.exists(self._drop_in_file), "Drop in file should be there")
        self.assertTrue(os.path.exists(self._network_service_bin_file), "Network setup Binary file should be there")

    @staticmethod
    def __mock_network_setup_service_enabled(cmd):
        if "firewall-cmd" in cmd:
            return True, ["echo", "not-running"]
        if "systemctl" in cmd:
            return True, ["echo", "enabled"]
        return False, []

    @staticmethod
    def __mock_network_setup_service_disabled(cmd):
        if "firewall-cmd" in cmd:
            return True, ["echo", "not-running"]
        if "systemctl" in cmd:
            return True, ["echo", "not enabled"]
        return False, []

    def test_it_should_skip_setup_if_firewalld_already_enabled(self):
        self.__replace_popen_cmd = lambda cmd: ("firewall-cmd" in cmd, ["echo", "running"])
        with self._get_persist_firewall_rules_handler() as handler:
            handler.setup()

        # Assert we verified that rules were set using firewall-cmd
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.QueryPassThrough, validate_command_called=True)
        # Assert no commands for adding rules using firewall-cmd were called
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=False)
        # Assert no commands for systemctl were called
        self.assertFalse(any(["systemctl" in cmd for cmd in self.__executed_commands]), "Systemctl shouldn't be called")

    def test_it_should_skip_setup_if_agent_network_setup_service_already_enabled(self):
        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_enabled
        with self._get_persist_firewall_rules_handler() as handler:
            handler.setup()

        self.__assert_systemctl_called(cmd="is-enabled", validate_command_called=True)
        self.__assert_systemctl_called(cmd="enabled", validate_command_called=False)
        self.__assert_firewall_cmd_running_called(validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.QueryPassThrough, validate_command_called=False)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=False)

    def test_it_should_always_replace_only_drop_in_file_if_using_custom_network_service(self):
        test_str = 'Environment="DST_IP={0}" "UID={1}" "WAIT={2}"'
        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_disabled
        with self._get_persist_firewall_rules_handler() as handler:
            self.assertFalse(os.path.exists(self._drop_in_file), "Drop in file should not be there")
            self.assertFalse(os.path.exists(self._network_service_unit_file), "Unit file should not be present")
            handler.setup()

        self.__assert_systemctl_called(cmd="is-enabled", validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=False)
        self.assertTrue(os.path.exists(self._drop_in_file), "Drop in file should be there")
        self.assertTrue(fileutil.findstr_in_file(self._drop_in_file, test_str.format(self.__test_dst_ip, self.__test_uid,
                                                                               self.__test_wait)),
                        "DropIn file not set correctly")
        self.assertTrue(fileutil.findstr_in_file(self._network_service_unit_file,
                                                 test_str.format(self.__test_dst_ip, self.__test_uid,
                                                                 self.__test_wait)),
                        "Service Unit file file not set correctly")

        # Change test params
        self.__test_dst_ip = "9.8.7.6"
        self.__test_uid = 5555
        self.__test_wait = ""
        # The service should say its enabled now
        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_enabled
        with self._get_persist_firewall_rules_handler() as handler:
            # The Drop-in file should be available on the 2nd run
            self.assertTrue(os.path.exists(self._drop_in_file), "Drop in file should be there")
            handler.setup()

        self.assertTrue(fileutil.findstr_in_file(self._drop_in_file, test_str.format(self.__test_dst_ip, self.__test_uid,
                                                                               self.__test_wait)),
                        "DropIn file not set correctly")
        # Unit file should NOT be updated
        self.assertFalse(fileutil.findstr_in_file(self._network_service_unit_file,
                                                  test_str.format(self.__test_dst_ip, self.__test_uid,
                                                                  self.__test_wait)),
                         "Service Unit file file should not be updated")

    def test_it_should_use_firewalld_if_available(self):

        def __mock_firewalld_running_and_not_applied(cmd):
            # protected-access<W0212> Disabled: OK to access PersistFirewallRulesHandler._* from unit test for PersistFirewallRuleHandler
            if cmd == PersistFirewallRulesHandler._FIREWALLD_RUNNING_CMD:   # pylint: disable=protected-access
                return True, ["echo", "running"]
            # This is to fail the check if firewalld-rules are already applied
            cmds_to_fail = ["firewall-cmd", FirewallCmdDirectCommands.QueryPassThrough, "conntrack"]
            if all([cmd_to_fail in cmd for cmd_to_fail in cmds_to_fail]):
                return True, ["exit", "1"]
            if "firewall-cmd" in cmd:
                return True, ["echo", "enabled"]
            return False, []

        self.__replace_popen_cmd = __mock_firewalld_running_and_not_applied
        with self._get_persist_firewall_rules_handler() as handler:
            handler.setup()

        self.__assert_firewall_cmd_running_called(validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.QueryPassThrough, validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=True)
        self.assertFalse(any(["systemctl" in cmd for cmd in self.__executed_commands]), "Systemctl shouldn't be called")

    def test_it_should_set_up_custom_service_if_no_firewalld(self):
        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_disabled
        with self._get_persist_firewall_rules_handler() as handler:
            self.assertFalse(os.path.exists(self._network_service_unit_file), "Service unit file should not be there")
            self.assertFalse(os.path.exists(self._drop_in_file), "Drop in file should not be there")
            self.assertFalse(os.path.exists(self._network_service_bin_file), "Network setup binary file file should not be there")
            handler.setup()

        self.__assert_network_service_setup_properly()

    def test_it_should_cleanup_files_on_error(self):

        orig_write_file = fileutil.write_file
        files_to_fail = []

        def mock_write_file(path, _, *__):
            if files_to_fail[0] in path:
                raise IOError("Invalid file: {0}".format(path))
            return orig_write_file(path, _, *__)

        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_disabled
        with self._get_persist_firewall_rules_handler() as handler:
            test_files = [self._drop_in_file, self._network_service_unit_file]
            for file_to_fail in test_files:
                files_to_fail = [file_to_fail]
                with patch("azurelinuxagent.common.persist_firewall_rules.fileutil.write_file",
                           side_effect=mock_write_file):
                    with self.assertRaises(Exception) as context_manager:
                        handler.setup()
                    self.assertIn("Invalid file: {0}".format(file_to_fail), ustr(context_manager.exception))
                    self.assertFalse(os.path.exists(file_to_fail), "File should be deleted: {0}".format(file_to_fail))

                # Cleanup remaining files for test clarity
                for test_file in test_files:
                    try:
                        os.remove(test_file)
                    except Exception:
                        pass

    def test_it_should_not_replace_network_setup_binary_file_if_available(self):

        guid = ustr(uuid.uuid4())

        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_disabled
        with self._get_persist_firewall_rules_handler() as handler:
            fileutil.write_file(self._network_service_bin_file, guid)
            self.assertTrue(os.path.exists(self._network_service_bin_file), "Bin file should be present")
            self.assertFalse(os.path.exists(self._network_service_unit_file), "Service unit file should not be there")
            self.assertFalse(os.path.exists(self._drop_in_file), "Drop in file should not be there")
            handler.setup()

        self.__assert_network_service_setup_properly()
        self.assertTrue(fileutil.findstr_in_file(self._network_service_bin_file, guid), "Bin file should not be updated")
