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
import sys

import uuid

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.ga.persist_firewall_rules import PersistFirewallRulesHandler
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.common.utils.networkutil import AddFirewallRules, FirewallCmdDirectCommands
from tests.lib.tools import AgentTestCase, MagicMock, patch


class TestPersistFirewallRulesHandler(AgentTestCase):

    original_popen = subprocess.Popen

    def __init__(self, *args, **kwargs):
        super(TestPersistFirewallRulesHandler, self).__init__(*args, **kwargs)
        self._expected_service_name = ""
        self._expected_service_name = ""
        self._binary_file = ""
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

        self.__tmp_conf_lib = os.path.join(self.tmp_dir, "waagent")
        fileutil.mkdir(self.__tmp_conf_lib)
        conf.get_lib_dir = MagicMock(return_value=self.__tmp_conf_lib)

    def tearDown(self):
        shutil.rmtree(self.__systemd_dir, ignore_errors=True)
        shutil.rmtree(self.__agent_bin_dir, ignore_errors=True)
        shutil.rmtree(self.__tmp_conf_lib, ignore_errors=True)
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

        self._expected_service_name = PersistFirewallRulesHandler._AGENT_NETWORK_SETUP_NAME_FORMAT.format(
            osutil.get_service_name())

        self._network_service_unit_file = os.path.join(self.__systemd_dir, self._expected_service_name)
        self._binary_file = os.path.join(conf.get_lib_dir(), PersistFirewallRulesHandler.BINARY_FILE_NAME)

        # Just for these tests, ignoring the mode of mkdir to allow non-sudo tests
        orig_mkdir = fileutil.mkdir
        with patch("azurelinuxagent.ga.persist_firewall_rules.fileutil.mkdir",
                   side_effect=lambda path, **mode: orig_mkdir(path)):
            with patch("azurelinuxagent.ga.persist_firewall_rules.get_osutil", return_value=osutil):
                with patch('azurelinuxagent.common.osutil.systemd.is_systemd', return_value=systemd):
                    with patch("azurelinuxagent.common.utils.shellutil.subprocess.Popen", side_effect=self.__mock_popen):
                        yield PersistFirewallRulesHandler(self.__test_dst_ip, self.__test_uid)

    def __assert_firewall_called(self, cmd, validate_command_called=True):
        if validate_command_called:
            self.assertIn(AddFirewallRules.get_wire_root_accept_rule(command=AddFirewallRules.APPEND_COMMAND,
                                                                     destination=self.__test_dst_ip,
                                                                     owner_uid=self.__test_uid,
                                                                     firewalld_command=cmd),
                          self.__executed_commands, "Firewall {0} command not found".format(cmd))
            self.assertIn(AddFirewallRules.get_wire_non_root_drop_rule(command=AddFirewallRules.APPEND_COMMAND,
                                                                       destination=self.__test_dst_ip,
                                                                       firewalld_command=cmd),
                          self.__executed_commands, "Firewall {0} command not found".format(cmd))
        else:
            self.assertNotIn(AddFirewallRules.get_wire_root_accept_rule(command=AddFirewallRules.APPEND_COMMAND,
                                                                        destination=self.__test_dst_ip,
                                                                        owner_uid=self.__test_uid,
                                                                        firewalld_command=cmd),
                             self.__executed_commands,
                             "Firewall {0} command found".format(cmd))
            self.assertNotIn(AddFirewallRules.get_wire_non_root_drop_rule(command=AddFirewallRules.APPEND_COMMAND,
                                                                          destination=self.__test_dst_ip,
                                                                          firewalld_command=cmd),
                             self.__executed_commands, "Firewall {0} command found".format(cmd))

    def __assert_systemctl_called(self, cmd="enable", validate_command_called=True):
        systemctl_command = ["systemctl", cmd, self._expected_service_name]
        if validate_command_called:
            self.assertIn(systemctl_command, self.__executed_commands, "Systemctl command {0} not found".format(cmd))
        else:
            self.assertNotIn(systemctl_command, self.__executed_commands, "Systemctl command {0} found".format(cmd))

    def __assert_systemctl_reloaded(self, validate_command_called=True):
        systemctl_reload = ["systemctl", "daemon-reload"]
        if validate_command_called:
            self.assertIn(systemctl_reload, self.__executed_commands, "Systemctl config not reloaded")
        else:
            self.assertNotIn(systemctl_reload, self.__executed_commands, "Systemctl config reloaded")

    def __assert_firewall_cmd_running_called(self, validate_command_called=True):
        cmd = PersistFirewallRulesHandler._FIREWALLD_RUNNING_CMD
        if validate_command_called:
            self.assertIn(cmd, self.__executed_commands, "Firewall state not checked")
        else:
            self.assertNotIn(cmd, self.__executed_commands, "Firewall state not checked")

    def __assert_network_service_setup_properly(self):
        self.__assert_systemctl_called(cmd="is-enabled", validate_command_called=True)
        self.__assert_systemctl_called(cmd="enable", validate_command_called=True)
        self.__assert_systemctl_reloaded()
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=False)
        self.assertTrue(os.path.exists(self._network_service_unit_file), "Service unit file should be there")
        self.assertTrue(os.path.exists(self._binary_file), "Binary file should be there")

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

    @staticmethod
    def __mock_firewalld_running_and_not_applied(cmd):
        if cmd == PersistFirewallRulesHandler._FIREWALLD_RUNNING_CMD:
            return True, ["echo", "running"]
        # This is to fail the check if firewalld-rules are already applied
        cmds_to_fail = ["firewall-cmd", FirewallCmdDirectCommands.QueryPassThrough, "conntrack"]
        if all(cmd_to_fail in cmd for cmd_to_fail in cmds_to_fail):
            return True, ["exit", "1"]
        if "firewall-cmd" in cmd:
            return True, ["echo", "enabled"]
        return False, []

    @staticmethod
    def __mock_firewalld_running_and_remove_not_successful(cmd):
        if cmd == PersistFirewallRulesHandler._FIREWALLD_RUNNING_CMD:
            return True, ["echo", "running"]
        # This is to fail the check if firewalld-rules are already applied
        cmds_to_fail = ["firewall-cmd", FirewallCmdDirectCommands.QueryPassThrough, "conntrack"]
        if all(cmd_to_fail in cmd for cmd_to_fail in cmds_to_fail):
            return True, ["exit", "1"]
        # This is to fail the remove if firewalld-rules fails to remove rule
        cmds_to_fail = ["firewall-cmd", FirewallCmdDirectCommands.RemovePassThrough, "conntrack"]
        if all(cmd_to_fail in cmd for cmd_to_fail in cmds_to_fail):
            return True, ["exit", "2"]
        if "firewall-cmd" in cmd:
            return True, ["echo", "enabled"]
        return False, []

    def __setup_and_assert_network_service_setup_scenario(self, handler, mock_popen=None):
        mock_popen = TestPersistFirewallRulesHandler.__mock_network_setup_service_disabled if mock_popen is None else mock_popen
        self.__replace_popen_cmd = mock_popen
        handler.setup()

        self.__assert_systemctl_called(cmd="is-enabled", validate_command_called=True)
        self.__assert_systemctl_called(cmd="enable", validate_command_called=True)
        self.__assert_systemctl_reloaded(validate_command_called=True)
        self.__assert_firewall_cmd_running_called(validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.QueryPassThrough, validate_command_called=False)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.RemovePassThrough, validate_command_called=False)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=False)
        self.assertTrue(os.path.exists(handler.get_service_file_path()), "Service unit file not found")

    def test_it_should_skip_setup_if_firewalld_already_enabled(self):
        self.__replace_popen_cmd = lambda cmd: ("firewall-cmd" in cmd, ["echo", "running"])
        with self._get_persist_firewall_rules_handler() as handler:
            handler.setup()

        # Assert we verified that rules were set using firewall-cmd
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.QueryPassThrough, validate_command_called=True)
        # Assert no commands for adding rules using firewall-cmd were called
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.RemovePassThrough, validate_command_called=False)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=False)
        # Assert no commands for systemctl were called
        self.assertFalse(any("systemctl" in cmd for cmd in self.__executed_commands), "Systemctl shouldn't be called")

    def test_it_should_skip_setup_if_agent_network_setup_service_already_enabled_and_version_same(self):

        with self._get_persist_firewall_rules_handler() as handler:
            # 1st time should setup the service
            self.__setup_and_assert_network_service_setup_scenario(handler)

            # 2nd time setup should do nothing as service is enabled and no version updated
            self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_enabled
            # Reset state
            self.__executed_commands = []
            handler.setup()

            self.__assert_systemctl_called(cmd="is-enabled", validate_command_called=True)
            self.__assert_systemctl_called(cmd="enable", validate_command_called=False)
            self.__assert_systemctl_reloaded(validate_command_called=False)
            self.__assert_firewall_cmd_running_called(validate_command_called=True)
            self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.QueryPassThrough, validate_command_called=False)
            self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.RemovePassThrough, validate_command_called=False)
            self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=False)
            self.assertTrue(os.path.exists(handler.get_service_file_path()), "Service unit file not found")

    def test_it_should_always_replace_binary_file_only_if_using_custom_network_service(self):

        def _find_in_file(file_name, line_str):
            try:
                with open(file_name, 'r') as fh:
                    content = fh.read()
                    return line_str in content
            except Exception:
                # swallow exception
                pass
            return False

        test_str = 'os.system("{py_path} {egg_path} --setup-firewall --dst_ip={wire_ip} --uid={user_id} {wait}")'
        current_exe_path = os.path.join(os.getcwd(), sys.argv[0])

        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_disabled
        with self._get_persist_firewall_rules_handler() as handler:
            self.assertFalse(os.path.exists(self._binary_file), "Binary file should not be there")
            self.assertFalse(os.path.exists(self._network_service_unit_file), "Unit file should not be present")
            handler.setup()

        orig_service_file_contents = "ExecStart={py_path} {binary_path}".format(py_path=sys.executable,
                                                                                binary_path=self._binary_file)
        self.__assert_systemctl_called(cmd="is-enabled", validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=False)
        self.assertTrue(os.path.exists(self._binary_file), "Binary file should be there")
        self.assertTrue(_find_in_file(self._binary_file,
                                      test_str.format(py_path=sys.executable, egg_path=current_exe_path,
                                                      wire_ip=self.__test_dst_ip, user_id=self.__test_uid,
                                                      wait=self.__test_wait)),
                        "Binary file not set correctly")
        self.assertTrue(_find_in_file(self._network_service_unit_file, orig_service_file_contents),
                        "Service Unit file file not set correctly")

        # Change test params
        self.__test_dst_ip = "9.8.7.6"
        self.__test_uid = 5555
        self.__test_wait = ""
        # The service should say its enabled now
        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_enabled
        with self._get_persist_firewall_rules_handler() as handler:
            # The Binary file should be available on the 2nd run
            self.assertTrue(os.path.exists(self._binary_file), "Binary file should be there")
            handler.setup()

        self.assertTrue(_find_in_file(self._binary_file,
                                      test_str.format(py_path=sys.executable, egg_path=current_exe_path,
                                                      wire_ip=self.__test_dst_ip, user_id=self.__test_uid,
                                                      wait=self.__test_wait)),
                        "Binary file not updated correctly")
        # Unit file should NOT be updated
        self.assertTrue(_find_in_file(self._network_service_unit_file, orig_service_file_contents),
                        "Service Unit file file should not be updated")

    def test_it_should_use_firewalld_if_available(self):

        self.__replace_popen_cmd = self.__mock_firewalld_running_and_not_applied
        with self._get_persist_firewall_rules_handler() as handler:
            handler.setup()

        self.__assert_firewall_cmd_running_called(validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.QueryPassThrough, validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.RemovePassThrough, validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=True)
        self.assertFalse(any("systemctl" in cmd for cmd in self.__executed_commands), "Systemctl shouldn't be called")

    def test_it_should_add_firewalld_rules_if_remove_raises_exception(self):

        self.__replace_popen_cmd = self.__mock_firewalld_running_and_remove_not_successful
        with self._get_persist_firewall_rules_handler() as handler:
            handler.setup()

        self.__assert_firewall_cmd_running_called(validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.QueryPassThrough, validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.RemovePassThrough, validate_command_called=True)
        self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=True)
        self.assertFalse(any("systemctl" in cmd for cmd in self.__executed_commands), "Systemctl shouldn't be called")

    def test_it_should_set_up_custom_service_if_no_firewalld(self):
        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_disabled
        with self._get_persist_firewall_rules_handler() as handler:
            self.assertFalse(os.path.exists(self._network_service_unit_file), "Service unit file should not be there")
            self.assertFalse(os.path.exists(self._binary_file), "Binary file should not be there")
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
            test_files = [self._binary_file, self._network_service_unit_file]
            for file_to_fail in test_files:
                files_to_fail = [file_to_fail]
                with patch("azurelinuxagent.ga.persist_firewall_rules.fileutil.write_file",
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

    def test_it_should_execute_binary_file_successfully(self):
        # A bare-bone test to ensure no simple syntactical errors in the binary file as its generated dynamically
        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_disabled
        with self._get_persist_firewall_rules_handler() as handler:
            self.assertFalse(os.path.exists(self._binary_file), "Binary file should not be there")
            handler.setup()

            self.assertTrue(os.path.exists(self._binary_file), "Binary file not set properly")

            shellutil.run_command([sys.executable, self._binary_file])

    def test_it_should_not_fail_if_egg_not_found(self):
        self.__replace_popen_cmd = TestPersistFirewallRulesHandler.__mock_network_setup_service_disabled
        test_str = str(uuid.uuid4())
        with patch("sys.argv", [test_str]):
            with self._get_persist_firewall_rules_handler() as handler:
                self.assertFalse(os.path.exists(self._binary_file), "Binary file should not be there")
                handler.setup()
                output = shellutil.run_command([sys.executable, self._binary_file], stderr=subprocess.STDOUT)
                expected_str = "{0} file not found, skipping execution of firewall execution setup for this boot".format(
                    os.path.join(os.getcwd(), test_str))
                self.assertIn(expected_str, output, "Unexpected output")

    def test_it_should_delete_custom_service_files_if_firewalld_enabled(self):
        with self._get_persist_firewall_rules_handler() as handler:
            # 1st run - Setup the Custom Service
            self.__setup_and_assert_network_service_setup_scenario(handler)

            # 2nd run - Enable Firewalld and ensure the agent sets firewall rules using firewalld and deletes custom service
            self.__executed_commands = []
            self.__replace_popen_cmd = self.__mock_firewalld_running_and_not_applied
            handler.setup()

            self.__assert_firewall_cmd_running_called(validate_command_called=True)
            self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.QueryPassThrough, validate_command_called=True)
            self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.RemovePassThrough, validate_command_called=True)
            self.__assert_firewall_called(cmd=FirewallCmdDirectCommands.PassThrough, validate_command_called=True)
            self.__assert_systemctl_called(cmd="is-enabled", validate_command_called=False)
            self.__assert_systemctl_called(cmd="enable", validate_command_called=False)
            self.__assert_systemctl_reloaded(validate_command_called=False)
            self.assertFalse(os.path.exists(handler.get_service_file_path()), "Service unit file found")
            self.assertFalse(os.path.exists(os.path.join(conf.get_lib_dir(), handler.BINARY_FILE_NAME)), "Binary file found")

    def test_it_should_reset_service_unit_files_if_version_changed(self):
        with self._get_persist_firewall_rules_handler() as handler:
            # 1st step - Setup the service with old Version
            test_ver = str(uuid.uuid4())
            with patch.object(handler, "_UNIT_VERSION", test_ver):
                self.__setup_and_assert_network_service_setup_scenario(handler)
                self.assertIn(test_ver, fileutil.read_file(handler.get_service_file_path()), "Test version not found")

            # 2nd step - Re-run the setup and ensure the service file set up again even if service enabled
            self.__executed_commands = []
            self.__setup_and_assert_network_service_setup_scenario(handler,
                                                                   mock_popen=self.__mock_network_setup_service_enabled)
            self.assertNotIn(test_ver, fileutil.read_file(handler.get_service_file_path()),
                             "Test version found incorrectly")
