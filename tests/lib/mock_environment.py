# -*- coding: utf-8 -*-
# Copyright 2020 Microsoft Corporation
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
import os
import re
import shutil
import subprocess

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import fileutil
from tests.lib.tools import patch, patch_builtin


class MockCommand:
    def __init__(self, command, stdout='', return_value=0, stderr=''):
        self.command = command
        self.stdout = stdout
        self.return_value = return_value
        self.stderr = stderr

    def __str__(self):
        return ' '.join(self.command) if isinstance(self.command, list) else self.command


class MockEnvironment:
    """
    A MockEnvironment is a Context Manager that can be used to mock a set of commands, file system paths, and/or files.
    It can be useful in tests that need to execute commands or access/modify files that are not available in all platforms,
    or require root privileges, or can change global system settings. For a sample usage see the mock_cgroup_environment()
    function.

    Currently, MockEnvironment mocks subprocess.Popen(), fileutil.mkdir(), os.path.exists() and the builtin() open function
    (it mocks fileutil.mkdir() instead od os.mkdir() because the agent's code users the former since it provides
    backwards compatibility with Python 2).

    The mock for Popen looks for a match in the given 'commands' and, if found, forwards the call to the mock_command.py,
    which produces the output specified by the matching item. Otherwise it forwards the call to the original Popen function.

    The mocks for the other functions first look for a match in the given 'files' array and, if found, map the file to the
    corresponding path in the matching item (if the mapping points to an Exception, the Exception is raised). If there is no
    match, then it checks if the file is included in the given 'paths' array and maps the path to the given 'tmp_dir'
    (e.g. "/lib/systemd/system" becomes "<tmp_dir>/lib/systemd/system".) If there no matches, the path is not changed.
    Once this mapping has completed the mocks invoke the corresponding original function.

    Matches are done using regular expressions; the regular expressions in 'paths' must create group 0 to indicate
    the section of the path that needs to be mapped (i.e. use parenthesis around the section that needs to be mapped.)

    The items in the given 'data_files' are copied to the 'tmp_dir'.

    The add_*() methods insert new items int the list of mock objects. Items added by these methods take precedence over
    the items provided to the __init__() method.
    """
    def __init__(self, tmp_dir, commands=None, paths=None, files=None, data_files=None):
        # make a copy of the arrays passed as arguments since individual tests can modify them
        self.tmp_dir = tmp_dir
        self.commands = [] if commands is None else commands[:]
        self.paths = [] if paths is None else paths[:]
        self.files = [] if files is None else files[:]
        self._data_files = data_files

        # get references to the functions we'll mock so that we can call the original implementations
        self._original_popen = subprocess.Popen
        self._original_mkdir = fileutil.mkdir
        self._original_path_exists = os.path.exists
        self._original_open = open

        self.patchers = [
            patch_builtin("open", side_effect=self._mock_open),
            patch("subprocess.Popen", side_effect=self._mock_popen),
            patch("os.path.exists", side_effect=self._mock_path_exists),
            patch("azurelinuxagent.common.utils.fileutil.mkdir", side_effect=self._mock_mkdir)
        ]

    def __enter__(self):
        if self._data_files is not None:
            for items in self._data_files:
                self.add_data_file(items[0], items[1])

        try:
            for patcher in self.patchers:
                patcher.start()
        except Exception:
            self._stop_patchers()
            raise

        return self

    def __exit__(self, *_):
        self._stop_patchers()

    def _stop_patchers(self):
        for patcher in self.patchers:
            try:
                patcher.stop()
            except Exception:
                pass

    def add_command(self, command):
        self.commands.insert(0, command)

    def add_path(self, mock):
        self.paths.insert(0, mock)

    def add_file(self, actual, mock):
        self.files.insert(0, (actual, mock))

    def add_data_file(self, source, target):
        shutil.copyfile(source, self.get_mapped_path(target))

    def get_mapped_path(self, path):
        for item in self.files:
            match = re.match(item[0], path)
            if match is not None:
                return item[1]

        for item in self.paths:
            mapped = re.sub(item, r"{0}\1".format(self.tmp_dir), path)
            if mapped != path:
                mapped_parent = os.path.split(mapped)[0]
                if not self._original_path_exists(mapped_parent):
                    os.makedirs(mapped_parent)
                return mapped
        return path

    def _mock_popen(self, command, *args, **kwargs):
        if isinstance(command, list):
            command_string = " ".join(command)
        else:
            command_string = command

        for cmd in self.commands:
            match = re.match(cmd.command, command_string)
            if match is not None:
                mock_script = os.path.join(os.path.split(__file__)[0], "mock_command.py")
                if 'shell' in kwargs and kwargs['shell']:
                    command = "{0} '{1}' {2} '{3}'".format(mock_script, cmd.stdout, cmd.return_value, cmd.stderr)
                else:
                    command = [mock_script, cmd.stdout, ustr(cmd.return_value), cmd.stderr]
                break

        return self._original_popen(command, *args, **kwargs)

    def _mock_mkdir(self, path, *args, **kwargs):
        return self._original_mkdir(self.get_mapped_path(path), *args, **kwargs)

    def _mock_open(self, path, *args, **kwargs):
        mapped_path = self.get_mapped_path(path)
        if isinstance(mapped_path, Exception):
            raise mapped_path
        return self._original_open(mapped_path, *args, **kwargs)

    def _mock_path_exists(self, path):
        return self._original_path_exists(self.get_mapped_path(path))

