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

import json
import re
import uuid
import contextlib
from enum import Enum
import subprocess

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.exception import ExtensionError
from tests.tools import Mock, patch

from tests.protocol.mocks import HttpRequestPredicates

from azurelinuxagent.ga.exthandlers import ExtHandlerInstance


class ExtensionCommandName(Enum):
    INSTALL = "install"
    UNINSTALL = "uninstall"
    UPDATE = "update"
    ENABLE = "enable"
    DISABLE = "disable"

class Actions(object):
    """
    A collection of static methods providing some basic functionality for the ExtensionEmulator
    class' actions.
    """

    @staticmethod
    def succeed_action(*args, **kwargs):
        """
        A nop action with the correct function signature for ExtensionEmulator actions.
        """
        return 0
    
    
    @staticmethod
    def fail_action(*args, **kwargs):
        """
        A simple fail action with the correct function signature for ExtensionEmulator actions.
        """
        raise ExtensionError("FailAction called.")

    @staticmethod
    def generate_unique_fail():
        """
        Utility function for tracking the return code of a command. Returns both a
        unique return code, and a function pointer which returns said return code.
        """
        return_code = str(uuid.uuid4())

        def fail_action(*args, **kwargs):
            return return_code
        
        return return_code, fail_action


def extension_emulator(name="OSTCExtensions.ExampleHandlerLinux", version="1.0.0",
    update_mode="UpdateWithInstall", report_heartbeat=False, continue_on_update_failure=False,
    install_action=Actions.succeed_action, uninstall_action=Actions.succeed_action, 
    enable_action=Actions.succeed_action, disable_action=Actions.succeed_action,
    update_action=Actions.succeed_action):
    """
    Factory method for ExtensionEmulator objects with sensible defaults.
    """
    
    return ExtensionEmulator(name, version,
        update_mode, report_heartbeat, continue_on_update_failure,
        _extend_func(install_action), _extend_func(uninstall_action),
        _extend_func(enable_action), _extend_func(disable_action),
        _extend_func(update_action))

@contextlib.contextmanager
def enable_invocations(*emulators):
    """
    Allows ExtHandlersHandler objects to call the specified emulators and keeps
    track of the order of those invocations. Returns the invocation record.

    Note that this method patches subprocess.Popen and
    ExtHandlerInstance.load_manifest.
    """
    invocation_record = InvocationRecord()

    patched_popen = generate_patched_popen(invocation_record, *emulators)
    patched_load_manifest = generate_mock_load_manifest(*emulators)
    
    with patch.object(ExtHandlerInstance, "load_manifest", patched_load_manifest):
        with patch("subprocess.Popen", patched_popen):
            yield invocation_record

def generate_put_handler(*emulators):
    """
    Create a HTTP handler to store status blobs for each provided emulator.
    For use with tests.protocol.mocks.mock_wire_protocol.
    """

    first_matching_emulator = lambda matches_func: next(emulator for emulator in emulators if matches_func(emulator))

    def mock_put_handler(url, *args, **kwargs):

        if HttpRequestPredicates.is_host_plugin_status_request(url):
            return None

        handler_statuses = json.loads(args[0]).get("aggregateStatus", {}).get("handlerAggregateStatus", [])

        for handler_status in handler_statuses:
            supplied_name = handler_status.get("handlerName", None)
            supplied_version = handler_status.get("handlerVersion", None)
            
            try:
                extension_emulator = first_matching_emulator(lambda ext: ext.matches(supplied_name, supplied_version))
                extension_emulator.status_blobs.append(handler_status)

            except StopIteration as e:
                # Tests will want to know that the agent is running an extension they didn't specifically allocate.
                raise Exception("Extension running, but not present in emulators: {0}, {1}".foramt(supplied_name, supplied_version))

    return mock_put_handler

class InvocationRecord:

    def __init__(self):
        self._queue = []

    def add(self, ext_name, ext_ver, ext_cmd):
        self._queue.append((ext_name, ext_ver, ext_cmd))

    def compare(self, *expected_cmds):
        """
        Verifies that any and all recorded invocations appear in the provided command list in that exact ordering.

        Each cmd in expected_cmds should be a tuple of the form (ExtensionEmulator, ExtensionCommandNames).
        """

        for (expected_ext_emulator, command_name) in expected_cmds:

            try:
                (ext_name, ext_ver, ext_cmd) = self._queue.pop(0)

                if not expected_ext_emulator.matches(ext_name, ext_ver) or command_name != ext_cmd:
                    raise Exception("Unexpected invocation: have ({0}, {1}, {2}), but expected ({3}, {4}, {5})".format(
                        ext_name, ext_ver, ext_cmd, expected_ext_emulator.name, expected_ext_emulator.version, command_name
                    ))

            except IndexError:
                raise Exception("No more invocations recorded. Expected ({0}, {1}, {2}).".format(expected_ext_emulator.name,
                    expected_ext_emulator.version, command_name))
        
        if self._queue:
            raise Exception("Invocation recorded, but not expected: ({0}, {1}, {2})".format(
                *self._queue[0]
            ))

class ExtensionEmulator:
    """
    A wrapper class for the possible actions and options that an extension might support.
    """

    def __init__(self, name, version,
        update_mode, report_heartbeat,
        continue_on_update_failure,
        install_action, uninstall_action,
        enable_action, disable_action,
        update_action):

        self.name = name
        self.version = version

        self.update_mode = update_mode
        self.report_heartbeat = report_heartbeat
        self.continue_on_update_failure = continue_on_update_failure

        self.actions = {
            ExtensionCommandName.INSTALL: install_action,
            ExtensionCommandName.UNINSTALL: uninstall_action,
            ExtensionCommandName.UPDATE: update_action,
            ExtensionCommandName.ENABLE: enable_action,
            ExtensionCommandName.DISABLE: disable_action
        }

        self.status_blobs = []
        
    
    def matches(self, name, version):
        return self.name == name and self.version == version

def generate_patched_popen(invocation_record, *emulators):
    """
    Create a mock popen function able to invoke the proper action for an extension
    emulator in emulators.
    """
    original_popen = subprocess.Popen

    first_matching_emulator = lambda matches_func: next(emulator for emulator in emulators if matches_func(emulator))
    
    def patched_popen(cmd, *args, **kwargs):

        try:
            ext_name, ext_version, command_name = _ExtractExtensionInfo.from_command(cmd)
            invocation_record.add(ext_name, ext_version, ExtensionCommandName(command_name))
        except ValueError:
            return original_popen(cmd, *args, **kwargs)
        
        try:
            extension_emulator = first_matching_emulator(lambda ext: ext.matches(ext_name, ext_version))
            return extension_emulator.actions[ExtensionCommandName(command_name)](cmd, *args, **kwargs)

        except StopIteration:
            raise Exception("Extension('{name}', '{version}') not listed as a parameter. Is it being emulated?".format(
                name=ext_name, version=ext_version
            ))

    return patched_popen

def generate_mock_load_manifest(*emulators):

    original_load_manifest = ExtHandlerInstance.load_manifest

    first_matching_emulator = lambda matches_func: next(emulator for emulator in emulators if matches_func(emulator))

    def mock_load_manifest(self):

        try:
            matching_emulator = first_matching_emulator(lambda ext: ext.matches(self.ext_handler.name,
                    self.ext_handler.properties.version))
        except StopIteration:
            raise Exception("Extension('{name}', '{version}') not listed as a parameter. Is it being emulated?".format(
                name=self.ext_handler.name, version=self.ext_handler.properties.version
            ))
                    
        base_manifest = original_load_manifest(self)

        base_manifest.data["handlerManifest"].update({
            "continueOnUpdateFailure": matching_emulator.continue_on_update_failure,
            "reportHeartbeat": matching_emulator.report_heartbeat,
            "updateMode": matching_emulator.update_mode
        })

        return base_manifest
    
    return mock_load_manifest

class _ExtractExtensionInfo:

    ext_name_regex = r'[a-zA-Z]+(?:\.[a-zA-Z]+)?'
    ext_ver_regex = r'[0-9]+(?:\.[0-9]+)*'

    @staticmethod
    def from_command(command):
        """
        Parse a command into a tuple of extension info.
        """
        if not isinstance(command, (str, ustr)):
            raise Exception("Cannot extract extension info from non-string commands")

        # Group layout of the expected command; this lets us grab what we want after a match
        template = r'(?<={base_dir}/)(?P<name>{ext_name})-(?P<ver>{ext_ver})(?:/{script_file} -)(?P<cmd>{ext_cmd})'

        base_dir_regex = conf.get_lib_dir()
        script_file_regex = r'[^\s]+'
        ext_cmd_regex = r'[a-zA-Z]+'

        full_regex = template.format(
            ext_name=_ExtractExtensionInfo.ext_name_regex,
            ext_ver=_ExtractExtensionInfo.ext_ver_regex, 
            base_dir=base_dir_regex, script_file=script_file_regex,
            ext_cmd=ext_cmd_regex
        )

        match_obj = re.search(full_regex, command)

        if not match_obj:
            raise ValueError("Command does not match the desired format: {0}".format(command))

        return match_obj.group('name', 'ver', 'cmd')


def _extend_func(func):
    """
    Convert a function such that its returned value mimicks a Popen object (i.e. with 
    correct return values for poll() and wait() calls).
    """
    
    def wrapped_func(cmd, *args, **kwargs):
        return_value = func(cmd, *args, **kwargs)

        return Mock(**{
            "poll.return_value": return_value,
            "wait.return_value": return_value
        })

    # Wrap the function in a mock to allow invocation reflection a la .assert_not_called(), etc.
    return Mock(wraps=wrapped_func)
