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
import os
import contextlib
import subprocess

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.ga.exthandlers import ExtHandlerInstance

from tests.tools import Mock, patch
from tests.protocol.mocks import HttpRequestPredicates


class ExtensionCommandNames(object):
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
    def succeed_action(*_, **__):
        """
        A nop action with the correct function signature for ExtensionEmulator actions.
        """
        return 0
    
    @staticmethod
    def generate_unique_fail():
        """
        Utility function for tracking the return code of a command. Returns both a
        unique return code, and a function pointer which returns said return code.
        """
        return_code = str(uuid.uuid4())

        def fail_action(*_, **__):
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
    # Linter reports too many arguments, but this isn't an issue because all are defaulted;
    # no caller will have to actually provide all of the arguments listed.
    
    return ExtensionEmulator(name, version, update_mode, report_heartbeat, continue_on_update_failure,
        install_action, uninstall_action, enable_action, disable_action, update_action)

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

    def mock_put_handler(url, *args, **_):

        if HttpRequestPredicates.is_host_plugin_status_request(url):
            return

        handler_statuses = json.loads(args[0]).get("aggregateStatus", {}).get("handlerAggregateStatus", [])

        for handler_status in handler_statuses:
            supplied_name = handler_status.get("handlerName", None)
            supplied_version = handler_status.get("handlerVersion", None)
            
            try:
                matching_ext = _first_matching_emulator(emulators, supplied_name, supplied_version)
                matching_ext.status_blobs.append(handler_status)

            except StopIteration:
                # Tests will want to know that the agent is running an extension they didn't specifically allocate.
                raise Exception("Extension running, but not present in emulators: {0}, {1}".format(supplied_name, supplied_version))

    return mock_put_handler

class InvocationRecord:

    def __init__(self):
        self._queue = []

    def add(self, ext_name, ext_ver, ext_cmd):
        self._queue.append((ext_name, ext_ver, ext_cmd))

    def compare(self, *expected_cmds):
        """
        Verifies that any and all recorded invocations appear in the provided command list in that exact ordering.

        Each cmd in expected_cmds should be a tuple of the form (ExtensionEmulator, ExtensionCommandNames object).
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

def _first_matching_emulator(emulators, name, version):
    for ext in emulators:
        if ext.matches(name, version):
            return ext
    
    raise StopIteration

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
        # Linter reports too many arguments, but this constructor has its access mediated by
        # a factory method; the calls affected by the number of arguments here is very
        # limited in scope. 

        self.name = name
        self.version = version

        self.update_mode = update_mode
        self.report_heartbeat = report_heartbeat
        self.continue_on_update_failure = continue_on_update_failure

        self._actions = {
            ExtensionCommandNames.INSTALL: ExtensionEmulator._extend_func(install_action),
            ExtensionCommandNames.UNINSTALL: ExtensionEmulator._extend_func(uninstall_action),
            ExtensionCommandNames.UPDATE: ExtensionEmulator._extend_func(update_action),
            ExtensionCommandNames.ENABLE: ExtensionEmulator._extend_func(enable_action),
            ExtensionCommandNames.DISABLE: ExtensionEmulator._extend_func(disable_action)
        }

        self._status_blobs = []

    @property
    def actions(self):
        """
        A read-only property designed to allow inspection for the emulated extension's
        actions. `actions` maps an ExtensionCommandNames object to a mock wrapping the
        function this emulator was initialized with.
        """
        return self._actions

    @property
    def status_blobs(self):
        """
        A property for storing and retreiving the status blobs for the extension this object
        is emulating that are uploaded to the HTTP PUT /status endpoint.
        """
        return self._status_blobs
    
    @staticmethod
    def _extend_func(func):
        """
        Convert a function such that its returned value mimicks a Popen object (i.e. with 
        correct return values for poll() and wait() calls).
        """
        
        def wrapped_func(cmd, *args, **kwargs):
            return_value = func(cmd, *args, **kwargs)

            config_dir = os.path.join(os.path.dirname(cmd), "config")
            
            regex = r'{directory}{sep}(?P<seq>{sequence})\.settings'.format(
                directory=config_dir, sep=os.path.sep, sequence=r'[0-9]+'
            )

            seq = 0
            for config_file in map(lambda filename: os.path.join(config_dir, filename), os.listdir(config_dir)):
                if not os.path.isfile(config_file):
                    continue

                match = re.match(regex, config_file)
                if not match:
                    continue

                if seq < int(match.group("seq")):
                    seq = int(match.group("seq"))
            
            status_file = os.path.join(os.path.dirname(cmd), "status", "{seq}.status".format(seq=seq))

            if return_value == 0:
                status_contents = [{ "status": {"status": "success"} }]
            else:
                status_contents = [{ "status": {"status": "error", "substatus": {"exit_code": return_value}} }]

            fileutil.write_file(status_file, json.dumps(status_contents))

            return Mock(**{
                "poll.return_value": return_value,
                "wait.return_value": return_value
            })

        # Wrap the function in a mock to allow invocation reflection a la .assert_not_called(), etc.
        return Mock(wraps=wrapped_func)
        
    
    def matches(self, name, version):
        return self.name == name and self.version == version

def generate_patched_popen(invocation_record, *emulators):
    """
    Create a mock popen function able to invoke the proper action for an extension
    emulator in emulators.
    """
    original_popen = subprocess.Popen

    def patched_popen(cmd, *args, **kwargs):

        try:
            ext_name, ext_version, command_name = _extract_extension_info_from_command(cmd)
            invocation_record.add(ext_name, ext_version, command_name)
        except ValueError:
            return original_popen(cmd, *args, **kwargs)
        
        try:
            matching_ext = _first_matching_emulator(emulators, ext_name, ext_version)

            return matching_ext.actions[command_name](cmd, *args, **kwargs)

        except StopIteration:
            raise Exception("Extension('{name}', '{version}') not listed as a parameter. Is it being emulated?".format(
                name=ext_name, version=ext_version
            ))

    return patched_popen

def generate_mock_load_manifest(*emulators):

    original_load_manifest = ExtHandlerInstance.load_manifest

    def mock_load_manifest(self):

        try:
            matching_emulator = _first_matching_emulator(emulators, self.ext_handler.name, self.ext_handler.properties.version)
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

def _extract_extension_info_from_command(command):
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
    ext_name_regex = r'[a-zA-Z]+(?:\.[a-zA-Z]+)?'
    ext_ver_regex = r'[0-9]+(?:\.[0-9]+)*'

    full_regex = template.format(
        ext_name=ext_name_regex,
        ext_ver=ext_ver_regex, 
        base_dir=base_dir_regex, script_file=script_file_regex,
        ext_cmd=ext_cmd_regex
    )

    match_obj = re.search(full_regex, command)

    if not match_obj:
        raise ValueError("Command does not match the desired format: {0}".format(command))

    return match_obj.group('name', 'ver', 'cmd')