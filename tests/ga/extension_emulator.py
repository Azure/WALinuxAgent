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
import zipfile
import subprocess

import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.conf as conf
from tests.tools import Mock


class Actions(object):
    """
    A collection of static methods providing some basic functionality for the ExtensionManifestInfo
    class' actions.
    """

    @staticmethod
    def succeed_action(*args, **kwargs):
        """
        A nop action with the correct function signature for ExtensionManifestInfo actions.
        """
        return 0
    
    
    @staticmethod
    def fail_action(*args, **kwargs):
        """
        A simple fail action with the correct function signature for ExtensionManifestInfo actions.
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
    """
    
    return ExtensionEmulator(name, version,
        update_mode, report_heartbeat, continue_on_update_failure,
        _extend_func(install_action), _extend_func(uninstall_action),
        _extend_func(enable_action), _extend_func(disable_action),
        _extend_func(update_action))


def generate_patched_popen(*emulators):
    """
    """
    invocation_record = InvocationRecord()
    
    original_popen = subprocess.Popen

    def patched_popen(cmd, *args, **kwargs):

        try:
            ext_name, ext_version, command_name = _ExtractExtensionInfo.from_command(cmd)
            invocation_record.add(ext_name, ext_version, command_name)
        except Exception:
            return original_popen(cmd, *args, **kwargs)
        
        try:
            return next(
                emulator.actions[command_name]
                for emulator in emulators
                if emulator.matches(ext_name, ext_version)
            )(cmd, *args, **kwargs)

        except StopIteration:
            pass # TODO: We want to let the test know there's an extension not being emulated

    return patched_popen, invocation_record

def generate_patched_zipfile(*emulators):

    original_constructor = zipfile.ZipFile

    def patched_zip_constructor(zip_filename, *args, **kwargs):

        zipfile = original_constructor(zip_filename, *args, **kwargs)

        try:
            ext_name, ext_version = _ExtractExtensionInfo.from_zipfilename(zip_filename)
            matching_emulator = next(
                emulator for emulator in emulators
                if emulator.matches(ext_name, ext_version)
            )
        
        except StopIteration:
            return zipfile # TODO: We want to let the test know there's an extension not being emulated
        except Exception:
            return zipfile

        def extended_extractall(destination):
            zipfile.extractall(destination)

            content = fileutil.read_file(os.path.join(destination, "HandlerManifest.json"))
            handler_manifest = json.loads(content)

            handler_manifest[0]["handlerManifest"].update({
                "continueOnUpdateFailure": matching_emulator.continue_on_update_failure,
                "updateMode": matching_emulator.update_mode,
                "reportHeartbeat": matching_emulator.report_heartbeat
            })

            fileutil.write_file(os.path.join(destination, "HandlerManifest.json"), json.dumps(handler_manifest))

        return Mock(**{ "extractall.side_effect": extended_extractall })

    return patched_zip_constructor


def generate_put_handler(*emulators):
    """
    """

    def mock_put_handler(url, *args, **kwargs):

        handler_statuses = json.loads(args[0]).get("aggregateStatus", {}).get("handlerAggregateStatus", [])

        for handler_status in handler_statuses:
            supplied_name = handler_status.get("handlerName", None)
            supplied_version = handler_status.get("handlerVersion", None)
            
            try:
                next(
                    emulator for emulator in emulators
                    if emulator.matches(supplied_name, supplied_version)
                ).status_blobs.append(handler_status)

            except StopIteration as e:
                # Tests will want to know that the agent is running an extension they didn't specifically allocate.
                raise Exception("")

    return mock_put_handler

class InvocationRecord:

    def __init__(self):
        self._delegate = []

    def add(self, ext_name, ext_ver, ext_cmd):
        self._delegate.append((ext_name, ext_ver, ext_cmd))

    def compare(self, *cmds):

        for (ext, command_name) in cmds:

            try:
                (ext_name, ext_ver, ext_cmd) = self._delegate.pop(0)

                if not ext.matches(ext_name, ext_ver) or command_name != ext_cmd:
                    raise Exception("({0}-{1}, {2}) vs. ({3}-{4}, {5})".format(ext.name, ext.version, command_name, ext_name, ext_ver, ext_cmd))

            except IndexError:
                raise Exception("{0}: {1}".format(ext.version, command_name))
        
        if self._delegate:
            raise Exception("")

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
            "install": install_action,
            "uninstall": uninstall_action,
            "update": update_action,
            "enable": enable_action,
            "disable": disable_action
        }

        self.status_blobs = []
        
    
    def matches(self, name, version):
        """
        """
        return self.name == name and self.version == version

class _ExtractExtensionInfo:

    ext_name_regex = r'[a-zA-Z]+(?:\.[a-zA-Z]+)?'
    ext_ver_regex = r'[0-9]+(?:\.[0-9]+)*'

    @staticmethod
    def from_command(command):
        """
        """
        if not isinstance(command, str):
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
            raise Exception("Command does not match the desired format: {0}".format(command))

        return match_obj.group('name', 'ver', 'cmd')
    
    @staticmethod
    def from_zipfilename(zip_filename):
        """
        """

        template = r'(?<={base_dir}/)(?P<name>{ext_name})__(?P<ver>{ext_ver})\.zip'

        base_dir_regex = conf.get_lib_dir()

        full_regex = template.format(
            ext_name=_ExtractExtensionInfo.ext_name_regex,
            ext_ver=_ExtractExtensionInfo.ext_ver_regex,
            base_dir=base_dir_regex
        )

        match_obj = re.search(full_regex, zip_filename)

        if not match_obj:
            raise Exception("Filename does not match the desired format: {0}".format(zip_filename))
        
        return match_obj.group('name', 'ver')


def _extend_func(func):
    
    def wrapped_func(cmd, *args, **kwargs):

        base_dir = os.path.dirname(cmd.split(" ")[0])
        
        status_file = os.path.join(base_dir, "status", "{0}.status".format(wrapped_func.inc))
        fileutil.write_file(
            status_file,
            """
            [{
                "status": {
                    "status": "success"
                }
            }]
            """
        )

        # Every time a command is called, the agent looks for the next status file
        # (by filename prefix). We need to keep track of that number ourselves
        # to write to the correct location.
        wrapped_func.inc += 1

        return_value = func(cmd, *args, **kwargs)

        return Mock(**{
            "poll.return_value": return_value,
            "wait.return_value": return_value
        })
    
    # this is the default value for the function's static variable; because each invocation
    # of this function generates a distinct wrapped_func, we shouldn't get collisions.
    wrapped_func.inc = 0

    return Mock(wraps=wrapped_func)
