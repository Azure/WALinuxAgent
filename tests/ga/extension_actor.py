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

import contextlib
import subprocess
import json
import uuid
import os

import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import ExtensionError
from azurelinuxagent.ga.exthandlers import get_exthandlers_handler
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates
from tests.protocol import mockwiredata
from tests.tools import patch, Mock


class Formats(object):

    @staticmethod
    def format_extension_uri(name, version):
        return "{0}__{1}".format(name, version)

    @staticmethod
    def format_extension_dir(name, version):
        return os.path.join(
            conf.get_lib_dir(),
            "{0}-{1}".format(name, version)
        )


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
        Use as such:

        exit_code, install_action = Actions.generate_unique_fail()
        extension = get_extension_actor(install_action=install_action)
        ...

        """
        return_code = str(uuid.uuid4())

        def fail_action(*args, **kwargs):
            return return_code
        
        return return_code, fail_action

    
    @staticmethod
    def _wrap_with_write_status(cmd, name, version):
        """
        A function factory for an action that executes the given command after writing 
        a simple (successful) status file in the appropriate directory. 
        
        Useful in particular for wrapping "enableCommand"s, as the agent expects any 
        extension to write such a status after enabling.
        """
        
        filedir = Formats.format_extension_dir(name, version)

        msg = """
            [{
                "status": {
                    "status": "success"
                }
            }]
        """

        def wrapped_cmd(*args, **kwargs):
            filename = os.path.join(filedir, "status", "{0}.status".format(wrapped_cmd.inc))
            fileutil.write_file(filename, msg)

            # Every time enable is called, the agent looks for the next status file
            # (by filename prefix). We need to keep track of that number ourselves
            # to write to the correct location.
            wrapped_cmd.inc += 1
            
            return cmd(*args, **kwargs)
        
        # this is the default value for the function's static variable; because each invocation
        # of this function generates a distinct wrapped_cmd, we shouldn't get collisions.
        wrapped_cmd.inc = 0

        return wrapped_cmd

def extension_manifest_info(name="OSTCExtensions.ExampleHandlerLinux", version="1.0.0",
    continue_on_update_failure=False, update_mode="UpdateWithInstall", report_heartbeat=False,
    install_action=Actions.succeed_action, uninstall_action=Actions.succeed_action, 
    update_action=Actions.succeed_action, enable_action=Actions.succeed_action,
    disable_action=Actions.succeed_action):
    """
    Factory method for ExtensionManifestInfo objects with sensible defaults.
    """
    
    return ExtensionManifestInfo(name, version, continue_on_update_failure, update_mode, report_heartbeat,
        install_action, uninstall_action, update_action, enable_action, disable_action)

class ExtensionActorManager:
    """
    A management class for mockwiredata.mock_wire_protocol() that adapts ExtensionManifestInfo objects
    into inputs that that function can work with. Additionally, creates and holds a exthandlers_handler
    object pointing to the returned protocol.
    """

    def _generate_mock_http_get(self):

        # It's beneficial to close over self, so that added actors will always be picked up.

        def mock_http_get(url, *args, **kwargs):
        
            for actor in self._actors:
                actor_id = Formats.format_extension_uri(actor.manifest_info.name, actor.manifest_info.version)

                if actor_id not in mock_http_get.wire_data.keys():
                    # Add to the cache so we aren't allocating new objects every http_get call, which
                    # could be frequent.
                    mock_http_get.wire_data[actor_id] = mockwiredata.get_dynamic_wire_protocol_data(actor.data_fetcher)
                
                if actor_id in url:
                    # Delegate to the correct actor's WireProtocolData* obj. This achieves the same effect that replacing
                    # a protocol's mock_wire_data attribute, for just this one call.
                    return mock_http_get.wire_data[actor_id].mock_http_get(url, *args, **kwargs)
            
            # The request is not for one of the actors; return None here to let the protocol know to handle it.
            return None
        
        mock_http_get.wire_data = {} # Initialize the cache.
        
        return mock_http_get

    def _generate_mock_http_put(self):

        def http_put_record_status(url, *args, **kwargs):
            if HttpRequestPredicates.is_host_plugin_status_request(url):
                return None

            handler_statuses = json.loads(args[0]).get("aggregateStatus", {}).get("handlerAggregateStatus", [])

            for handler_status in handler_statuses:
                supplied_name = handler_status.get("handlerName", None)
                supplied_version = handler_status.get("handlerVersion", None)
                
                try: 
                    matches_info = (
                        lambda actor: actor.manifest_info.name == supplied_name
                        and actor.manifest_info.version == supplied_version
                    )
                    
                    next(
                        actor for actor in self._actors
                        if matches_info(actor)
                    ).status_blobs.append(handler_status)

                except StopIteration as e:
                    # Tests will want to know that the agent is running an extension they didn't specifically allocate.
                    raise Exception("Status submitted for non-emulated extension: {0}".format(json.dumps(handler_status)))

        return http_put_record_status

    def __init__(self, data_fetcher=mockwiredata.DEFAULT_FETCHER):
        """
        Note that non-default manifest.xml files must use the same url format as the default in order to be compatible with this
        function. Specifically, the *.zip resource urls for an extension must end in "{ExtensionName}__{ExtensionVersion}".
        """
        self._protocol_manager = mock_wire_protocol(data_fetcher,
            http_get_handler=self._generate_mock_http_get(), http_put_handler=self._generate_mock_http_put(),
            mockwiredata_factory=mockwiredata.get_dynamic_wire_protocol_data)

        self._actors = []
        self._patched_popens = []
        self._invocation_record = []
        self._data_fetcher = data_fetcher

        self._incarnation = 1
    
    def __enter__(self):
        self._protocol = self._protocol_manager.__enter__()

        self._exthandlers_handler = get_exthandlers_handler(self._protocol)
        
        # Note that register_extension_actor starts the patched popens as it gets them. No need to do that here.
        # (even if we had them in scope, which we don't.)

        return self
        
    def __exit__(self, type, value, traceback):
        self._protocol_manager.__exit__(type, value, traceback)

        # If we don't stop back to front, a call to subprocess.Popen could potentially reach a stopped
        # patched popen, which would be a Bad Thing.
        for patched_popen in reversed(self._patched_popens):
            patched_popen.stop()    # Stop ALL popen patches, even those added after __enter__ was called (i.e. added in register_extension_actor).
    
    def run_exthandlers_handler(self):
        self._exthandlers_handler.run()


    def register_extension_actor(self, manifest_info):
        """
        Creates the specified ExtensionActor object and integrates it into the Manager's protocol. Additionally, Popen is patched (until 
        ExtensionActorManager.__exit__ is called) to enable the stored exthandlers_handler to interact with the returned actor.
        
        Note that the provided name and version needs to match a plugin listed in the xml doc returned by data_fetcher["manifest"] (as
        provided to this object's constructor); otherwise, the agent won't be able to properly download this extension.
        """
        self._incarnation += 1

        new_actor = ExtensionActor(self._data_fetcher, manifest_info, self._invocation_record)

        new_popen = new_actor.patch_popen()
        new_popen.start() # Allow later patches to "see" this one (as subprocess.Popen).

        self._actors.append(new_actor)
        self._patched_popens.append(new_popen)

        distinct_names = set(actor.manifest_info.name for actor in self._actors)
        for name in distinct_names:
            
            max_ver = max(map(lambda actor: FlexibleVersion(actor.manifest_info.version),
                filter(lambda actor: actor.manifest_info.name == name, self._actors)))

            self._protocol.mock_wire_data.set_specific_extension_config_version(name, max_ver)
        
        self._protocol.mock_wire_data.set_incarnation(self._incarnation)
        self._protocol.client.update_goal_state()

        return new_actor
    
    def verify_invocation_ordering(self, *invocation_order):
        """
        Consumes extension command invocation records, verifying that the number of records, as well as the key of each record,
        is the same as invocation_order. Each call's args should only contain the invocations made since the last call to
        verify_invocation_ordering if there was one.

        Note that this function will raise an exception if the stored invocation records do not match invocation_order exactly.
        """
        err_msg = "Extension Command invocation did not happen in expected ordering"

        for invocation_key in invocation_order:
            
            try:
                next_key = self._invocation_record.pop(0)
            except IndexError:
                raise Exception("{0}: Expected {1}, but ran out of invocations!".format(err_msg, invocation_key))

            if invocation_key != next_key:
                raise Exception("{0}: Got {1}, Expected {2}".format(err_msg, next_key, invocation_key))
        
        if self._invocation_record:
            raise Exception("{0}: Got {1}, but did not expect any more invocations!".format(err_msg, self._invocation_record[-1]))


class ExtensionManifestInfo:
    """
    A wrapper class for the possible actions and options that an extension might support.
    """

    def __init__(self, name, version, continue_on_update_failure, update_mode, report_heartbeat,
        install_action, uninstall_action, update_action, enable_action, disable_action):

        # The keys below will be used to configure attributes for a mock; periods in such attributes are treated
        # as attribute trees, which would break introspection.
        formatted_id = os.path.split(Formats.format_extension_dir(name, version))[-1].replace(".", "_")

        self.name = name
        self.version = version
        self.update_mode = update_mode
        self.report_heartbeat = report_heartbeat
        self.continue_on_update_failure = continue_on_update_failure

        self._delegate = {
            "installCommand": dict(key="{0}_install".format(formatted_id), action=Actions._wrap_with_write_status(install_action, name, version)),
            "uninstallCommand": dict(key="{0}_uninstall".format(formatted_id), action=Actions._wrap_with_write_status(uninstall_action, name, version)),
            "updateCommand": dict(key="{0}_update".format(formatted_id), action=Actions._wrap_with_write_status(update_action, name, version)),
            "enableCommand": dict(key="{0}_enable".format(formatted_id), action=Actions._wrap_with_write_status(enable_action, name, version)),
            "disableCommand": dict(key="{0}_disable".format(formatted_id), action=Actions._wrap_with_write_status(disable_action, name, version))
        }

    def as_generator(self):
        """
        Convert this object into a generator lambda that returns a valid *.zip extension
        resource file containing this object's data upon invocation.
        """

        base_manifest = [{
            "name": self.name.split(".")[-1],
            "version": self.version,
            "handlerManifest": {
                "reportHeartbeat": self.report_heartbeat,
                "continueOnUpdateFailure": self.continue_on_update_failure,
                "updateMode": self.update_mode,
                "rebootAfterInstall": False     # Not yet needed (or implemented)
            }
        }]

        for title, cmd in self.commands():
            base_manifest[0]["handlerManifest"][title] = cmd["key"]

        return mockwiredata.generate_ext_fetcher_func(base_manifest)
    
    def commands(self):
        """
        Keys are the various command names an extension must support, and values have the property layout { key, action }.

        A wrapper around dict.items().
        """
        for key, action in self._delegate.items():
            yield key, action
    
    def command_names(self):
        """
        Yields the list of all possible command names an extension must support.

        A wrapper around dict.keys().
        """
        for key in self._delegate.keys():
            yield key
    
    def get_key_for_command(self, cmd):
        """
        Returns the unique ID associated with a specific command name in this ExtensionManifestInfo.
        cmd may be "installCommand", "enableCommand", etc.
        """
        return self._delegate[cmd]["key"]


class ExtensionActor:
    """
    An emulator for an extension, responsible for intercepting popen commands meant to run the extension's
    commands (via patch_popen) and allowing introspection on the calls on said commands (via Mocks returned by
    get_command_mock).
    """
    
    @staticmethod
    def _configure_action_scope(action_scope, manifest_info, invocation_record):
        """
        Creates a mock specced to the set of commands within the manifest_info provided. The mock (action_scope) will
        correctly call the (corresponding) actions provided in the manifest_info when given any command present within
        the manifest_info.

        The action_scope mock is intended for use with a mock_popen function; if a command passed to mock_popen is
        present within the attribute list of the action_scope (and therefore listed as a action["key"] in the
        manifest_info), that attribute should add the attribute name to invocation_record, and return a mock popen
        object with the proper return code (the value returned by the particular action function in the manifest_info
        matching the action["key"]).
        """

        def wrap_action_for_popen(action_func):
            """
            Creates and returns a wrapper function for the given action func which records the invocation in invocation_record,
            and calls said action func and returns a mock popen obj whose poll() and wait() methods return the value returned
            by the action func.
            """

            def action_for_popen(*args, **kwargs):
                # We know args[0] (command) must be in a viable format, otherwise this function would never have been called.
                if args: invocation_record.append(os.path.basename(args[0]))

                return_code = action_func(*args, **kwargs)

                return Mock(**{
                    "poll.return_value": return_code,
                    "wait.return_value": return_code
                })

            return action_for_popen
        
        action_scope_attributes = {}
        for _, action in manifest_info.commands():
            # The action passed to us is meant to return some sort of error_code.
            # However, it is advantageous for our actions to return a mock specced to
            # a popen object, so that our mock popen func can delegate straight to the
            # action. see wrap_action_return_in_popen_obj for impl details.
            action_returning_popen_obj = wrap_action_for_popen(action["action"])
            # Attempting to specify action["key"].side_effect throws an AttributeError
            # at runtime, as we (below) have added a spec to the action_scope mock. Thus,
            # we need to instantiate a mock object for the attribute directly.
            action_scope_attributes[action["key"]] = Mock(wraps=action_returning_popen_obj)

        action_scope.mock_add_spec(manifest_info.command_names()) # We rely on this spec to enable proper fallthrough (as described in patch_popen())
        action_scope.configure_mock(**action_scope_attributes)
    
    @staticmethod
    def _configure_data_fetcher(data_fetcher, manifest_info):
        """
        Replaces the "test_ext" fetcher function in the provided data fetcher
        with a fetcher function matching the manifest_info.
        """

        data_fetcher["test_ext"] = manifest_info.as_generator()


    def __init__(self, data_fetcher_base, manifest_info, invocation_record):
        """
        Creates a ExtensionActor emulating an extension specified by the provided
        manifest_info. Copies the data_fetcher_base to serve as the dynamic
        loader of info required by a WireProtocolData* object.
        """
        self._action_scope = Mock()
        ExtensionActor._configure_action_scope(self._action_scope, manifest_info, invocation_record)

        self.data_fetcher = data_fetcher_base.copy()
        ExtensionActor._configure_data_fetcher(self.data_fetcher, manifest_info)

        self.manifest_info = manifest_info

        self.status_blobs = []
    
    def get_command_mock(self, cmd):
        """
        Returns the Mock object responsible for recording calls to the extension
        command specified by a cmd in ["installCommand", "enableCommand", "uninstallCommand", etc.].
        """
        return getattr(self._action_scope, self.manifest_info.get_key_for_command(cmd))

    def get_command_key(self, cmd):
        """
        Returns a unique key that specifies this extension's action for cmd.
        """
        return self.manifest_info.get_key_for_command(cmd)
        
    def patch_popen(self):
        """
        Returns a mock that patches the existing subprocess.Popen function call (on start()) such that any
        calls supposed to invoke the extension emulated by this object are intercepted and correctly ran
        (via the action funcs in the ExtensionManifestInfo that initialized this object). Any other commands
        are passed through to the prior existing subprocess.Popen.

        Note that the passthrough on failure to match a command to this extension's action commands enables
        multiple patch_popen() Mocks to function at the same time.

            try:
                first_patch = first_ext.patch_popen()
                first_patch.start()
                second_patch = second_ext.patch_popen()
                second_patch.start()

                # Execute code that might try to invoke either extension.
                {more code}

            finally:
                second_patch.stop()
                first_patch.stop()

        
        For instance: if {more code} involves a invocation of the extension emulated by first_ext, the mock popen for
        second_ext will be invoked, but will fail to match the provided command to one within second_ext's action_scope.
        It will then fall back to the prior popen-- in this case, that's the mock popen from first_ext-- which will
        successfully match the provided command to one within first_ext's action_scope. The corresponding action will
        then be called and returned.

        Note the need to interleave the patch_popen() and start() calls; in order for second_patch to know to fall back
        to first_patch (instead of simply falling back to the original subprocess.Popen), first_patch must have already
        replaced subprocess.Popen, which is handled by the start() function.
        """

        original_popen = subprocess.Popen

        def mock_popen(command, *args, **kwargs):
            # The command can be specified as a list of args or one single string. Handle that here.
            format_command = lambda cmd: " ".join(cmd) if isinstance(cmd, list) else cmd

            script_name = os.path.basename(format_command(command)) # The command passed here (if it corresponds to one within
                        # this object's action set) will be localized with the base dir of the extension
                        # this object is emulating. We don't want that file path because we aren't actually
                        # calling a script, just using the name as a tag.

            # Here we look within our own action_scope first for the tag (script_name), but we need to fall
            # back to the original_popen command if we can't find it to enable patch_popen stacking (as 
            # described in the docstring above).
            return getattr(self._action_scope, script_name, original_popen)(command, *args, **kwargs)

        return patch("subprocess.Popen", side_effect=mock_popen)