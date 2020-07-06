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

from azurelinuxagent.common.exception import ExtensionError
from azurelinuxagent.ga.exthandlers import get_exthandlers_handler
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from tests.protocol.mocks import mock_wire_protocol, HttpRequestPredicates
from tests.protocol import mockwiredata
from tests.tools import patch, Mock


class Formats(object):

    @staticmethod
    def FormatExtensionUri(name, version):
        return "{0}__{1}".format(name, version)

    @staticmethod
    def FormatExtensionDir(name, version):
        return "{0}-{1}".format(name, version)



class Actions(object):
    """
    A collection of static methods providing some basic functionality for the ActionSet
    class' actions.
    """

    @staticmethod
    def SucceedAction(*args, **kwargs):
        """
        A nop action with the correct function signature for ActionSet actions.
        """
        return 0
    
    @staticmethod
    def FailAction(*args, **kwargs):
        """
        A simple fail action with the correct function signature for ActionSet actions.
        """
        raise ExtensionError("FailAction called.")

    
    @staticmethod
    def _wrap_with_write_status(cmd, name, version):
        """
        A function factory for an action that executes the given command after writing 
        a simple (successful) status file in the appropriate directory. 
        
        Useful in particular for wrapping "enableCommand"s, as the agent expects any 
        extension to write such a status after enabling.
        """
        import azurelinuxagent.common.utils.fileutil as fileutil
        import azurelinuxagent.common.conf as conf
        
        filedir = "/".join([
            conf.get_lib_dir(),
            Formats.FormatExtensionDir(name, version),
            "status"
        ])

        msg = """
            [{
                "status": {
                    "status": "success"
                }
            }]
        """

        def wrapped_cmd(*args, **kwargs):
            filename = "/".join([filedir, "{0}.status".format(wrapped_cmd.inc)])
            fileutil.write_file(filename, msg)

            # Every time enable is called, the agent looks for the next status file
            # (by filename prefix). We need to keep track of that number ourselves
            # to write to the correct location.
            wrapped_cmd.inc += 1
            
            return cmd()
        
        # this is the default value for the function's static variable; because each invocation
        # of this function generates a distinct wrapped_cmd, we shouldn't get collisions.
        wrapped_cmd.inc = 0

        return wrapped_cmd

def get_extension_actor(name="OSTCExtensions.ExampleHandlerLinux", version="1.0.0", continueOnUpdateFailure=False, 
    updateMode="UpdateWithInstall", data_fetcher_base=mockwiredata.DEFAULT_FETCHER, installAction=Actions.SucceedAction,
    uninstallAction=Actions.SucceedAction, updateAction=Actions.SucceedAction, enableAction=Actions.SucceedAction,
    disableAction=Actions.SucceedAction):
    """
    Factory method for ExtensionActor class. Note that the provided name and version needs to match a plugin listed
    in the xml doc returned by data_fetcher_base["manifest"]; otherwise, the agent won't be able to properly download
    this extension.
    """
    
    actionSet = ActionSet(installAction, uninstallAction, updateAction, enableAction, disableAction, name, version)
    info = ExtensionInfo(name, version, continueOnUpdateFailure, updateMode)

    return ExtensionActor(data_fetcher_base, actionSet, info)


def _generate_mock_http_get(actors):

    actorIdToData = {}
    for actor in actors:
        actorId = Formats.FormatExtensionUri(actor.extension_info.name, actor.extension_info.version)
        # By wrapping the actor's data_fetcher, we gain access to the WireProtocolDataFromMemory.mock_http_get func.
        actorData = mockwiredata.get_dynamic_wire_protocol_data(actor.data_fetcher)

        actorIdToData[actorId] = actorData

    def mock_http_get(url, *args, **kwargs):
        
        for actorId, wire_data in actorIdToData.items():

            if actorId in url:
                # Delegate to the correct actor's WireProtocolData* obj. This achieves the same effect that replacing
                # the (yet to be instantiated) protocol's mock_wire_data attribute, for just this one call.
                return wire_data.mock_http_get(url, *args, **kwargs)
        
        # In order to correctly pull from firstActor's data, we need to let its WireProtocolData* obj know that we
        # haven't satisfied the http_get request. Returning None here does that.
        return None
    
    return mock_http_get

def _generate_mock_http_put(actors):

    def http_put_record_status(url, *args, **kwargs):
        if HttpRequestPredicates.is_host_plugin_status_request(url):
            return None

        handlerStatuses = json.loads(args[0]).get('aggregateStatus', {}).get('handlerAggregateStatus', [])

        for handlerStatus in handlerStatuses:
            supplied_name = handlerStatus.get('handlerName', None)
            supplied_version = handlerStatus.get('handlerVersion', None)
            
            try: 
                matches_info = lambda actor: \
                    actor.extension_info.name == supplied_name \
                        and actor.extension_info.version == supplied_version
                
                next(
                    actor for actor in actors
                    if matches_info(actor)
                ).statusBlobs.append(handlerStatus)

            except StopIteration as e:
                # Tests will want to know that the agent is running an extension they didn't specifically allocate.
                raise Exception("Status submitted for non-emulated extension: {0}".format(json.dumps(handlerStatus)))

    return http_put_record_status


@contextlib.contextmanager
def get_protocol_and_handler(firstActor, *remainingActors):
    """
    A wrapper for mockwiredata.mock_wire_protocol() that adapts a set of ExtensionActor objects into inputs that 
    that function can work with, whilst also creating and returning an exthandlers_handler instance pointing to the
    returned protocol. Additionally, Popen is patched (for the scope of the with) to enable the returned exthandlers_handler 
    to interact with every extension actor supplied. Only firstActor need be populated.

    Note that non-default manifest.xml files must use the same url format as the default in order to be compatible with this
    function. Specifically, the *.zip resource urls for an extension must end in "{ExtensionName}__{ExtensionVersion}".
    """

    with mock_wire_protocol(firstActor.data_fetcher, mockwiredata_factory=mockwiredata.get_dynamic_wire_protocol_data) as protocol:
        
        # We save the patched popens within the protocol to enable additions in future function calls
        # (e.g. update_extension_actors).
        protocol._patched_popens = [ ] # Populated later; timing matters, and a patched_popen needs to be started immediately after creation.
        # We also need actor objs to, amoung other things, guarantee that the same actor doesn't have
        # two different patch_popen's running at the same time.
        protocol._actors = [firstActor, *remainingActors]

        protocol.set_http_handlers(http_get_handler=_generate_mock_http_get(protocol._actors[1:]),
            http_put_handler=_generate_mock_http_put(protocol._actors))

        try:
            # enable the exthandlers_handler to interact with every actor before it is exposed.
            for actor in protocol._actors:
                patched_popen = actor.patch_popen() # We delay creation so that *this* patched_popen can "see" the prior ones (they must be started already).
                patched_popen.start() # Allow later patches to "see" this one (as subprocess.Popen).

                protocol._patched_popens.append(patched_popen)

            yield protocol, get_exthandlers_handler(protocol)

        finally:
            for patched_popen in protocol._patched_popens:
                patched_popen.stop()


def add_extension_actors(protocol, incarnation, *actors):
    """
    Given a protocol obj returned by a extension_actor.get_protocol_and_handler(firstActor, *remainingActors) call, injects the
    extensions emulated by (the objects within) actors.
    
    It accomplishes this though applying the following updates onto the provided protocol:
        *   adds unique data sources for *.zip extension resources garnered from actors (unique meaning ones not already given
            by [firstActor, *remainingActors], if any)
        *   updates ext_conf to reflect the extension names and versions within actors
        *   updates the goal state's incarnation (to force the agent to re-read it)

    In order to force a goal state update, the incarnation parameter needs to be greater than the value passed in the last
    extension_actor.update_extension_actors() function call, or greater than 0 if this is the first of such calls.

    Note that non-default manifest.xml files must use the same url format as the default in order to be compatible with this
    function. Specifically, the *.zip resource urls for an extension must end in "{ExtensionName}__{ExtensionVersion}".

    Note that this function does not update xml for ext_conf or manifest, meaning that added extensions must already be present
    within those files as provided by the firstActor's data source. This could probably be implemented with the
    WireProtocolDataBase.replace_xml_element_value function, but it would probably make sense to first implement autogeneration
    of those files within ExtensionActor.__init__, as we would then know exactly the xml elements in those files. This would
    simplify the logic of adding the new actors, but is a bigger change. Ultimately, this feature isn't currently (i.e. as of
    writing) needed.
    """

    new_actors = list(filter(lambda actor: actor not in protocol._actors, actors))  # list() applies the lambda before we edit protocol._actors
    protocol._actors.extend(new_actors)

    for actor in new_actors:
        patched_popen = actor.patch_popen() # Like in get_protocol_and_handler, the patch_popen() and start() calls must
        patched_popen.start()               # be interleaved.

        # Keep track of the patches so the finally clause within get_protocol_and_handler can stop them.
        protocol._patched_popens.append(patched_popen)
    
    protocol.set_http_handlers(http_get_handler=_generate_mock_http_get(protocol._actors[1:]),
        http_put_handler=_generate_mock_http_put(protocol._actors))

    distinct_names = set(actor.extension_info.name for actor in protocol._actors)
    for name in distinct_names:
        
        max_ver = max(map(lambda actor: FlexibleVersion(actor.extension_info.version),
            filter(lambda actor: actor.extension_info.name == name, protocol._actors)))

        protocol.mock_wire_data.set_specific_extension_config_version(name, max_ver)
    
    protocol.mock_wire_data.set_incarnation(incarnation)
    protocol.client.update_goal_state()


class ActionSet(object):
    """
    A wrapper class for the possible actions that an extension much support.
    """

    def __init__(self, installAction, uninstallAction, updateAction, enableAction, disableAction, name, version):

        # The keys below will be used to configure attributes for a mock; periods in such attributes are treated
        # as attribute trees, which would break introspection.
        formattedId = Formats.FormatExtensionDir(name, version).replace(".", "_")

        self.delegate ={
            "installCommand": dict(key="{0}_install".format(formattedId), action=installAction),
            "uninstallCommand": dict(key="{0}_uninstall".format(formattedId), action=uninstallAction),
            "updateCommand": dict(key="{0}_update".format(formattedId), action=updateAction),
            "enableCommand": dict(key="{0}_enable".format(formattedId), action=Actions._wrap_with_write_status(enableAction, name, version)),
            "disableCommand": dict(key="{0}_disable".format(formattedId), action=disableAction),
        }

    def items(self):
        """
        Keys are the various command names an extension must support, and values have the property layout { key, action }.

        A wrapper around dict.items().
        """
        for key, action in self.delegate.items():
            yield key, action
    
    def keys(self):
        """
        Yields the list of all possible command names an extension must support.

        A wrapper around dict.keys().
        """
        for key in self.delegate.keys():
            yield key
    
    def getKeyForCommand(self, cmd):
        """
        Returns the unique ID associated with a specific command name in this ActionSet.
        cmd may be "installCommand", "enableCommand", etc.
        """
        return self.delegate.get(cmd, {}).get("key", None)


class ExtensionInfo(object):

    def __init__(self, name, version, continueOnUpdateFailure, updateMode):
        self.name = name
        self.version = version
        self.continueOnUpdateFailure = continueOnUpdateFailure
        self.updateMode = updateMode


class ExtensionActor(object):
    """
    An emulator for an extension, responsible for intercepting popen commands meant to run the extension's
    commands (via patch_popen) and allowing introspection on the calls on said commands (via Mocks returned by
    get_command).
    """
    
    @staticmethod
    def _configure_action_scope(actionScope, actionSet):
        """
        Creates a mock specced to the set of commands within the actionSet provided. The mock (actionScope) will
        correctly call the (corresponding) actions provided in the actionSet when given any command present within
        the actionSet.

        The actionScope mock is intended for use with a mock_popen function; if a command passed to mock_popen is
        present within the attribute list of the actionScope (and therefore listed as a action["key"] in the
        actionSet), that attribute should return a mock popen object with the proper return code (the value returned
        by the particular action function in the actionSet matching the action["key"]).
        """

        def wrap_action_return_in_popen_obj(action_func):
            """
            Creates and returns a wrapper function for the given action func which calls said action func and returns
            a mock popen obj whose poll() and wait() methods return the value returned by the action func.
            """

            def return_mock_popen_obj(*args, **kwargs):
                return_code = action_func(*args, **kwargs)

                return Mock(**{
                    "poll.return_value": return_code,
                    "wait.return_value": return_code
                })

            return return_mock_popen_obj
        
        action_scope_attributes = {}
        for _, action in actionSet.items():
            # The action passed to us is meant to return some sort of error_code.
            # However, it is advantageous for our actions to return a mock specced to
            # a popen object, so that our mock popen func can delegate straight to the
            # action. see wrap_action_return_in_popen_obj for impl details.
            action_returning_popen_obj = wrap_action_return_in_popen_obj(action["action"])
            # Attempting to specify action["key"].side_effect throws an AttributeError
            # at runtime, as we (below) have added a spec to the actionScope mock. Thus,
            # we need to instantiate a mock object for the attribute directly.
            action_scope_attributes[action["key"]] = Mock(wraps=action_returning_popen_obj)

        actionScope.mock_add_spec(actionSet.keys()) # We rely on this spec to enable proper fallthrough (as described in patch_popen())
        actionScope.configure_mock(**action_scope_attributes)
    
    @staticmethod
    def _configure_data_fetcher(dataFetcher, actionSet, extensionInfo):
        """
        Replaces the "test_ext" fetcher function in the provided data fetcher
        with a lambda which generates a proper zip file containing a HanderManifest.json
        file populated with the correct extension metadata and command names (i.e. the
        name of the commands to call for installCommand, enableCommand, etc.) from the
        given actionSet and extensionInfo.
        """

        dataFetcher["test_ext"] = mockwiredata.generate_ext_fetcher_func([{
            "name": extensionInfo.name.split(".")[-1],
            "version": extensionInfo.version,
            "handlerManifest": {
                **{ title: cmd["key"] for title, cmd in actionSet.items() },
                "rebootAfterInstall": False, "reportHeartbeat": False,
                "continueOnUpdateFailure": extensionInfo.continueOnUpdateFailure,
                "updateMode": extensionInfo.updateMode
            }
        }])


    def __init__(self, dataFetcherBase, actionSet, extensionInfo):
        """
        Creates a ExtensionActor emulating an extension specified by the provided
        extensionInfo and actionSet. Copies the dataFetcherBase to serve as the dynamic
        loader of info required by a WireProtocolData* object.
        """
        self.action_scope = Mock()
        ExtensionActor._configure_action_scope(self.action_scope, actionSet)

        self.data_fetcher = dataFetcherBase.copy()
        ExtensionActor._configure_data_fetcher(self.data_fetcher, actionSet, extensionInfo)

        self.get_command = lambda cmd: getattr(self.action_scope, actionSet.getKeyForCommand(cmd), None)
        self.extension_info = extensionInfo

        self.statusBlobs = []
        
    def patch_popen(self):
        """
        Returns a mock that patches the existing subprocess.Popen function call (on start()) such that any
        calls supposed to invoke the extension emulated by this object are intercepted and correctly ran
        (via the action funcs in the actionSet that initialized this object). Any other commands are passed
        through to the prior existing subprocess.Popen.

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
                first_patch.stop()
                second_patch.stop()

        
        For instance: if {more code} involves a invocation of the extension emulated by first_ext, the mock popen for
        second_ext will be invoked, but will fail to match the provided command to one within second_ext's actionScope.
        It will then fall back to the prior popen-- in this case, that's the mock popen from first_ext-- which will
        successfully match the provided command to one within first_ext's actionScope. The corresponding action will
        then be called and returned.

        Note the need to interleave the patch_popen() and start() calls; in order for second_patch to know to fall back
        to first_patch (instead of simply falling back to the original subprocess.Popen), first_patch must have already
        replaced subprocess.Popen, which is handled by the start() function.
        """

        original_popen = subprocess.Popen

        def mock_popen(command, *args, **kwargs):
            # The command can be specified as a list of args or one single string. Handle that here.
            format_command = lambda cmd: " ".join(cmd) if isinstance(cmd, list) else cmd

            script_name = format_command(command).split("/")[-1] # The command passed here (if it corresponds to one within
                        # this object's action set) will be localized with the base dir of the extension
                        # this object is emulating. We don't want that file path because we aren't actually
                        # calling a script, just using the name as a tag.

            # Here we look within our own actionScope first for the tag (script_name), but we need to fall
            # back to the original_popen command if we can't find it to enable patch_popen stacking (as 
            # described in the docstring above).
            return getattr(self.action_scope, script_name, original_popen)(command, *args, **kwargs)

        return patch("subprocess.Popen", side_effect=mock_popen)