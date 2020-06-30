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

# TODO: Check the licensing; it was copy-pasted from another file.\

import contextlib
import subprocess

from azurelinuxagent.common.exception import ExtensionError
from azurelinuxagent.ga.exthandlers import get_exthandlers_handler
from tests.protocol.mocks import mock_wire_protocol
from tests.protocol import mockwiredata
from tests.tools import patch, Mock


class Actions(object):
    """
    TODO: Desc
    """

    @staticmethod
    def SucceedAction(*args, **kwargs):
        """
        TODO: Desc
        """
        return 0
    
    @staticmethod
    def FailAction(*args, **kwargs):
        """
        TODO: Desc
        """
        raise ExtensionError("FailAction called.")

    
    @staticmethod
    def _wrap_with_write_status(cmd, extensionId):
        """
        TODO: Desc
        """
        import azurelinuxagent.common.utils.fileutil as fileutil
        import azurelinuxagent.common.conf as conf
        
        filedir = "/".join([
            conf.get_lib_dir(),
            extensionId,
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

            wrapped_cmd.inc += 1
            
            return cmd()
        
        wrapped_cmd.inc = 0

        return wrapped_cmd

def get_extension_actor(name="OSTCExtensions.ExampleHandlerLinux", version="1.0.0", continueOnUpdateFailure=False,
    data_fetcher_base=mockwiredata.DEFAULT_FETCHER, installAction=Actions.SucceedAction, uninstallAction=Actions.SucceedAction,
    updateAction=Actions.SucceedAction, enableAction=Actions.SucceedAction, disableAction=Actions.SucceedAction):
    """
    TODO: Desc
    """
    
    actionSet = ActionSet(installAction, uninstallAction, updateAction, enableAction, disableAction,
        "{0}-{1}".format(name, version))
    info = ExtensionInfo(name, version, continueOnUpdateFailure)

    return ExtensionActor(data_fetcher_base, actionSet, info)


@contextlib.contextmanager
def get_protocol_and_handler(firstActor, *remainingActors):
    """
    TODO: Desc
    """

    remainingActors_mockwiredata = {
        "{0}__{1}".format(actor.extension_info.name, actor.extension_info.version): mockwiredata.get_dynamic_wire_protocol_data(actor.data_fetcher)
        for actor in remainingActors
    }

    def http_get_remaining_actors(url, *args, **kwargs):
        
        for actorId, wire_data in remainingActors_mockwiredata.items():

            if actorId in url:
                return wire_data.mock_http_get(url, *args, **kwargs)
        
        return None

    with mock_wire_protocol(firstActor.data_fetcher, mockwiredata_factory=mockwiredata.get_dynamic_wire_protocol_data) as protocol:

        protocol.set_http_handlers(http_get_handler=http_get_remaining_actors)
        yield protocol, get_exthandlers_handler(protocol)


def update_secondary_extension_actors(protocol, incarnation, *actors):
    """
    TODO: Desc
    """

    actors_mockwiredata = {
        "{0}__{1}".format(actor.extension_info.name, actor.extension_info.version): mockwiredata.get_dynamic_wire_protocol_data(actor.data_fetcher)
        for actor in actors
    }

    def http_get(url, *args, **kwargs):
        for actorId, wire_data in actors_mockwiredata.items():

            if actorId in url:
                return wire_data.mock_http_get(url, *args, **kwargs)
        
        return None

    # TODO: Revist this to make it less hacky; currently, we set ALL versions in ext_conf to
    # the version of a single actor.
    if len(actors) > 0:
        protocol.mock_wire_data.set_extensions_config_version(actors[0].extension_info.version)

    protocol.set_http_handlers(http_get_handler=http_get)
    protocol.mock_wire_data.set_incarnation(incarnation)
    protocol.client.update_goal_state()


class ActionSet(object):
    """
    TODO: Desc
    """

    def __init__(self, installAction, uninstallAction, updateAction, enableAction, disableAction, extensionId):
        """
        TODO: Desc
        """
        formattedId = extensionId.replace(".", "_") # TODO: explain

        self.delegate ={
            "installCommand": dict(key="{0}_install".format(formattedId), action=installAction),
            "uninstallCommand": dict(key="{0}_uninstall".format(formattedId), action=uninstallAction),
            "updateCommand": dict(key="{0}_update".format(formattedId), action=updateAction),
            "enableCommand": dict(key="{0}_enable".format(formattedId), action=Actions._wrap_with_write_status(enableAction, extensionId)),
            "disableCommand": dict(key="{0}_disable".format(formattedId), action=disableAction),
        }

    def items(self):
        """
        TODO: Desc
        """
        for key, action in self.delegate.items():
            yield key, action
    
    def keys(self):
        """
        TODO: Desc
        """
        for key in self.delegate.keys():
            yield key
    
    def getKeyForCommand(self, cmd):
        """
        TODO: Desc
        """
        return self.delegate.get(cmd, {}).get("key", None)


class ExtensionInfo(object):
    """
    TODO: Desc
    """

    def __init__(self, name, version, continueOnUpdateFailure):
        self.name = name
        self.version = version
        self.continueOnUpdateFailure = continueOnUpdateFailure


class ExtensionActor(object):
    """
    TODO: Desc
    """
    
    @staticmethod
    def _configure_action_scope(actionScope, actionSet):
        """
        TODO: Desc
        """
        actionScope.mock_add_spec(actionSet.keys())
        
        actionScope.configure_mock(**{
            action["key"]: Mock(wraps=action["action"]) \
                for _, action in actionSet.items()
        })
    
    @staticmethod
    def _configure_data_fetcher(dataFetcher, actionSet, extensionInfo):
        """
        TODO: Desc
        """

        dataFetcher["test_ext"] = mockwiredata.generate_ext_fetcher_func([{
            "name": extensionInfo.name.split(".")[-1],
            "version": extensionInfo.version,
            "handlerManifest": {
                **{ title: cmd["key"] for title, cmd in actionSet.items() },
                "rebootAfterInstall": False, "reportHeartbeat": False,
                "continueOnUpdateFailure": extensionInfo.continueOnUpdateFailure
            }
        }])


    def __init__(self, dataFetcherBase, actionSet, extensionInfo):
        """
        TODO: Desc
        """
        self.action_scope = Mock()
        ExtensionActor._configure_action_scope(self.action_scope, actionSet)

        self.data_fetcher = dataFetcherBase.copy()
        ExtensionActor._configure_data_fetcher(self.data_fetcher, actionSet, extensionInfo)

        self.get_command = lambda cmd: getattr(self.action_scope, actionSet.getKeyForCommand(cmd), None)
        self.extension_info = extensionInfo
        

    @contextlib.contextmanager
    def patch_popen(self):
        """
        TODO: Desc
        """

        original_popen = subprocess.Popen

        def mock_popen(command, *args, **kwargs):
            # TODO: Explain delegate (specifically, how it can stack onto previous mock_popens,
            # TODO: and why we woudl want that). 
            # TODO: Remove .wait() in concert with below changes
            delegate = (lambda *args, **kwargs: original_popen(command, *args, **kwargs).wait())

            script_name = command.split("/")[-1] # TODO: explain the why.

            # TODO: Transition the return of these attributes to a mock following the spec of
            # TODO: the mock object returned below.
            return_code = getattr(self.action_scope, script_name, delegate)(*args, **kwargs)

            # TODO: return return_code (later mock_popen_obj)
            return Mock(**{
                "poll.return_value": return_code,
                "wait.return_value": return_code
            })

        with patch("subprocess.Popen", side_effect=mock_popen):
            yield