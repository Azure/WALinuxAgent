# Wrapper module for waagent
#
# waagent is not written as a module. This wrapper module is created 
# to use the waagent code as a module.
#
# Copyright 2014 Microsoft Corporation
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

import imp
import os
import os.path


#
# The following code will search and load waagent code and expose
# it as a submodule of current module
#
def searchWAAgent():
    # if the extension ships waagent in its package to default to this version first
    pkg_agent_path = os.path.join(os.getcwd(), 'waagent')
    if os.path.isfile(pkg_agent_path):
        return pkg_agent_path

    agentPath = '/usr/sbin/waagent'
    if os.path.isfile(agentPath):
        return agentPath

    user_paths = os.environ['PYTHONPATH'].split(os.pathsep)
    for user_path in user_paths:
        agentPath = os.path.join(user_path, 'waagent')
        if os.path.isfile(agentPath):
            return agentPath
    return None


waagent = None
agentPath = searchWAAgent()
if agentPath:
    waagent = imp.load_source('waagent', agentPath)
else:
    raise Exception("Can't load waagent.")

if not hasattr(waagent, "AddExtensionEvent"):
    """
    If AddExtensionEvent is not defined, provide a dummy impl.
    """


    def _AddExtensionEvent(*args, **kwargs):
        pass


    waagent.AddExtensionEvent = _AddExtensionEvent

if not hasattr(waagent, "WALAEventOperation"):
    class _WALAEventOperation:
        HeartBeat = "HeartBeat"
        Provision = "Provision"
        Install = "Install"
        UnIsntall = "UnInstall"
        Disable = "Disable"
        Enable = "Enable"
        Download = "Download"
        Upgrade = "Upgrade"
        Update = "Update"


    waagent.WALAEventOperation = _WALAEventOperation

# Better deal with the silly waagent typo, in anticipation of a proper fix of the typo later on waagent
if not hasattr(waagent.WALAEventOperation, 'Uninstall'):
    if hasattr(waagent.WALAEventOperation, 'UnIsntall'):
        waagent.WALAEventOperation.Uninstall = waagent.WALAEventOperation.UnIsntall
    else:  # This shouldn't happen, but just in case...
        waagent.WALAEventOperation.Uninstall = 'Uninstall'


def GetWaagentHttpProxyConfigString():
    """
    Get http_proxy and https_proxy from waagent config.
    Username and password is not supported now.
    This code is adopted from /usr/sbin/waagent
    """
    host = None
    port = None
    try:
        waagent.Config = waagent.ConfigurationProvider(
            None)  # Use default waagent conf file (most likely /etc/waagent.conf)

        host = waagent.Config.get("HttpProxy.Host")
        port = waagent.Config.get("HttpProxy.Port")
    except Exception as e:
        # waagent.ConfigurationProvider(None) will throw an exception on an old waagent
        # Has to silently swallow because logging is not yet available here
        # and we don't want to bring that in here. Also if the call fails, then there's
        # no proxy config in waagent.conf anyway, so it's safe to silently swallow.
        pass

    result = ''
    if host is not None:
        result = "http://" + host
        if port is not None:
            result += ":" + port

    return result


waagent.HttpProxyConfigString = GetWaagentHttpProxyConfigString()

# end: waagent http proxy config stuff

__ExtensionName__ = None


def InitExtensionEventLog(name):
    global __ExtensionName__
    __ExtensionName__ = name


def AddExtensionEvent(name=__ExtensionName__,
                      op=waagent.WALAEventOperation.Enable,
                      isSuccess=False,
                      message=None):
    if name is not None:
        waagent.AddExtensionEvent(name=name,
                                  op=op,
                                  isSuccess=isSuccess,
                                  message=message)
