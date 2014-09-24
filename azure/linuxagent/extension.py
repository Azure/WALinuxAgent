# Windows Azure Linux Agent
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
#
# Requires Python 2.4+ and Openssl 1.0+
#

############################################################
# exthandler.py
############################################################

def HandleExtensions(self, config):
    for extInfo in config:
        ext = GetExtension(extInfo)
        state = extInfo.getState()
        if state == 'enabled':
            ext.enable()
        elif state == 'disabled':
            ext.disable()
        elif state == 'uninstalled':
            ext.uninstall()
        else
            raise Exception('Unknown extension state: {0}'.format(ext.state))

class ExtensionInfo():

    def getName(self):
        pass

    def getMetadataUri(self):
        pass

    def getPackageUri(self):
        pass

    def getVersion(self):
        pass

    def getState(self):
        pass

def GetExtension(extInfo):
    """
    Return extension installed. If not return a new object.
    """
    pass

class Extension():
    def __init__(self, name, version, extInfo, installed=False):
        self.name = name
        self.version = version
        self.extInfo = extInfo
        self.state = ExtensionInstalled() if installed else ExtensionNotInstalled()

    def enable(self):
        self.state.handleEnable()

    def disable(self):
        self.state.handleDisable()

    def uninstall(self):
        self.state.handleUninstall()

    def setState(self, state):
        self.state = state

    def launchCmd(self, cmd):
        pass

    def download(self, uri):
        pass

class ExtensionState()
    
    def handleEnable(self, extension):
        pass

    def handleDisable(self, extension):
        pass

    def handleUninstall(self, extension):
        pass

class ExtensionEnabled(ExtensionState):
    
    def handleEnable(self, extension):
        pass

    def handleDisable(self, extension):
        pass

    def handleUninstall(self, extension):
        pass

class ExtensionDisabled(ExtensionState):
    
    def handleEnable(self, extension):
        pass

    def handleDisable(self, extension):
        pass

    def handleUninstall(self, extension):
        pass

class ExtensionNotInstalled(ExtensionState):
    
    def handleEnable(self, extension):
        pass

    def handleDisable(self, extension):
        pass

    def handleUninstall(self, extension):

class ExtensionInstalled(ExtensionState):
    
    def handleEnable(self, extension):
        pass

    def handleDisable(self, extension):
        pass

    def handleUninstall(self, extension):
        pass
