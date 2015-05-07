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

import os
import azureguestagent.utils.fileutil as fileutil
from azureguestagent.exception import *
from azureguestagent.utils.osutil import CurrOSUtil

def LoadConfiguration(confFilePath):
    if os.path.isfile(confFilePath) == False:
        raise AgentConfigError("Missing configuration in {0}", confFilePath)
    try:
        content = fileutil.GetFileContents(confFilePath)
        __Config__ = ConfigurationProvider(content)
        return __Config__
    except IOError, e:
        raise AgentConfigError("Failed to load conf file:{0}", confFilePath)

__Config__ = None
def Get(key, defaultValue=None):
    if __Config__ is not None:
        return __Config__.get(key, defaultValue)
    else:
        return defaultValue
 
def GetSwitch(key, defaultValue=None):
     if __Config__ is not None:
         return __Config__.getSwitch(key, defaultValue)
     else:
         return defaultValue

def GetInt(key, defaultValue=None):
    if __Config__ is not None:
        return __Config__.getInt(key, defaultValue)
    else:
        return defaultValue

class ConfigurationProvider(object):
    """
    Parse amd store key:values in /etc/waagent.conf.
    """
    def __init__(self, content):
        self.values = dict()
        if not content:
            raise AgentConfigError("Can't not parse empty configuration")
        for line in content.split('\n'):
            if not line.startswith("#") and "=" in line:
                parts = line.split()[0].split('=')
                value = parts[1].strip("\" ")
                if value != "None":
                    self.values[parts[0]] = value
                else:
                    self.values[parts[0]] = None

    def get(self, key, defaultValue=None):
        val = self.values.get(key)
        return val if val else defaultValue

    def getSwitch(self, key, defaultValue=False):
        val = self.values.get(key)
        return True if (val and val.lower() == 'y') else defaultValue

    def getInt(self, key, defaultValue=-1):
        try:
            return int(self.values.get(key))
        except:
            return defaultValue


