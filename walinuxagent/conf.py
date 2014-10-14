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
import walinuxagent.utils.fileutil as fileutil

ConfFilePath = '/etc/waagent.conf' 

def LoadConfiguration(confFilePath = ConfFilePath):
    if os.path.isfile(confFilePath) == False:
        raise Exception("Missing configuration in {0}", confFilePath)
    try:
        return ConfigurationProvider(fileutil.GetFileContents(confFilePath)) 
    except IOError, e:
        raise Exception("Failed to load conf file:{0}", confFilePath)

class ConfigurationProvider(object):
    """
    Parse amd store key:values in /etc/waagent.conf.
    """
    def __init__(self, content):
        self.values = dict()
        if not content:
            raise Exception("Can't not parse empty configuration")
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

        
