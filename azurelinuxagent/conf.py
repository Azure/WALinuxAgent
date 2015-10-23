# Microsoft Azure Linux Agent
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

"""
Module conf loads and parses configuration file
"""
import os
import azurelinuxagent.utils.fileutil as fileutil
from azurelinuxagent.exception import AgentConfigError

class ConfigurationProvider(object):
    """
    Parse amd store key:values in /etc/waagent.conf.
    """
    def __init__(self):
        self.values = dict()

    def load(self, content):
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

    def get(self, key, default_val=None):
        val = self.values.get(key)
        return val if val is not None else default_val

    def get_switch(self, key, default_val=False):
        val = self.values.get(key)
        if val is not None and val.lower() == 'y':
            return True
        elif val is not None and val.lower() == 'n':
            return False
        return default_val

    def get_int(self, key, default_val=-1):
        try:
            return int(self.values.get(key))
        except TypeError:
            return default_val
        except ValueError:
            return default_val


__config__ = ConfigurationProvider()

def load_conf(conf_file_path, conf=__config__):
    """
    Load conf file from: conf_file_path
    """
    if os.path.isfile(conf_file_path) == False:
        raise AgentConfigError(("Missing configuration in {0}"
                                "").format(conf_file_path))
    try:
        content = fileutil.read_file(conf_file_path)
        conf.load(content)
    except IOError as err:
        raise AgentConfigError(("Failed to load conf file:{0}, {1}"
                                "").format(conf_file_path, err))

def get(key, default_val=None, conf=__config__):
    """
    Get option value by key, return default_val if not found
    """
    if conf is not None:
        return conf.get(key, default_val)
    else:
        return default_val

def get_switch(key, default_val=None, conf=__config__):
    """
    Get bool option value by key, return default_val if not found
    """
    if conf is not None:
        return conf.get_switch(key, default_val)
    else:
        return default_val

def get_int(key, default_val=None, conf=__config__):
    """
    Get int option value by key, return default_val if not found
    """
    if conf is not None:
        return conf.get_int(key, default_val)
    else:
        return default_val

