#!/usr/bin/env python
#
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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx
#

import urllib2
import shutil
import imp

if __name__ == '__main__':
    account = 'yuezh'
    agentUri = ('https://raw.githubusercontent.com/{0}/'
                'WALinuxAgent/2.0/waagent').format(account)
    response = urllib2.urlopen(agentUri)
    html = response.read()
    with open("waagent") as F:
        F.write(html)
    os.chmod("waagent", 544)
    shutil.copyfile("waagent", "/usr/sbin/waagent")
    waagent=imp.load_source('waagent','/usr/sbin/waagent')
    waagent.MyDistro=waagent.GetMyDistro()
    waagent.MyDistro.stopAgentService()
    waagent.MyDistro.startAgentService()
