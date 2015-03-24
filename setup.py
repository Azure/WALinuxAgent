#!/usr/bin/env python
#
# Windows Azure Linux Agent setup.py
#
# Copyright 2013 Microsoft Corporation
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

from distutils.core import setup
from azurelinuxagent.utils.osutil import CurrOS, CurrOSInfo
import azurelinuxagent.agent as agent

name = CurrOSInfo[0]
version = CurrOSInfo[1]
codeName = CurrOSInfo[2]
data_files=[]

if name == 'ubuntu':
    data_files.extend([
        ('/usr/sbin', ['bin/waagent']),
        ('/etc/logrotate.d', ['config/waagent.logrotate']),
        ('/etc', ['config/ubuntu/waagent.conf']),
        ('/etc/init', ['config/ubuntu/init/waagent.conf']),
    ])
elif name == 'redhat' or name == 'centos':
    data_files.extend([
        ('/usr/sbin', ['bin/waagent']),
        ('/etc/logrotate.d', ['config/waagent.logrotate']),
        ('/etc', ['config/redhat/waagent.conf']),
        ('/etc/init.d', ['config/redhat/init.d/waagent.conf']),
    ])
elif name == 'coreos':
    data_files.extend([
        ('/usr/share/oem/bin', ['bin/waagent']),
        ('/usr/share/oem/waagent.conf', ['config/coreos/waagent.conf']),
        ('/etc/systemd/system/', ['config/coreos/waagent.service']),
    ])
elif name == 'suse':
    data_files.extend([
        ('/usr/sbin', ['bin/waagent']),
        ('/etc/logrotate.d', ['config/waagent.logrotate']),
        ('/etc', ['config/suse/waagent.conf']),
        ('/etc/init.d', ['config/suse/init.d/waagent.conf']),
    ])
else:
    print "NOT support: {0} {1} {2}".format(name, version, codeName)
    sys.exit(-1)

setup(name=agent.GuestAgentName,
      version=agent.GuestAgentVersion,
      description=agent.GuestAgentLongVersion,
      author=agent.GuestAgentAuthor,
      url=agent.GuestAgentUri,
      packages=['azurelinuxagent', 
                'azurelinuxagent.utils', 
                'azurelinuxagent.protocol'],
      data_files=data_files)

CurrOS.RegisterAgentService()
