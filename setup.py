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

import os
from azurelinuxagent.metadata import AGENT_NAME, AGENT_VERSION, \
                                     AGENT_DESCRIPTION, \
                                     DISTRO_NAME, DISTRO_VERSION, DISTRO_FULL_NAME

from azurelinuxagent.utils.osutil import OSUTIL
import azurelinuxagent.agent as agent
import setuptools
from setuptools import find_packages
from setuptools.command.install import install as  _install

root_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(root_dir)

def get_data_files(name, version, fullname):
    """
    Determine data_files according to distro name, version and init system type
    """
    data_files=[]

    #Script file
    script_dest = '/usr/sbin'
    script_src = ['bin/waagent']
    if name == 'coreos':
        script_dest = '/usr/share/oem/bin'
    data_files.append((script_dest, script_src))

    #Config file
    conf_dest = '/etc'
    conf_src = ['config/waagent.conf']
    if name == 'suse':
        conf_src = ['config/suse/waagent.conf']
    if name == 'ubuntu':
        conf_src = ['config/ubuntu/waagent.conf']
    if name == 'coreos':
        conf_dest = '/usr/share/oem/'
    data_files.append((conf_dest, conf_src))
    
    #logrotate config file
    logrotate_dest = '/etc/logrotate.d'
    logrotate_src = ['config/waagent.logrotate']
    data_files.append((logrotate_dest, logrotate_src))

    #init script file, default is sysV
    init_dest = '/etc/rc.d/init.d'
    init_src = ['init/waagent']

    if name == 'redhat' or name == 'centos':
        if version >= "7.0":
            init_dest = '/etc/systemd/system'
            init_src = ['init/waagent.service']
    elif name == 'coreos':
        init_dest = '/usr/share/oem'
        init_src = ['init/coreos/cloud-config.yml']
    elif name == 'ubuntu':
        if version >= "15.04":
            init_dest = '/lib/systemd/system'
            init_src = ['init/ubuntu/walinuxagent.service']
        else:
            init_dest = '/etc/init'
            init_src = ['init/ubuntu/walinuxagent.conf']
    elif name == 'suse':
        if fullname == 'SUSE Linux Enterprise Server' and version >= '12' or \
                fullname == 'openSUSE' and version >= '13.2':
            init_dest = '/etc/systemd/system'
            init_src = ['init/waagent.service']
        else:
            init_dest = '/etc/init.d'
            init_src = ['init/waagent']

    data_files.append((init_dest, init_src))

    return data_files

class install(_install):
    user_options = _install.user_options + [
        # This will magically show up in member variable 'init_system'
        ('init-system=', None, 'Deprecated, use --lnx-distro* instead'),
        ('lnx-distro=', None, 'target Linux distribution'),
        ('lnx-distro-version=', None, 'target Linux distribution version'),
        ('lnx-distro-fullname=', None, 'target Linux distribution full name'),
        ('register-service', None, 'register as startup service'),
    ]

    def initialize_options(self):
        _install.initialize_options(self)
        self.lnx_distro = DISTRO_NAME
        self.lnx_distro_version = DISTRO_VERSION
        self.lnx_distro_fullname = DISTRO_FULL_NAME
        self.register_service = False
        
    def finalize_options(self):
        _install.finalize_options(self)
        data_files = get_data_files(self.lnx_distro, self.lnx_distro_version,
                                    self.lnx_distro_fullname)
        self.distribution.data_files = data_files
        self.distribution.reinitialize_command('install_data', True)

    def run(self):
        _install.run(self)
        if self.register_service:
            agent.register_service()

setuptools.setup(name=AGENT_NAME,
                 version=AGENT_VERSION,
                 long_description=AGENT_DESCRIPTION,
                 author= 'Yue Zhang, Stephen Zarkos, Eric Gable',
                 author_email = 'walinuxagent@microsoft.com',
                 platforms = 'Linux',
                 url='https://github.com/Azure/WALinuxAgent',
                 license = 'Apache License Version 2.0',
                 packages=find_packages(exclude=["tests"]),
                 cmdclass = {
                     'install': install
                 })
