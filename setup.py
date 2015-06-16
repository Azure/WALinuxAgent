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
from azurelinuxagent.agent import GuestAgentName, GuestAgentVersion
from azurelinuxagent.osinfo import CurrOSInfo
from azurelinuxagent.utils.osutil import CurrOSUtil

import setuptools
from setuptools import find_packages
from setuptools.command.install import install

root_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(root_dir)

def get_data_files(name, version, init_system):
    """
    Determine data_files according to distro name, version and init system type
    """
    data_files=[]

    #Script file
    script_dest = '/usr/sbin'
    script_src = ['bin/waagent', 'bin/alagent']
    if name == 'coreos':
        script_dest = '/usr/share/oem/bin'
    data_files.append((script_dest, script_src))

    #Config file
    conf_dest = '/etc'
    conf_src = ['config/waagent.conf']
    if name == 'suse':
        conf_src = ['config/suse/waagent.conf']
    data_files.append((conf_dest, conf_src))
    
    #logrotate config file
    logrotate_dest = '/etc/logrotate.d'
    logrotate_src = ['config/waagent.logrotate']
    data_files.append((logrotate_dest, logrotate_src))

    #init script file
    init_dest = '/etc/systemd'
    init_src = ['init/waagent.service']

    if name == 'redhat' or name == 'centos':
        init_dest = '/etc/rc.d/init.d'
        init_src = ['init/waagent.sysV']
    elif name == 'suse':
        init_dest = '/etc/init.d'
        init_src = ['init/waagent.sysV']
    elif name == 'coreos':
        init_dest = '/usr/share/oem'
        init_src = ['init/coreos/cloud-config.yml']
    elif init_system == 'sysV':
        init_dest = '/etc/init.d'
        init_src = ['init/waagent.sysV']

    data_files.append((init_dest, init_src))

    return data_files

class InstallData(install):
    user_options = install.user_options + [
        # This will magically show up in member variable 'init_system'
        ('init-system=', None, 'init system to configure [default: sysV]'),
        ('lnx-distro=', None, 'target Linux distribution'),
        ('lnx-distro-version=', None, 'target Linux distribution version'),
    ]

    def initialize_options(self):
        install.initialize_options(self)
        self.init_system = 'sysV'
        self.lnx_distro = CurrOSInfo[0]
        self.lnx_distro_version = CurrOSInfo[1]

    def finalize_options(self):
        install.finalize_options(self)
        data_files = get_data_files(self.lnx_distro, self.lnx_distro_version,
                                    self.init_system)
        print data_files
        self.distribution.data_files = data_files
        self.distribution.reinitialize_command('install_data', True)


def readme():
    with open('README') as f:
        return f.read()

setuptools.setup(name=GuestAgentName,
                 version=GuestAgentVersion,
                 description=readme(),
                 author= 'Yue Zhang, Stephen Zarkos, Eric Gable',
                 author_email = 'walinuxagent@microsoft.com',
                 platforms = 'Linux',
                 url='https://github.com/Azure/WALinuxAgent',
                 license = 'Apache License Version 2.0',
                 packages=find_packages(exclude=["tests"]),
                 cmdclass = {
                     'install': InstallData,
                 })
