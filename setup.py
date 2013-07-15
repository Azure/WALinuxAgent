#!/usr/bin/python
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
import glob
import os
import sys
import platform
import setuptools
from setuptools.command.install import install

from distutils.errors import DistutilsArgError

def getDistro():
    """
    Try to figure out the distribution we are running on
    """
    distro = platform.linux_distribution()[0].lower()
    # Manipulate the distribution to meet our needs we treat
    # Fedora, RHEL, and CentOS the same
    # openSUSE and SLE the same
    if distro.find('suse') != -1:
        distro = 'suse'
    if (distro.find('fedora') != -1
    or distro.find('red hat') != -1
    or distro.find('centos') != -1):
        distro = 'redhat'

    return distro
    

class InstallData(install):
    user_options = install.user_options + [
        # This will magically show up in member variable 'init_system'
        ('init-system=', None, 'init system to configure [default: sysV]'),
        ('lnx-distro=', None, 'target Linux distribution'),
    ]

    def initialize_options(self):
        install.initialize_options(self)
        self.init_system = 'sysV'
        self.lnx_distro = None

    def finalize_options(self):
        install.finalize_options(self)
        if not self.lnx_distro:
            self.lnx_distro = getDistro()
        if self.init_system not in ['sysV', 'systemd', 'upstart']:
            print 'Do not know how to handle %s init system' %self.init_system
            system.exit(1)
        if self.init_system == 'sysV':
            if not os.path.exists('distro/%s' %self.lnx_distro):
                msg = 'Unknown distribution "%s"' %self.lnx_distro
                msg += ', no entry in distro directory'
                sys.exit(1)

    def run(self):
        """
        Install the files for the Windows Azure Linux Agent
        """
        distro = self.lnx_distro
        init = self.init_system
        tgtDir = self.prefix
        if tgtDir[-1] != '/':
            tgtDir += '/'
        # Handle the different init systems
        if init == 'sysV':
            if not os.path.exists(tgtDir + 'etc/init.d'):
                try:
                    self.mkpath(tgtDir + 'etc/init.d', 0755)
                except:
                    msg = 'Could not create init script directory '
                    msg += tgtDir
                    msg += 'etc/init.d'
                    print msg
                    print sys.exc_info()[0]
                    sys.exit(1)
            initScripts = glob.glob('distro/%s/*.sysV' %distro)
            try:
                for f in initScripts:
                    newName = f.split('/')[-1].split('.')[0]
                    self.copy_file(f, tgtDir + 'etc/init.d/' + newName)
            except:
                print 'Could not install systemV init script', 
                sys.exit(1)
        elif init == 'systemd':
            if not os.path.exists(tgtDir + 'usr/lib/systemd/system'):
                try:
                    self.mkpath(tgtDir + 'usr/lib/systemd/system', 0755)
                except:
                    msg = 'Could not create systemd service directory '
                    msg += tgtDir
                    msg += 'etc/init.d'
                    print msg
                    sys.exit(1)
            services = glob.glob('distro/systemd/*')
            for f in services:
                try:
                    baseName = f.split('/')[-1]
                    self.copy_file(f,
                                tgtDir + 'usr/lib/systemd/system/' + baseName)
                except:
                    print 'Could not install systemd service files'
                    sys.exit(1)
        elif init == 'upstart':
            print 'Upstart init files installation not supported at this time.'
            print 'Need an implementtaion, please submit a patch ;) '
    
        # Configuration file
        if not os.path.exists(tgtDir + 'etc'):
                try:
                    self.mkpath(tgtDir + 'etc', 0755)
                except:
                    msg = 'Could not create config dir '
                    msg += tgtDir
                    msg += 'etc'
                    print msg
                    sys.exit(1)
        try:
            self.copy_file('config/waagent.conf', tgtDir + 'etc/waagent.conf')
        except:
            print 'Could not install configuration file %etc' %tgtDir
            sys.exit(1)
        if not os.path.exists(tgtDir + 'etc/logrotate.d'):
            try:
                self.mkpath(tgtDir + 'etc/logrotate.d', 0755)
            except:
                msg = 'Could not create ' + tgtDir + 'etc/logrotate.d'
                print msg
                sys.exit(1)
        try:
            self.copy_file('config/waagent.logrotate',
                      tgtDir + 'etc/logrotate.d/waagent')
        except:
            msg = 'Could not install logrotate file in '
            msg += tgtDir + 'etc/logrotate.d'
            print  msg
            sys.exit(1)
    
        # Daemon
        if not os.path.exists(tgtDir + 'usr/sbin'):
            try:
                self.mkpath(tgtDir + 'usr/sbin', 0755)
            except:
                msg = 'Could not create target daemon dir '
                msg+= tgtDir + 'usr/sbin'
                print msg
                sys.exit(1)
        try:
            self.copy_file('waagent', tgtDir + 'usr/sbin/waagent')
        except:
            print 'Could not install daemon %susr/sbin/waagent' %tgtDir
            sys.exit(1)
        os.chmod('%susr/sbin/waagent' %tgtDir, 0755)

def readme():
    with open('README') as f:
        return f.read()
    
setuptools.setup(name = 'waagent',
      version = '1.3.4-PRE',
      description = 'Windows Azure Linux Agent',
      long_description = readme(),
      author = 'Stephen Zarkos, Eric Gable',
      author_email = 'walinuxagent@microsoft.com',
      platforms = 'Linux',
      url = 'https://github.com/Windows-Azure/',
      license = 'Apache License Version 2.0',
      cmdclass = {
          # Use a subclass for install that handles
          # install, we do not have a "true" python package
          'install': InstallData,
      },
)



