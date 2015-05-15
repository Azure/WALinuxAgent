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
            sys.exit(1)
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
        prefix = self.prefix
        tgtDir = self.root
        if prefix and prefix[-1] != '/':
            prefix += '/'
        else:
            prefix = '/'
        if tgtDir and tgtDir[-1] != '/':
            tgtDir += '/'
        else:
            tgtDir = '/'
        # Handle the different init systems
        if init == 'sysV':
            initdir = 'etc/init.d'
            if self.lnx_distro == 'redhat':
                initdir = 'etc/rc.d/init.d'
            if not os.path.exists(tgtDir + initdir):
                try:
                    self.mkpath(tgtDir + initdir, 0755)
                except:
                    msg = 'Could not create init script directory '
                    msg += tgtDir
                    msg += initdir
                    print msg
                    print sys.exc_info()[0]
                    sys.exit(1)
            initScripts = glob.glob('distro/%s/*.sysV' %distro)
            try:
                for f in initScripts:
                    newName = f.split('/')[-1].split('.')[0]
                    self.copy_file(f, tgtDir + initdir + '/' + newName)
            except:
                print 'Could not install systemV init script', 
                sys.exit(1)
        elif init == 'systemd':
            if not os.path.exists(tgtDir + prefix +'lib/systemd/system'):
                try:
                    self.mkpath(tgtDir + prefix + 'lib/systemd/system', 0755)
                except:
                    msg = 'Could not create systemd service directory '
                    msg += tgtDir + prefix
                    msg += 'lib/systemd/system'
                    print msg
                    sys.exit(1)
            services = glob.glob('distro/systemd/*')
            for f in services:
                try:
                    baseName = f.split('/')[-1]
                    self.copy_file(f,
                            tgtDir + prefix +'lib/systemd/system/' + baseName)
                except:
                    print 'Could not install systemd service files'
                    sys.exit(1)
        elif init == 'upstart':
            print 'Upstart init files installation not supported at this time.'
            print 'Need an implementation, please submit a patch ;)'
            print 'See WALinuxAgent/debian directory for Debian/Ubuntu packaging'
    
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
            print 'Could not install configuration file %setc' %tgtDir
            sys.exit(1)

        if not os.path.exists(tgtDir + 'etc/udev/rules.d'):
            try:
                self.mkpath(tgtDir + 'etc/udev/rules.d', 0755)
            except Exception as e:
                print e

        try:
            self.copy_file('config/99-azure-product-uuid.rules', tgtDir + 'etc/udev/rules.d/99-azure-product-uuid.rules')
        except Exception as e:
            print e
            print 'Could not install product uuid rules file %setc' %tgtDir
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
        if not os.path.exists(tgtDir + prefix + 'sbin'):
            try:
                self.mkpath(tgtDir + prefix + 'sbin', 0755)
            except:
                msg = 'Could not create target daemon dir '
                msg+= tgtDir + prefix + 'sbin'
                print msg
                sys.exit(1)
        try:
            self.copy_file('waagent', tgtDir + prefix + 'sbin/waagent')
        except:
            print 'Could not install daemon %s%ssbin/waagent' %(tgtDir,prefix)
            sys.exit(1)
        os.chmod('%s%ssbin/waagent' %(tgtDir,prefix), 0755)

def readme():
    with open('README') as f:
        return f.read()
    
setuptools.setup(name = 'waagent',
      version = '1.4.0',
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



