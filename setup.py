#!/usr/bin/env python
#
# Microsoft Azure Linux Agent setup.py
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
import subprocess
import sys

import setuptools
from setuptools import find_packages
from setuptools.command.install import install as _install

from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, \
    AGENT_DESCRIPTION, \
    DISTRO_NAME, DISTRO_VERSION, DISTRO_FULL_NAME

root_dir = os.path.dirname(os.path.abspath(__file__))  # pylint: disable=invalid-name
os.chdir(root_dir)


def set_files(data_files, dest=None, src=None):
    data_files.append((dest, src))


def set_bin_files(data_files, dest, src=None):
    if src is None:
        src = ["bin/waagent", "bin/waagent2.0"]
    data_files.append((dest, src))


def set_conf_files(data_files, dest="/etc", src=None):
    if src is None:
        src = ["config/waagent.conf"]
    data_files.append((dest, src))


def set_logrotate_files(data_files, dest="/etc/logrotate.d", src=None):
    if src is None:
        src = ["config/waagent.logrotate"]
    data_files.append((dest, src))


def set_sysv_files(data_files, dest="/etc/rc.d/init.d", src=None):
    if src is None:
        src = ["init/waagent"]
    data_files.append((dest, src))


def set_systemd_files(data_files, dest, src=None):
    if src is None:
        src = ["init/waagent.service"]
    data_files.append((dest, src))


def set_freebsd_rc_files(data_files, dest="/etc/rc.d/", src=None):
    if src is None:
        src = ["init/freebsd/waagent"]
    data_files.append((dest, src))


def set_openbsd_rc_files(data_files, dest="/etc/rc.d/", src=None):
    if src is None:
        src = ["init/openbsd/waagent"]
    data_files.append((dest, src))


def set_udev_files(data_files, dest="/etc/udev/rules.d/", src=None):
    if src is None:
        src = ["config/66-azure-storage.rules",
               "config/99-azure-product-uuid.rules"]
    data_files.append((dest, src))


def get_data_files(name, version, fullname):  # pylint: disable=R0912
    """
    Determine data_files according to distro name, version and init system type
    """
    data_files = []
    osutil = get_osutil()
    systemd_dir_path = osutil.get_systemd_unit_file_install_path()
    agent_bin_path = osutil.get_agent_bin_path()

    if name in ('redhat', 'centos', 'almalinux', 'cloudlinux', 'rocky'):
        if version.startswith("8"):
            # redhat8+ default to py3
            set_bin_files(data_files, dest=agent_bin_path,
                          src=["bin/py3/waagent", "bin/waagent2.0"])
        else:
            set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files)
        set_logrotate_files(data_files)
        set_udev_files(data_files)
        if version.startswith("8"):
            # redhat 8+ uses systemd and python3
            set_systemd_files(data_files, dest=systemd_dir_path,
                              src=["init/redhat/waagent.service",
                              "init/azure.slice",
                              "init/azure-vmextensions.slice"
                                   ])

        elif version.startswith("6"):
            set_sysv_files(data_files)
        else:
            # redhat7.0+ use systemd
            set_systemd_files(data_files, dest=systemd_dir_path,
                              src=[
                                  "init/redhat/py2/waagent.service",
                                  "init/azure.slice",
                                  "init/azure-vmextensions.slice"
                              ])
            if version.startswith("7.1"):
                # TODO this is a mitigation to systemctl bug on 7.1
                set_sysv_files(data_files)
    elif name == 'arch':
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files, src=["config/arch/waagent.conf"])
        set_udev_files(data_files)
        set_systemd_files(data_files, dest=systemd_dir_path,
                          src=["init/arch/waagent.service"])
    elif name in ('coreos', 'flatcar'):
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files, dest="/usr/share/oem",
                       src=["config/coreos/waagent.conf"])
        set_logrotate_files(data_files)
        set_udev_files(data_files)
        set_files(data_files, dest="/usr/share/oem",
                  src=["init/coreos/cloud-config.yml"])
    elif "Clear Linux" in fullname:
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files, dest="/usr/share/defaults/waagent",
                       src=["config/clearlinux/waagent.conf"])
        set_systemd_files(data_files, dest=systemd_dir_path,
                          src=["init/clearlinux/waagent.service"])
    elif name == 'mariner':
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files, dest="/etc",
                       src=["config/mariner/waagent.conf"])
        set_systemd_files(data_files, dest=systemd_dir_path,
                          src=["init/mariner/waagent.service"])
        set_logrotate_files(data_files)
        set_udev_files(data_files)
    elif name == 'ubuntu':
        set_conf_files(data_files, src=["config/ubuntu/waagent.conf"])
        set_logrotate_files(data_files)
        set_udev_files(data_files)
        if version.startswith("12") or version.startswith("14"):
            # Ubuntu12.04/14.04 - uses upstart
            if version.startswith("12"):
                set_bin_files(data_files, dest=agent_bin_path)
            else:
                set_bin_files(data_files, dest=agent_bin_path,
                              src=["bin/py3/waagent", "bin/waagent2.0"])
            set_files(data_files, dest="/etc/init",
                      src=["init/ubuntu/walinuxagent.conf"])
            set_files(data_files, dest='/etc/default',
                      src=['init/ubuntu/walinuxagent'])
        else:
            set_bin_files(data_files, dest=agent_bin_path,
                          src=["bin/py3/waagent", "bin/waagent2.0"])
            # Ubuntu15.04+ uses systemd
            set_systemd_files(data_files, dest=systemd_dir_path,
                              src=[
                                  "init/ubuntu/walinuxagent.service",
                                  "init/azure.slice",
                                  "init/azure-vmextensions.slice"
                              ])
    elif name == 'suse' or name == 'opensuse':  # pylint: disable=R1714
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files, src=["config/suse/waagent.conf"])
        set_logrotate_files(data_files)
        set_udev_files(data_files)
        if fullname == 'SUSE Linux Enterprise Server' and \
                version.startswith('11') or \
                fullname == 'openSUSE' and version.startswith(
                    '13.1'):
            set_sysv_files(data_files, dest='/etc/init.d',
                           src=["init/suse/waagent"])
        else:
            # sles 12+ and openSUSE 13.2+ use systemd
            set_systemd_files(data_files, dest=systemd_dir_path)
    elif name == 'sles':  # sles 15+ distro named as sles
        set_bin_files(data_files, dest=agent_bin_path,
                      src=["bin/py3/waagent", "bin/waagent2.0"])
        set_conf_files(data_files, src=["config/suse/waagent.conf"])
        set_logrotate_files(data_files)
        set_udev_files(data_files)
        # sles 15+ uses systemd and python3
        set_systemd_files(data_files, dest=systemd_dir_path,
                          src=["init/sles/waagent.service"])
    elif name == 'freebsd':
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files, src=["config/freebsd/waagent.conf"])
        set_freebsd_rc_files(data_files)
    elif name == 'openbsd':
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files, src=["config/openbsd/waagent.conf"])
        set_openbsd_rc_files(data_files)
    elif name == 'debian':
        set_bin_files(data_files, dest=agent_bin_path,
                      src=["bin/py3/waagent", "bin/waagent2.0"])
        set_conf_files(data_files, src=["config/debian/waagent.conf"])
        set_logrotate_files(data_files)
        set_udev_files(data_files, dest="/lib/udev/rules.d")
        if debian_has_systemd():
            set_systemd_files(data_files, dest=systemd_dir_path)
    elif name == 'iosxe':
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files, src=["config/iosxe/waagent.conf"])
        set_logrotate_files(data_files)
        set_udev_files(data_files)
        set_systemd_files(data_files, dest=systemd_dir_path)
        if version.startswith("7.1"):
            # TODO this is a mitigation to systemctl bug on 7.1
            set_sysv_files(data_files)
    elif name == 'openwrt':
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files)
        set_logrotate_files(data_files)
        set_sysv_files(data_files, dest='/etc/init.d', src=["init/openwrt/waagent"])
    elif name == 'photonos':
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files, src=["config/photonos/waagent.conf"])
        set_systemd_files(data_files, dest=systemd_dir_path,
                          src=["init/photonos/waagent.service"])
    else:
        # Use default setting
        set_bin_files(data_files, dest=agent_bin_path)
        set_conf_files(data_files)
        set_logrotate_files(data_files)
        set_udev_files(data_files)
        set_sysv_files(data_files)
    return data_files


def debian_has_systemd():
    try:
        return subprocess.check_output(
            ['cat', '/proc/1/comm']).strip() == 'systemd'
    except subprocess.CalledProcessError:
        return False


class install(_install):  # pylint: disable=C0103
    user_options = _install.user_options + [
        ('lnx-distro=', None, 'target Linux distribution'),
        ('lnx-distro-version=', None, 'target Linux distribution version'),
        ('lnx-distro-fullname=', None, 'target Linux distribution full name'),
        ('register-service', None, 'register as startup service and start'),
        ('skip-data-files', None, 'skip data files installation'),
    ]

    def initialize_options(self):
        _install.initialize_options(self)
        # pylint: disable=attribute-defined-outside-init
        self.lnx_distro = DISTRO_NAME
        self.lnx_distro_version = DISTRO_VERSION
        self.lnx_distro_fullname = DISTRO_FULL_NAME
        self.register_service = False
        self.skip_data_files = False
        # pylint: enable=attribute-defined-outside-init

    def finalize_options(self):
        _install.finalize_options(self)
        if self.skip_data_files:
            return

        data_files = get_data_files(self.lnx_distro, self.lnx_distro_version,
                                    self.lnx_distro_fullname)
        self.distribution.data_files = data_files
        self.distribution.reinitialize_command('install_data', True)

    def run(self):
        _install.run(self)
        if self.register_service:
            osutil = get_osutil()
            osutil.register_agent_service()
            osutil.stop_agent_service()
            osutil.start_agent_service()


# Note to packagers and users from source.
# In version 3.5 of Python distribution information handling in the platform
# module was deprecated. Depending on the Linux distribution the
# implementation may be broken prior to Python 3.7 wher the functionality
# will be removed from Python 3
requires = []  # pylint: disable=invalid-name
if float(sys.version[:3]) >= 3.7:
    requires = ['distro']  # pylint: disable=invalid-name

modules = []  # pylint: disable=invalid-name

if "bdist_egg" in sys.argv:
    modules.append("__main__")

setuptools.setup(
    name=AGENT_NAME,
    version=AGENT_VERSION,
    long_description=AGENT_DESCRIPTION,
    author='Microsoft Corporation',
    author_email='walinuxagent@microsoft.com',
    platforms='Linux',
    url='https://github.com/Azure/WALinuxAgent',
    license='Apache License Version 2.0',
    packages=find_packages(exclude=["tests*", "dcr*"]),
    py_modules=modules,
    install_requires=requires,
    cmdclass={
        'install': install
    }
)

