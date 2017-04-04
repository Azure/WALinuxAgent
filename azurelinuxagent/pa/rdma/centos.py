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

import glob
import os
import re
import time
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.rdma import RDMAHandler


class CentOSRDMAHandler(RDMAHandler):
    rdma_user_mode_package_name = 'microsoft-hyper-v-rdma'
    rdma_kernel_mode_package_name = 'kmod-microsoft-hyper-v-rdma'
    rdma_wrapper_package_name = 'msft-rdma-drivers'

    hyper_v_package_name = "hypervkvpd"
    hyper_v_package_name_new = "microsoft-hyper-v"

    version_major = None
    version_minor = None

    def __init__(self, distro_version):
        v = distro_version.split('.')
        if len(v) < 2:
            raise Exception('Unexpected centos version: %s' % distro_version)
        self.version_major, self.version_minor = v[0], v[1]

    def install_driver(self):
        """
        Install the KVP daemon and the appropriate RDMA driver package for the
        RDMA firmware.
        """

        # Check and install the KVP deamon if it not running
        time.sleep(10) # give some time for the hv_hvp_daemon to start up.
        kvpd_running = RDMAHandler.is_kvp_daemon_running()
        logger.info('RDMA: kvp daemon running: %s' % kvpd_running)
        if not kvpd_running:
            self.check_or_install_kvp_daemon()
        time.sleep(10) # wait for post-install reboot or kvp to come up

        # Find out RDMA firmware version and see if the existing package needs
        # updating or if the package is missing altogether (and install it)
        fw_version = RDMAHandler.get_rdma_version()
        if not fw_version:
            raise Exception('Cannot determine RDMA firmware version')
        logger.info("RDMA: found firmware version: {0}".format(fw_version))
        fw_version = self.get_int_rdma_version(fw_version)
        installed_pkg = self.get_rdma_package_info()
        if installed_pkg:
            logger.info(
                'RDMA: driver package present: {0}'.format(installed_pkg))
            if self.is_rdma_package_up_to_date(installed_pkg, fw_version):
                logger.info('RDMA: driver package is up-to-date')
                return
            else:
                logger.info('RDMA: driver package needs updating')
                self.update_rdma_package(fw_version)
        else:
            logger.info('RDMA: driver package is NOT installed')
            self.update_rdma_package(fw_version)

    def is_rdma_package_up_to_date(self, pkg, fw_version):
        # Example match (pkg name, -, followed by 3 segments, fw_version and -):
        # - pkg=microsoft-hyper-v-rdma-4.1.0.142-20160323.x86_64
        # - fw_version=142
        pattern = '{0}-(\d+\.){{3,}}({1})-'.format(self.rdma_user_mode_package_name, fw_version)
        return re.match(pattern, pkg)

    @staticmethod
    def get_int_rdma_version(version):
        s = version.split('.')
        if len(s) == 0:
            raise Exception('Unexpected RDMA firmware version: "%s"' % version)
        return s[0]

    def get_rdma_package_info(self):
        """
        Returns the installed rdma package name or None
        """
        ret, output = shellutil.run_get_output(
            'rpm -q %s' % self.rdma_user_mode_package_name, chk_err=False)
        if ret != 0:
            return None
        return output

    def update_rdma_package(self, fw_version):
        logger.info("RDMA: updating RDMA packages")
        self.refresh_repos()
        self.force_install_package(self.rdma_wrapper_package_name)
        self.install_rdma_drivers(fw_version)

    def force_install_package(self, pkg_name):
        """
        Attempts to remove existing package and installs the package
        """
        logger.info('RDMA: Force installing package: %s' % pkg_name)
        if self.uninstall_package(pkg_name) != 0:
            logger.info('RDMA: Erasing package failed but will continue')
        if self.install_package(pkg_name) != 0:
            raise Exception('Failed to install package "{0}"'.format(pkg_name))
        logger.info('RDMA: installation completed: %s' % pkg_name)

    @staticmethod
    def uninstall_package(pkg_name):
        return shellutil.run('yum erase -y -q {0}'.format(pkg_name))

    @staticmethod
    def install_package(pkg_name):
        return shellutil.run('yum install -y -q {0}'.format(pkg_name))

    def refresh_repos(self):
        logger.info("RDMA: refreshing yum repos")
        if shellutil.run('yum clean all') != 0:
            raise Exception('Cleaning yum repositories failed')
        if shellutil.run('yum updateinfo') != 0:
            raise Exception('Failed to act on yum repo update information')
        logger.info("RDMA: repositories refreshed")

    def install_rdma_drivers(self, fw_version):
        """
        Installs the drivers from /opt/rdma/rhel[Major][Minor] directory,
        particularly the microsoft-hyper-v-rdma-* kmod-* and (no debuginfo or
        src). Tries to uninstall them first.
        """
        pkg_dir = '/opt/microsoft/rdma/rhel{0}{1}'.format(
            self.version_major, self.version_minor)
        logger.info('RDMA: pkgs dir: {0}'.format(pkg_dir))
        if not os.path.isdir(pkg_dir):
            raise Exception('RDMA packages directory %s is missing' % pkg_dir)

        pkgs = os.listdir(pkg_dir)
        logger.info('RDMA: found %d files in package directory' % len(pkgs))

        # Uninstal KVP daemon first (if exists)
        self.uninstall_kvp_driver_package_if_exists()

        # Install kernel mode driver (kmod-microsoft-hyper-v-rdma-*)
        kmod_pkg = self.get_file_by_pattern(
            pkgs, "%s-(\d+\.){3,}(%s)-\d{8}\.x86_64.rpm" % (self.rdma_kernel_mode_package_name, fw_version))
        if not kmod_pkg:
            raise Exception("RDMA kernel mode package not found")
        kmod_pkg_path = os.path.join(pkg_dir, kmod_pkg)
        self.uninstall_pkg_and_install_from(
            'kernel mode', self.rdma_kernel_mode_package_name, kmod_pkg_path)

        # Install user mode driver (microsoft-hyper-v-rdma-*)
        umod_pkg = self.get_file_by_pattern(
            pkgs, "%s-(\d+\.){3,}(%s)-\d{8}\.x86_64.rpm" % (self.rdma_user_mode_package_name, fw_version))
        if not umod_pkg:
            raise Exception("RDMA user mode package not found")
        umod_pkg_path = os.path.join(pkg_dir, umod_pkg)
        self.uninstall_pkg_and_install_from(
            'user mode', self.rdma_user_mode_package_name, umod_pkg_path)

        logger.info("RDMA: driver packages installed")
        if not self.load_driver_module() or not self.is_driver_loaded():
            logger.info("RDMA: driver module is not loaded; reboot required")
            self.reboot_system()
        else:
            logger.info("RDMA: kernel module is loaded")

    @staticmethod
    def get_file_by_pattern(list, pattern):
        for l in list:
            if re.match(pattern, l):
                return l
        return None

    def uninstall_pkg_and_install_from(self, pkg_type, pkg_name, pkg_path):
        logger.info(
            "RDMA: Processing {0} driver: {1}".format(pkg_type, pkg_path))
        logger.info("RDMA: Try to uninstall existing version: %s" % pkg_name)
        if self.uninstall_package(pkg_name) == 0:
            logger.info("RDMA: Successfully uninstaled %s" % pkg_name)
        logger.info(
            "RDMA: Installing {0} package from {1}".format(pkg_type, pkg_path))
        if self.install_package(pkg_path) != 0:
            raise Exception(
                "Failed to install RDMA {0} package".format(pkg_type))

    @staticmethod
    def is_package_installed(pkg):
        """Runs rpm -q and checks return code to find out if a package
        is installed"""
        return shellutil.run("rpm -q %s" % pkg, chk_err=False) == 0

    def uninstall_kvp_driver_package_if_exists(self):
        logger.info('RDMA: deleting existing kvp driver packages')

        kvp_pkgs = [self.hyper_v_package_name,
                    self.hyper_v_package_name_new]

        for kvp_pkg in kvp_pkgs:
            if not self.is_package_installed(kvp_pkg):
                logger.info(
                    "RDMA: kvp package %s does not exist, skipping" % kvp_pkg)
            else:
                logger.info('RDMA: erasing kvp package "%s"' % kvp_pkg)
                if shellutil.run("yum erase -q -y %s" % kvp_pkg, chk_err=False) == 0:
                    logger.info("RDMA: successfully erased package")
                else:
                    logger.error("RDMA: failed to erase package")

    def check_or_install_kvp_daemon(self):
        """Checks if kvp daemon package is installed, if not installs the
        package and reboots the machine.
        """
        logger.info("RDMA: Checking kvp daemon packages.")
        kvp_pkgs = [self.hyper_v_package_name,
                    self.hyper_v_package_name_new]

        for pkg in kvp_pkgs:
            logger.info("RDMA: Checking if package %s installed" % pkg)
            installed = self.is_package_installed(pkg)
            if installed:
                raise Exception('RDMA: package %s is installed, but the kvp daemon is not running' % pkg)

        kvp_pkg_to_install=self.hyper_v_package_name
        logger.info("RDMA: no kvp drivers installed, will install '%s'" % kvp_pkg_to_install)
        logger.info("RDMA: trying to install kvp package '%s'" % kvp_pkg_to_install)
        if self.install_package(kvp_pkg_to_install) != 0:
            raise Exception("RDMA: failed to install kvp daemon package '%s'" % kvp_pkg_to_install)
        logger.info("RDMA: package '%s' successfully installed" % kvp_pkg_to_install)
        logger.info("RDMA: Machine will now be rebooted.")
        self.reboot_system()