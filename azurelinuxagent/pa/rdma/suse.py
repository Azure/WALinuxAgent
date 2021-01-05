# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+
#

import glob
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.rdma import RDMAHandler


class SUSERDMAHandler(RDMAHandler):

    def install_driver(self):  # pylint: disable=R1710
        """Install the appropriate driver package for the RDMA firmware"""

        fw_version = self.get_rdma_version()
        if not fw_version:
            error_msg = 'RDMA: Could not determine firmware version. '
            error_msg += 'Therefore, no driver will be installed.'
            logger.error(error_msg)
            return
        zypper_install = 'zypper -n in %s'
        zypper_install_noref = 'zypper -n --no-refresh in %s'
        zypper_lock = 'zypper addlock %s'
        zypper_remove = 'zypper -n rm %s'
        zypper_search = 'zypper -n se -s %s'
        zypper_unlock = 'zypper removelock %s'
        package_name = 'dummy'
        # Figure out the kernel that is running to find the proper kmp
        cmd = 'uname -r'
        status, kernel_release = shellutil.run_get_output(cmd)  # pylint: disable=W0612
        if 'default' in kernel_release:
            package_name = 'msft-rdma-kmp-default'
            info_msg = 'RDMA: Detected kernel-default'
            logger.info(info_msg)
        elif 'azure' in kernel_release:
            package_name = 'msft-rdma-kmp-azure'
            info_msg = 'RDMA: Detected kernel-azure'
            logger.info(info_msg)
        else:
            error_msg = 'RDMA: Could not detect kernel build, unable to '
            error_msg += 'load kernel module. Kernel release: "%s"'
            logger.error(error_msg % kernel_release)
            return
        cmd = zypper_search % package_name
        status, repo_package_info = shellutil.run_get_output(cmd)
        driver_package_versions = []
        driver_package_installed = False
        for entry in repo_package_info.split('\n'):
            if package_name in entry:
                sections = entry.split('|')
                if len(sections) < 4:
                    error_msg = 'RDMA: Unexpected output from"%s": "%s"'
                    logger.error(error_msg % (cmd, entry))
                    continue
                installed = sections[0].strip()
                version = sections[3].strip()
                driver_package_versions.append(version)
                if fw_version in version and installed.startswith('i'):
                    info_msg = 'RDMA: Matching driver package "%s-%s" '
                    info_msg += 'is already installed, nothing to do.'
                    logger.info(info_msg % (package_name, version))
                    return True
                if installed.startswith('i'):
                    # A driver with a different version is installed
                    driver_package_installed = True
                    cmd = zypper_unlock % package_name
                    result = shellutil.run(cmd)
                    info_msg = 'Driver with different version installed '
                    info_msg += 'unlocked package "%s".'
                    logger.info(info_msg % (package_name))

        # If we get here the driver package is installed but the
        # version doesn't match or no package is installed
        requires_reboot = False
        if driver_package_installed:
            # Unloading the particular driver with rmmod does not work
            # We have to reboot after the new driver is installed
            if self.is_driver_loaded():
                info_msg = 'RDMA: Currently loaded driver does not match the '
                info_msg += 'firmware implementation, reboot will be required.'
                logger.info(info_msg)
                requires_reboot = True
            logger.info("RDMA: removing package %s" % package_name)
            cmd = zypper_remove % package_name
            shellutil.run(cmd)
            logger.info("RDMA: removed package %s" % package_name)

        logger.info("RDMA: looking for fw version %s in packages" % fw_version)
        for entry in driver_package_versions:
            if fw_version not in entry:
                logger.info("Package '%s' is not a match." % entry)
            else:
                logger.info("Package '%s' is a match. Installing." % entry)
                complete_name = '%s-%s' % (package_name, entry)
                cmd = zypper_install % complete_name
                result = shellutil.run(cmd)
                if result:
                    error_msg = 'RDMA: Failed install of package "%s" '
                    error_msg += 'from available repositories.'
                    logger.error(error_msg % complete_name)
                msg = 'RDMA: Successfully installed "%s" from '
                msg += 'configured repositories'
                logger.info(msg % complete_name)
                # Lock the package so it does not accidentally get updated
                cmd = zypper_lock % package_name
                result = shellutil.run(cmd)
                info_msg = 'Applied lock to "%s"' % package_name
                logger.info(info_msg)
                if not self.load_driver_module() or requires_reboot:
                    self.reboot_system()
                return True
        else:  # pylint: disable=W0120
            logger.info("RDMA: No suitable match in repos. Trying local.")
            local_packages = glob.glob('/opt/microsoft/rdma/*.rpm')
            for local_package in local_packages:
                logger.info("Examining: %s" % local_package)
                if local_package.endswith('.src.rpm'):
                    continue
                if (
                        package_name in local_package and
                        fw_version in local_package
                ):
                    logger.info("RDMA: Installing: %s" % local_package)
                    cmd = zypper_install_noref % local_package
                    result = shellutil.run(cmd)
                    if result and result != 106:
                        error_msg = 'RDMA: Failed install of package "%s" '
                        error_msg += 'from local package cache'
                        logger.error(error_msg % local_package)
                        break
                    msg = 'RDMA: Successfully installed "%s" from '
                    msg += 'local package cache'
                    logger.info(msg % (local_package))
                    # Lock the package so it does not accidentally get updated
                    cmd = zypper_lock % package_name
                    result = shellutil.run(cmd)
                    info_msg = 'Applied lock to "%s"' % package_name
                    logger.info(info_msg)
                    if not self.load_driver_module() or requires_reboot:
                        self.reboot_system()
                    return True
            else:
                error_msg = 'Unable to find driver package that matches '
                error_msg += 'RDMA firmware version "%s"' % fw_version
                logger.error(error_msg)
                return
