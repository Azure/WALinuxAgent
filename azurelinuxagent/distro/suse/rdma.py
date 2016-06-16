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
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.distro.default.rdma import RDMAHandler


class SUSERDMAHandler(RDMAHandler):
    def install_driver(self):
        """Install the appropriate driver package for the RDMA firmware"""

        fw_version = self._RDMAHandler__get_rdma_version()
        if not fw_version:
            error_msg = 'Could not determine firmware version. Therefore, '
            error_msg += 'no driver will be installed.'
            logger.error(error_msg)
            return
        zypper_install = 'zypper -n in'
        zypper_remove = 'zypper -n rm'
        zypper_search = 'zypper se -s'
        package_name = 'msft-rdma-kmp-default'
        cmd = '%s %s' % (zypper_search, package_name)
        status, repo_package_info = shellutil.run_get_output(cmd)
        driver_package_versions = []
        driver_package_installed = False
        for entry in repo_package_info.split('\n'):
            if package_name in entry:
                sections = entry.split('|')
                if len(sections) < 4:
                    error_msg = 'Unexpected output of "%s" with result "%s"'
                    logger.error(error_msg % (cmd, entry))
                    continue
                installed = sections[0].strip()
                version = sections[3].strip()
                driver_package_versions.append(version)
                if fw_version in version and installed == 'i':
                    info_msg = 'Matching driver package "%s-%s" '
                    info_msg += 'is already installed, nothing to do'
                    logger.info(info_msg % (package_name, version))
                    return True
                if installed == 'i':
                    driver_package_installed = True

        # If we get here the driver package is installed but the
        # version doesn't match or no package is installed
        if driver_package_installed:
            self.remove_driver_module()
            cmd = '%s &s' % (zypper_remove, package_name)
            shellutil.run(cmd)

        for entry in driver_package_versions:
            if fw_version in version:
                cmd = '%s %s-%s' % (zypper_install, package_name, version)
                result = shellutil.run(cmd)
                if result:
                    error_msg = 'Failed install of package "%s-%s" '
                    error_msg += 'from available repositories.'
                    logger.error(error_msg % (package_name, version))
                msg = 'Successfully installed "%s-%s" from '
                msg += 'configured repositories'
                logger.info(msg % (package_name, version))
                self.load_driver_module()
                break
        else:
            local_packages = glob.glob('/opt/microsoft/rdma/*.rpm')
            for local_package in local_packages:
                if local_package.endswith('.src.rpm'):
                    continue
                if (
                        package_name in local_package and
                        fw_version in local_package
                ):
                    cmd = '%s %s' % (zypper_install, local_package)
                    result = shellutil.run(cmd)
                    if result:
                        error_msg = 'Failed install of package "%s" '
                        error_msg += 'from local package cache'
                        logger.error(error_msg % local_package)
                        break
                    msg = 'Successfully installed "%s" from '
                    msg += 'local package cache'
                    logger.info(msg % (local_package))
                    self.load_driver_module()
                    break
            else:
                error_msg = 'Unable to find driver package that matches '
                error_msg += 'RDMA firmware version "%s"' % fw_version
                logger.error(error_msg)
