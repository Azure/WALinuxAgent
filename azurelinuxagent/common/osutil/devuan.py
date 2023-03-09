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

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class DevuanOSUtil(DefaultOSUtil):

    def __init__(self):
        super(DevuanOSUtil, self).__init__()
        self.jit_enabled = True

    def restart_ssh_service(self):
        logger.info("DevuanOSUtil::restart_ssh_service - trying to restart sshd")
        return shellutil.run("/usr/sbin/service restart ssh", chk_err=False)

    def stop_agent_service(self):
        logger.info("DevuanOSUtil::stop_agent_service - trying to stop waagent")
        return shellutil.run("/usr/sbin/service walinuxagent stop", chk_err=False)

    def start_agent_service(self):
        logger.info("DevuanOSUtil::start_agent_service - trying to start waagent")
        return shellutil.run("/usr/sbin/service walinuxagent start", chk_err=False)

    def start_network(self):
        pass

    def remove_rules_files(self, rules_files=""):
        pass

    def restore_rules_files(self, rules_files=""):
        pass

    def get_dhcp_lease_endpoint(self):
        return self.get_endpoint_from_leases_path('/var/lib/dhcp/dhclient.*.leases')
