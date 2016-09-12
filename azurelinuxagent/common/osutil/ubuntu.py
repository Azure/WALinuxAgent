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

import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil

class Ubuntu14OSUtil(DefaultOSUtil):
    def __init__(self):
        super(Ubuntu14OSUtil, self).__init__()

    def start_network(self):
        return shellutil.run("service networking start", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("service walinuxagent stop", chk_err=False)

    def start_agent_service(self):
        return shellutil.run("service walinuxagent start", chk_err=False)

    def remove_rules_files(self, rules_files=""):
        pass

    def restore_rules_files(self, rules_files=""):
        pass

    def get_dhcp_lease_endpoint(self):
        return self.get_endpoint_from_leases_path('/var/lib/dhcp/dhclient.*.leases')

class Ubuntu12OSUtil(Ubuntu14OSUtil):
    def __init__(self):
        super(Ubuntu12OSUtil, self).__init__()

    # Override
    def get_dhcp_pid(self):
        ret = shellutil.run_get_output("pidof dhclient3", chk_err=False)
        return ret[1] if ret[0] == 0 else None

class UbuntuOSUtil(Ubuntu14OSUtil):
    def __init__(self):
        super(UbuntuOSUtil, self).__init__()

    def register_agent_service(self):
        return shellutil.run("systemctl unmask walinuxagent", chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("systemctl mask walinuxagent", chk_err=False)

class UbuntuSnappyOSUtil(Ubuntu14OSUtil):
    def __init__(self):
        super(UbuntuSnappyOSUtil, self).__init__()
        self.conf_file_path = '/apps/walinuxagent/current/waagent.conf'
