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

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.osutil.redhat import Redhat6xOSUtil

'''
The IOSXE distribution is a variant of the Centos distribution, 
version 7.1.
The primary difference is that IOSXE makes some assumptions about
the waagent environment:
 - only the waagent daemon is executed
 - no provisioning is performed
 - no DHCP-based services are available
'''
class IosxeOSUtil(DefaultOSUtil):
    def __init__(self):
        super(IosxeOSUtil, self).__init__()

    def set_hostname(self, hostname):
        """
        Unlike redhat 6.x, redhat 7.x will set hostname via hostnamectl
        Due to a bug in systemd in Centos-7.0, if this call fails, fallback
        to hostname.
        """
        hostnamectl_cmd = "hostnamectl set-hostname {0} --static".format(hostname)
        if shellutil.run(hostnamectl_cmd, chk_err=False) != 0:
            logger.warn("[{0}] failed, attempting fallback".format(hostnamectl_cmd))
            DefaultOSUtil.set_hostname(self, hostname)

    def publish_hostname(self, hostname):
        """
        Restart NetworkManager first before publishing hostname
        """
        shellutil.run("service NetworkManager restart")
        super(RedhatOSUtil, self).publish_hostname(hostname)

    def register_agent_service(self):
        return shellutil.run("systemctl enable waagent", chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("systemctl disable waagent", chk_err=False)

    def openssl_to_openssh(self, input_file, output_file):
        DefaultOSUtil.openssl_to_openssh(self, input_file, output_file)

    def is_dhcp_available(self):
        return (False, '168.63.129.16')

    def get_instance_id(self):
        '''
        Azure records a UUID as the instance ID
        First check /sys/class/dmi/id/product_uuid.
        If that is missing, then extracts from dmidecode
        If nothing works (for old VMs), return the empty string
        '''
        if os.path.isfile(PRODUCT_ID_FILE):
            try:
                s = fileutil.read_file(PRODUCT_ID_FILE).strip()
                return self._correct_instance_id(s.strip())
            except IOError:
                pass
        rc, s = shellutil.run_get_output(DMIDECODE_CMD)
        if rc != 0 or UUID_PATTERN.match(s) is None:
            return ""
        return self._correct_instance_id(s.strip())
