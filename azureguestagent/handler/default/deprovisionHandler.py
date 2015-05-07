# Windows Azure Linux Agent
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

from azureguestagent.utils.osutil import CurrOSUtilUtil
import azureguestagent.utils.fileutil as fileutil

class Deprovisionhandler(object):
    
    def promptUser(self, delRootPasswd, ovf):
        print("WARNING! The waagent service will be stopped.")
        print("WARNING! All SSH host key pairs will be deleted.")
        print("WARNING! Cached DHCP leases will be deleted.")
        if delRootPasswd:
            print("WARNING! root password will be disabled. "
                  "You will not be able to login as root.")
        if ovf is not None and deluser:
            print ("WARNING! {0} account and entire home directory "
                   "will be deleted.").format(ovf.getUserName())
        
    def deprovision(force=False, deluser=False):
        configPath = CurrOSUtil.GetConfigurationPath()
        config = conf.LoadConfiguration(configPath)
        delRootPasswd = config.getSwitch("Provisioning.DeleteRootPassword", False)
        protocol = proto.GetDefaultProtocol()
        ovf = protocol.getOvf()

        self.promptUser(delRootPasswd, ovf)
        if not force:
            confirm = raw_input("Do you want to proceed (y/n)")
            if not confirm.lower().startswith('y'):
                return

        self.cleanup(delRootPasswd)
    
    def cleanup(self, delRootPasswd, ovf)
        CurrOSUtil.StopAgentService()
        if delRootPasswd:
            CurrOSUtil.DeleteRootPassword()
        if config.getSwitch("Provisioning.RegenerateSshHostkey", False):
            shellutil.Run("rm -f /etc/ssh/ssh_host_*key*")
        CurrOSUtil.SetHostname('localhost.localdomain')
        fileutil.CleanupDirs(CurrOSUtil.GetLibDir(), "/var/lib/dhclient", 
                             "/var/lib/dhcpcd", "/var/lib/dhcp")
        fileutil.RemoveFiles('/root/.bash_history', '/var/log/waagent.log')

        if ovf is not None and deluser:
            CurrOSUtil.DeleteAccount(ovf.getUserName())

