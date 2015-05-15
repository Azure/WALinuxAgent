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

import azureguestagent.conf as conf
from azureguestagent.utils.osutil import CurrOSUtil
import azureguestagent.utils.fileutil as fileutil

class DeprovisionAction(object):
    def __init__(self, func, args=[], kwargs={}):
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def invoke(self):
        self.func(*self.args, **self.kwargs)

class DeprovisionHandler(object):
   
    def deleteRootPassword(self, warnings, actions):
        warnings.append("WARNING! root password will be disabled. "
                        "You will not be able to login as root.")

        actions.append(DeprovisionAction(CurrOSUtil.DeleteRootPassword))
    
    def deleteUser(self, warnings, actions):
        protocol = proto.GetDefaultProtocol()
        ovf = protocol.getOvf()
        if ovf is None:
            warnings.append("WARNING! ovf-env.xml is not found.")
            warnings.append("WARNING! Skip delete user.")
            return

        userName = ovf.getUserName()
        warnings.append(("WARNING! {0} account and entire home directory "
                         "will be deleted.").format(userName))
        actions.append(DeprovisionAction(CurrOSUtil.DeleteAccount, [userName]))


    def regenerateHostKeyPair(self, warnings, actions):
        warnings.append("WARNING! All SSH host key pairs will be deleted.")
        actions.append(DeprovisionAction(CurrOSUtil.SetHostname, 
                                         ['localhost.localdomain']))
        actions.append(DeprovisionAction(shellutil.Run, 
                                         ['rm -f /etc/ssh/ssh_host_*key*']))
    
    def stopAgentService(self, warnings, actions):
        warnings.append("WARNING! The waagent service will be stopped.")
        actions.append(DeprovisionAction(CurrOSUtil.StopAgentService))
        filesToDel = ['/root/.bash_history', '/var/log/waagent.log']
        actions.append(DeprovisionAction(fileutil.RemoveFiles, [filesToDel]))

    def deleteDhcpLease(self, warnings, actions):
        warnings.append("WARNING! Cached DHCP leases will be deleted.")
        dirsToDel = [CurrOSUtil.GetLibDir(), "/var/lib/dhclient", 
                     "/var/lib/dhcpcd", "/var/lib/dhcp"]
        actions.append(DeprovisionAction(fileutil.CleanupDirs, [dirsToDel]))

    def setUp(self, deluser):
        warnings = []
        actions = []

        self.stopAgentService(warnings, actions)
        if conf.GetSwitch("Provisioning.RegenerateSshHostkey", False):
            self.regenerateHostKeyPair(warnings, actions)
        
        self.deleteDhcpLease(warnings, actions)

        if conf.GetSwitch("Provisioning.DeleteRootPassword", False):
            self.deleteRootPassword(warnings, actions)

        if deluser:
            self.deleteUser(warnings, actions)

        return warnings, actions
        
    def deprovision(self, force=False, deluser=False):
        warnings, actions = self.setUp(deluser)
        for warning in warnings:
            print warning

        if not force:
            confirm = raw_input("Do you want to proceed (y/n)")
            if not confirm.lower().startswith('y'):
                return

        for action in actions:
            action.invoke()
    
    
    def cleanup(self):
        fileutil.CleanupDirs()

