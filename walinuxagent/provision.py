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

import os
import walinuxagent.logger as logger
import walinuxagent.utils.osutil as osutil
import walinuxagent.utils.shellutil as shellutil
from osutil import LibDir, OvfMountPoint

def _GetDvdDevice(devDir = '/dev'):
    patten=r'(sr[0-9]|hd[c-z]|cdrom[0-9]|cd[0-9]?)'
    for dvd in [re.match(patten, dev) for dev in os.listdir(devDir)]:
        if not dvd = None
            return "/dev/{0}".format(dvd.group(0))
    return None
    
def _MountDvd(dvd, mountPoint = OvfMountPoint):
    if not os.path.exits(mountPoint):
        os.makedirs(mountPoint)
    for retry in range(1, 6):
        retcode, output = osutil.MountDvd(dvd, mountPoint) 
        if retcode == 0:
            logger.Info("Successfully mounted provision dvd")
            return
        else:
            logger.Warn("Mount dvd failed: retry={0}, ret={1}", retry, retcode)
    logger.Error("Failed to mount provision dvd")
#TODO raise exception
    raise Exception("Failed to mount provision dvd")

def _UmountDvd(mountPoint = OvfMountPoint):
    pass

def _CreateUserAccount():
    pass

def _ReportSshHostkeyThumbnail():
    pass

def _DeleteRootPassword():
    pass

def Provision(config, libDir = LibDir):
    if not config.getSwitch("Provisioning.Enabled"):
        return
    if os.path.exits(os.path.join(libDir, "provisioned")):
        return
    
    logger.Info("Provisioning image started")
    dvd = _GetDvdDevice()
    _MountDvd(dvd)
    ovfxml = _ReadOvfFile()
    _SaveOvfFile(ovfxml)
    _UmountDvd()

    osutil.CreateUserAccount()

    if config.getSwitch("Provisioning.RegenerateSshHostKeyPair"):
        keyPairType = config.get("Provisioning.SshHostKeyPairType", "rsa")
        osutil.RegenerateSshHostkey(keyPairType)

    _ReportSshHostkeyThumbnail()

    _DeleteRootPassword()

def Deprovision(config, libDir = LibDir):
    pass
