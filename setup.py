#!/usr/bin/python
#
# Windows Azure Linux Agent setup.py
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
import sys
import platform
from distutils.core import setup

Init_Suse = """\
#! /bin/sh

### BEGIN INIT INFO
# Provides: WindowsAzureLinuxAgent
# Required-Start: $network sshd
# Required-Stop: $network sshd
# Default-Start: 3 5
# Default-Stop: 0 1 2 6
# Description: Start the WindowsAzureLinuxAgent
### END INIT INFO

WAZD_BIN=/usr/sbin/waagent
test -x $WAZD_BIN || exit 5

case "$1" in
    start)
        echo "Starting WindowsAzureLinuxAgent"
        ## Start daemon with startproc(8). If this fails
        ## the echo return value is set appropriate.

        startproc -f $WAZD_BIN -daemon
        exit $?
        ;;
    stop)
        echo "Shutting down WindowsAzureLinuxAgent"
        ## Stop daemon with killproc(8) and if this fails
        ## set echo the echo return value.

        killproc -p /var/run/waagent.pid $WAZD_BIN
        exit $?
        ;;
    try-restart)
        ## Stop the service and if this succeeds (i.e. the
        ## service was running before), start it again.
        $0 status >/dev/null &&  $0 restart
        ;;
    restart)
        ## Stop the service and regardless of whether it was
        ## running or not, start it again.
        $0 stop
        $0 start
        ;;
    force-reload|reload)
        ;;
    status)
        echo -n "Checking for service WindowsAzureLinuxAgent "
        ## Check status with checkproc(8), if process is running
        ## checkproc will return with exit status 0.

        checkproc -p $WAZD_PIDFILE $WAZD_BIN
        exit $?
        ;;
    probe)
        ;;
    *)
        echo "Usage: $0 {start|stop|status|try-restart|restart|force-reload|reload}"
        exit 1
        ;;
esac
"""

Init_RedHat = """\
#!/bin/bash
#
# Init file for WindowsAzureLinuxAgent.
#
# chkconfig: 2345 60 80
# description: WindowsAzureLinuxAgent
#

# source function library
. /etc/rc.d/init.d/functions

RETVAL=0
FriendlyName="WindowsAzureLinuxAgent"
WAZD_BIN=/usr/sbin/waagent

start()
{
    echo -n $"Starting $FriendlyName: "
    $WAZD_BIN -daemon &
}

stop()
{
    echo -n $"Stopping $FriendlyName: "
    killproc -p /var/run/waagent.pid $WAZD_BIN
    RETVAL=$?
    echo
    return $RETVAL
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    reload)
        ;;
    report)
        ;;
    status)
        status $WAZD_BIN
        RETVAL=$?
        ;;
    *)
        echo $"Usage: $0 {start|stop|restart|status}"
        RETVAL=1
esac
exit $RETVAL
"""

WaagentConf = """\
#
# Windows Azure Linux Agent Configuration
#

Role.StateConsumer=None                 # Specified program is invoked with "Ready" or "Shutdown".
                                        # Shutdown will be initiated only after the program returns. Windows Azure will
                                        # power off the VM if shutdown is not completed within ?? minutes.
Role.ConfigurationConsumer=None         # Specified program is invoked with XML file argument specifying role configuration.
Role.TopologyConsumer=None              # Specified program is invoked with XML file argument specifying role topology.

Provisioning.Enabled=y                  #
Provisioning.DeleteRootPassword=y       # Password authentication for root account will be unavailable.
Provisioning.RegenerateSshHostKeyPair=y # Generate fresh host key pair.
Provisioning.SshHostKeyPairType=rsa     # Supported values are "rsa", "dsa" and "ecdsa".
Provisioning.MonitorHostName=y          # Monitor host name changes and publish changes via DHCP requests.

ResourceDisk.Format=y                   # Format if unformatted. If 'n', resource disk will not be mounted.
ResourceDisk.Filesystem=ext4            #
ResourceDisk.MountPoint=/mnt/resource   #
ResourceDisk.EnableSwap=n               # Create and use swapfile on resource disk.
ResourceDisk.SwapSizeMB=0               # Size of the swapfile.

LBProbeResponder=y                      # Respond to load balancer probes if requested by Windows Azure.

Logs.Verbose=n                          #

OS.RootDeviceScsiTimeout=300            # Root device timeout in seconds.
OS.OpensslPath=None                     # If "None", the system default version is used.
"""

WaagentLogrotate = """\
/var/log/waagent.log {
    monthly
    rotate 6
    notifempty
    missingok
}
"""

def SetFileContents(filepath, contents):
    """
    Write 'contents' to 'filepath'.
    """
    with open(filepath, "w+") as F :
        F.write(contents)
    return 0

def PackagedInstall(buildroot):
    """
    Called from setup.py for use by RPM.
    Generic implementation Creates directories and
    files /etc/waagent.conf, /etc/init.d/waagent, /usr/sbin/waagent,
    /etc/logrotate.d/waagent, /etc/sudoers.d/waagent under buildroot.
    """
    if not os.path.exists(buildroot+'/etc'):
        os.mkdir(buildroot+'/etc')
    SetFileContents(buildroot+'/etc/waagent.conf', WaagentConf)
        
    if not os.path.exists(buildroot+'/etc/logrotate.d'):
        os.mkdir(buildroot+'/etc/logrotate.d')
    SetFileContents(buildroot+'/etc/logrotate.d/waagent', WaagentLogrotate)
    
    # Regular init.d configurations
    filename = "waagent"
    filepath = buildroot+ "/etc/init.d/" + filename
    if 'SuSE' in platform.dist()[0]:
        init_file=Init_Suse
    else :
        init_file=Init_RedHat
    if not os.path.exists(buildroot+'/etc/init.d'):
        os.mkdir(buildroot+'/etc/init.d')
    SetFileContents(filepath, init_file)
    os.chmod(filepath, 0755)


BUILDROOT=None

for a in range(len(sys.argv)):
    if sys.argv[a] == '--buildroot':
        BUILDROOT=sys.argv[a+1]

if BUILDROOT : # called by rpm-build
    PackagedInstall(BUILDROOT)

