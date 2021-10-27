#!/usr/bin/env bash

#            1          2           3
# Usage:
set -euxo pipefail

if systemctl status walinuxagent;then
    agent="walinuxagent"
else
    agent="waagent"
fi

systemctl stop $agent
# Change ETP collection period for faster testing and turn on verbose
echo 'Debug.EtpCollectionPeriod=30' >> /etc/waagent.conf
sed -i 's/Logs.Verbose=n/Logs.Verbose=y/g' /etc/waagent.conf
# Moving the log to create a new fresh log for testing
mv /var/log/waagent.log /var/log/waagent.old.log
systemctl start $agent
systemctl status $agent
