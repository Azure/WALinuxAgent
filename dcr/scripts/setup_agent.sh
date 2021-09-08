#!/usr/bin/env bash

set -euxo pipefail

#           $1          $2          $3            $4              $5            $6                    $7
# Usage:  AgentVersion

# Copy agent zip file to /var/lib/waagent to force it to autoupdate
[ -z "$1" ] && version="9.9.9.9" || version=$1

if systemctl status walinuxagent;then
    agent="walinuxagent"
else
    agent="waagent"
fi

# Required for Agent-BVT test
echo "$version" > /etc/agent-release
sudo systemctl stop $agent

# We need to force the agent to AutoUpdate to enable our testing
sed -i 's/AutoUpdate.Enabled=n/AutoUpdate.Enabled=y/g' /etc/waagent.conf
# Move the older agent log file to ensure we have a clean slate when testing agent logs
mv /var/log/waagent.log /var/log/waagent.old.log

sudo cp -r ./dcr/*-$version /var/lib/waagent
sudo systemctl daemon-reload && sudo systemctl start $agent

sudo systemctl status $agent --no-pager
waagent --version