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
#sudo cp ./dcr/*-$version.zip /var/lib/waagent
#sudo apt-get update && sudo apt-get install zip -y
#sudo unzip /var/lib/waagent/WALinuxAgent-$version.zip -d /var/lib/waagent/WALinuxAgent-$version

sudo cp -r ./dcr/*-$version /var/lib/waagent
sudo systemctl daemon-reload && sudo systemctl start $agent

#apt-get install python3-pip -y
#pip3 install -U pytest
#pip3 install junit-xml
#pip3 install distro

sudo systemctl status $agent --no-pager
waagent --version