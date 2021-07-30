#!/usr/bin/env bash

set -euxo pipefail

#           $1          $2          $3            $4              $5            $6                    $7
# Usage:  AgentVersion

# Copy agent zip file to /var/lib/waagent to force it to autoupdate
[ -z "$1" ] && version="9.9.9.9" || version=$1

# Required for Agent-BVT test
echo "$version" > /etc/agent-release

sudo systemctl stop walinuxagent
sudo cp ./dcr/*-$version.zip /var/lib/waagent
sudo apt-get update && sudo apt-get install zip -y
sudo unzip /var/lib/waagent/WALinuxAgent-$version.zip -d /var/lib/waagent/WALinuxAgent-$version
sudo systemctl daemon-reload && sudo systemctl start walinuxagent

sleep 10

sudo systemctl status walinuxagent --no-pager
waagent --version