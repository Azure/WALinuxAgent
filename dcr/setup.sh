#!/usr/bin/env bash

set -euxo pipefail

#           $1          $2          $3            $4              $5            $6                    $7
# Usage:  AgentVersion

# Copy agent zip file to /var/lib/waagent to force it to autoupdate
echo "PWD: $(pwd)"
[  -z "$1" ] && version="9.9.9.9" || version=$1

# Required for Agent-BVT test
echo "$version" > /etc/agent-release

sudo systemctl stop walinuxagent
sudo cp ./*-$version.zip /var/lib/waagent
sudo unzip /var/lib/waagent/WALinuxAgent-$version.zip -d /var/lib/waagent/WALinuxAgent-$version
sudo systemctl daemon-reload && sudo systemctl start walinuxagent
waagent --version