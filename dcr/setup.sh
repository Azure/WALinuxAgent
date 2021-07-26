#!/usr/bin/env bash
#           $1          $2          $3            $4              $5            $6                    $7
# Usage: <Agent Code Dir>

#"Install latest WALinuxAgent from source"

cd "$1" || exit
version=$(grep '^AGENT_VERSION' azurelinuxagent/common/version.py |  sed "s/.*'\([^']\+\)'.*/\1/")
sudo ./makepkg.py
sudo cp ./eggs/WALinuxAgent-$version.zip /var/lib/waagent/
sudo systemctl stop walinuxagent
sudo unzip /var/lib/waagent/WALinuxAgent-$version.zip -d /var/lib/waagent/WALinuxAgent-$version
sudo systemctl daemon-reload && sudo systemctl start walinuxagent

# Required for Agent-BVT test
grep '^AGENT_VERSION' azurelinuxagent/common/version.py > /etc/agent-release