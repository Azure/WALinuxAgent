#!/usr/bin/env bash

# https://linuxcommand.org/lc3_man_pages/seth.html
# -e  Exit immediately if a command exits with a non-zero status.
# -u  Treat unset variables as an error when substituting.
# -x  Print commands and their arguments as they are executed.
# -o pipefail     the return value of a pipeline is the status of the last command to exit with a non-zero status,
#                 or zero if no command exited with a non-zero status
set -euxo pipefail

#           $1          $2          $3            $4              $5            $6                    $7
# Usage:  AgentVersion

# Copy agent zip file to /var/lib/waagent to force it to auto-update
[ -z "$1" ] && version="9.9.9.9" || version=$1

if systemctl status walinuxagent;then
    agent="walinuxagent"
else
    agent="waagent"
fi

sudo systemctl stop $agent

# We need to force the agent to AutoUpdate to enable our testing
sed -i 's/AutoUpdate.Enabled=n/AutoUpdate.Enabled=y/g' /etc/waagent.conf
# Move the older agent log file to ensure we have a clean slate when testing agent logs
mv /var/log/waagent.log /var/log/waagent.old.log

sudo cp -r ./dcr/*-$version /var/lib/waagent
sudo systemctl daemon-reload && sudo systemctl start $agent

sudo systemctl status $agent --no-pager
waagent --version