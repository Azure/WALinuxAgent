#!/usr/bin/env bash
#            1          2           3
# Usage: <username>   <IP>  <Artifact Directory>
set -euxo pipefail

ssh -o "StrictHostKeyChecking no" "$1"@"$2" "sudo tar --exclude='journal/*' --exclude='*.zip' -czf logs-$2.tgz /var/log /var/lib/waagent/ /root /etc/waagent.conf"

# Create directory if doesn't exist
mkdir -p "$3"
scp -o "StrictHostKeyChecking no" "$1@$2:logs-$2.tgz" "$3/logs-$2.tgz"