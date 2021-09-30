#!/usr/bin/env bash
#            1          2           3
# Usage: <username>    <IP>   <Artifact Directory>
set -euxo pipefail

ssh -o "StrictHostKeyChecking no" "$1"@"$2" "sudo tar cfz logs.tgz /var/log /var/lib/waagent/ /root"

# Create directory if doesn't exist
mkdir -p "$3"
scp -o "StrictHostKeyChecking no" "$1"@"$2":logs.tgz "$3"/logs.tgz