#!/usr/bin/env bash
#            1          2           3
# Usage: <username>   <IP>  <Artifact Directory>

# https://linuxcommand.org/lc3_man_pages/seth.html
# -e  Exit immediately if a command exits with a non-zero status.
# -u  Treat unset variables as an error when substituting.
# -x  Print commands and their arguments as they are executed.
# -o pipefail     the return value of a pipeline is the status of the last command to exit with a non-zero status,
#                 or zero if no command exited with a non-zero status
set -euxo pipefail

ssh -o "StrictHostKeyChecking no" "$1"@"$2" "sudo tar --exclude='journal/*' --exclude='omsbundle' --exclude='omsagent' --exclude='mdsd' --exclude='scx*' --exclude='*.so' --exclude='*__LinuxDiagnostic__*' --exclude='*.zip' --exclude='*.deb' --exclude='*.rpm' -czf logs-$2.tgz /var/log /var/lib/waagent/ /etc/waagent.conf"

# Create directory if doesn't exist
mkdir -p "$3"
scp -o "StrictHostKeyChecking no" "$1@$2:logs-$2.tgz" "$3/logs-$2.tgz"