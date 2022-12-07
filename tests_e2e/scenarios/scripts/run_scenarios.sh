#!/usr/bin/env bash

set -euxo pipefail

cd "$HOME"

# The private ssh key is shared from the container host as $HOME/id_rsa; copy it to
# HOME/.ssh, set the correct mode and generate the public key.
mkdir "$HOME/.ssh"
cp "$HOME/id_rsa" "$HOME/.ssh"
chmod 700 "$HOME/.ssh/id_rsa"
ssh-keygen -y -f "$HOME/.ssh/id_rsa" > "$HOME/.ssh/id_rsa.pub"

lisa \
  --runbook "$HOME/WALinuxAgent/tests_e2e/scenarios/runbooks/daily.yml" \
  --log_path "$HOME/logs" \
  --working_path "$HOME/logs" \
  -v subscription_id:"$SUBSCRIPTION_ID" \
  -v identity_file:"$HOME/.ssh/id_rsa.pub"
