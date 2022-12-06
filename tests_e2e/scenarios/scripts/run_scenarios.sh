#!/usr/bin/env bash

set -euxo pipefail

# The private ssh key is shared from the container host as $HOME/id_rsa; copy it to
# HOME/.ssh, set the correct mode and generate the public key.
mkdir "$HOME/.ssh"
cp "$HOME/id_rsa" "$HOME/.ssh"
chmod 700 "$HOME/.ssh/id_rsa"
ssh-keygen -y -f "$HOME/.ssh/id_rsa" > "$HOME/.ssh/id_rsa.pub"

# Execute the tests, this needs to be done from the LISA root directory
cd "$HOME/lisa"

./lisa.sh \
  --runbook "$HOME/WALinuxAgent/tests_e2e/scenarios/runbook/scenarios.yml" \
  --log_path "$HOME/logs" \
  --working_path "$HOME/logs" \
  -v subscription_id:"$SUBSCRIPTION_ID" \
  -v identity_file:"$HOME/.ssh/id_rsa.pub"
