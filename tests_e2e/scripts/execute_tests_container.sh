#!/usr/bin/env bash

set -euxo pipefail

az login --service-principal --username "$AZURE_CLIENT_ID" --password "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" > /dev/null

az acr login --name waagenttests

docker pull waagenttests.azurecr.io/waagenttests:latest

# Logs will be placed in this location. Make waagent (UID 1000 in the container) the owner.
mkdir "$HOME/logs"
sudo chown 1000 "$HOME/logs"

docker run --rm \
      --volume "$BUILD_SOURCESDIRECTORY:/home/waagent/WALinuxAgent" \
      --volume "$DOWNLOADSSHKEY_SECUREFILEPATH:/home/waagent/id_rsa" \
      --volume "$HOME/logs:/home/waagent/logs" \
      --env SUBSCRIPTION_ID \
      --env AZURE_CLIENT_ID \
      --env AZURE_CLIENT_SECRET \
      --env AZURE_TENANT_ID \
      waagenttests.azurecr.io/waagenttests \
      bash --login -c '~/WALinuxAgent/tests_e2e/scripts/execute_tests.sh'

ls -lR "$HOME/logs"

