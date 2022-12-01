#!/usr/bin/env bash

set -euxo pipefail

az login --service-principal --username "$AZURE_CLIENT_ID" --password "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" > /dev/null

az acr login --name waagenttests

docker pull waagenttests.azurecr.io/waagenttests:latest

# Logs will be placed in the staging directory. Make waagent (UID 1000 in the container) the owner so that it can write to that location
sudo chown 1000 "$BUILD_ARTIFACTSTAGINGDIRECTORY"

docker run --rm \
      --volume "$BUILD_SOURCESDIRECTORY:/home/waagent/WALinuxAgent" \
      --volume "$DOWNLOADSSHKEY_SECUREFILEPATH:/home/waagent/id_rsa" \
      --volume "$BUILD_ARTIFACTSTAGINGDIRECTORY:/home/waagent/logs" \
      --env SUBSCRIPTION_ID \
      --env AZURE_CLIENT_ID \
      --env AZURE_CLIENT_SECRET \
      --env AZURE_TENANT_ID \
      waagenttests.azurecr.io/waagenttests \
      bash --login -c '$HOME/WALinuxAgent/tests_e2e/scripts/execute_tests.sh'

# Retake ownership of the staging directory
sudo find "$BUILD_ARTIFACTSTAGINGDIRECTORY" -exec chown "$USER" {} \;

# LISA organizes its logs in a tree similar to
#
#    .../20221130
#    .../20221130/20221130-160013-749
#    .../20221130/20221130-160013-749/environments
#    .../20221130/20221130-160013-749/lisa-20221130-160013-749.log
#    .../20221130/20221130-160013-749/lisa.junit.xml
#    etc
#
# Remove the first 2 levels of the tree (which indicate the time of the test run) to make navigation
# in the Azure Pipelines UI easier.
#
mv "$BUILD_ARTIFACTSTAGINGDIRECTORY"/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]/*/* "$BUILD_ARTIFACTSTAGINGDIRECTORY"
rm -r "$BUILD_ARTIFACTSTAGINGDIRECTORY"/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]
