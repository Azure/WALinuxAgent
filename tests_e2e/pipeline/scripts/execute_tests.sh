#!/usr/bin/env bash

set -euxo pipefail

# Pull the container image used to execute the tests
az login --service-principal --username "$AZURE_CLIENT_ID" --password "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" > /dev/null

az acr login --name waagenttests

docker pull waagenttests.azurecr.io/waagenttests:latest

# Building the agent package writes the egg info to the source code directory, and test write their logs to the staging directory.
# Make waagent (UID 1000 in the container) the owner of both locations, so that it can write to them.
sudo chown 1000 "$BUILD_SOURCESDIRECTORY"
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
      bash --login -c '$HOME/WALinuxAgent/tests_e2e/orchestrator/scripts/run-scenarios'

# Retake ownership of the source and staging directory (note that the former does not need to be done recursively)
sudo chown "$USER" "$BUILD_SOURCESDIRECTORY"
sudo find "$BUILD_ARTIFACTSTAGINGDIRECTORY" -exec chown "$USER" {} \;

# The LISA run will produce a tree similar to
#
#    $BUILD_ARTIFACTSTAGINGDIRECTORY/lisa/20221130
#    $BUILD_ARTIFACTSTAGINGDIRECTORY/lisa/20221130/20221130-160013-749
#    $BUILD_ARTIFACTSTAGINGDIRECTORY/lisa/20221130/20221130-160013-749/environments
#    $BUILD_ARTIFACTSTAGINGDIRECTORY/lisa/20221130/20221130-160013-749/lisa-20221130-160013-749.log
#    $BUILD_ARTIFACTSTAGINGDIRECTORY/lisa/20221130/20221130-160013-749/lisa.junit.xml
#    etc
#
# Remove the 2 levels of the tree that indicate the time of the test run to make navigation
# in the Azure Pipelines UI easier.
#
mv "$BUILD_ARTIFACTSTAGINGDIRECTORY"/lisa/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]/*/* "$BUILD_ARTIFACTSTAGINGDIRECTORY"/lisa
rm -r "$BUILD_ARTIFACTSTAGINGDIRECTORY"/lisa/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]
