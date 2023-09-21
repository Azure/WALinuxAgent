#!/usr/bin/env bash
#
# Deletes the resource groups created by the combinator. Finds resource group names from txt file written on machine by
# combinator.
#
set -euxo pipefail

#
# The execute_test.sh script gives ownership of the log directory to the 'waagent' user in
# the Docker container; re-take ownership
#
sudo find "$BUILD_SOURCESDIRECTORY" -exec chown "$USER" {} \;

az login --service-principal --username "$AZURE_CLIENT_ID" --password "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID"
az account set --subscription "$SUBSCRIPTION_ID"

resource_group_file="$BUILD_SOURCESDIRECTORY"/resource_groups_to_delete.txt
cat $resource_group_file|while read line; do
  az group delete --name "$line" --yes --no-wait
done