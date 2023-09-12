#!/usr/bin/env bash

set -euxo pipefail

#
# UID of 'waagent' in the Docker container
#
WAAGENT_UID=1000

#
# Set the correct mode and owner for the private SSH key and generate the public key.
#
cd "$HOME"
mkdir ssh
cp "$DOWNLOADSSHKEY_SECUREFILEPATH" ssh
chmod 700 ssh/id_rsa
ssh-keygen -y -f ssh/id_rsa > ssh/id_rsa.pub
sudo find ssh -exec chown "$WAAGENT_UID" {} \;

#
# Allow write access to the sources directory. This is needed because building the agent package (within the Docker
# container) writes the egg info to that directory.
#
chmod a+w "$BUILD_SOURCESDIRECTORY"

#
# Create the directory where the Docker container will create the test logs and give ownership to 'waagent'
#
LOGS_DIRECTORY="$HOME/logs"
echo "##vso[task.setvariable variable=logs_directory]$LOGS_DIRECTORY"
mkdir "$LOGS_DIRECTORY"
sudo chown "$WAAGENT_UID" "$LOGS_DIRECTORY"

#
# Pull the container image used to execute the tests
#
az acr login --name waagenttests --username "$CR_USER" --password "$CR_SECRET"

docker pull waagenttests.azurecr.io/waagenttests-mariner:version1.0

# Azure Pipelines does not allow an empty string as the value for a pipeline parameter; instead we use "-" to indicate
# an empty value. Change "-" to "" for the variables that capture the parameter values.
if [[ $TEST_SUITES == "-" ]]; then
    TEST_SUITES=""  # Don't set the test_suites variable
else
    TEST_SUITES="-v test_suites:\"$TEST_SUITES\""
fi
if [[ $IMAGE == "-" ]]; then
    IMAGE=""
fi
if [[ $LOCATION == "-" ]]; then
    LOCATION=""
fi
if [[ $VM_SIZE == "-" ]]; then
    VM_SIZE=""
fi

docker run --rm \
    --volume "$BUILD_SOURCESDIRECTORY:/home/waagent/WALinuxAgent" \
    --volume "$HOME"/ssh:/home/waagent/.ssh \
    --volume "$LOGS_DIRECTORY":/home/waagent/logs \
    --env AZURE_CLIENT_ID \
    --env AZURE_CLIENT_SECRET \
    --env AZURE_TENANT_ID \
    waagenttests.azurecr.io/waagenttests-mariner:version1.0 \
    bash --login -c \
      "lisa \
          --runbook \$HOME/WALinuxAgent/tests_e2e/orchestrator/runbook.yml \
          --log_path \$HOME/logs/lisa \
          --working_path \$HOME/tmp \
          -v cloud:$CLOUD \
          -v subscription_id:$SUBSCRIPTION_ID \
          -v identity_file:\$HOME/.ssh/id_rsa \
          -v log_path:\$HOME/logs \
          -v collect_logs:\"$COLLECT_LOGS\" \
          -v keep_environment:\"$KEEP_ENVIRONMENT\" \
          -v image:\"$IMAGE\" \
          -v location:\"$LOCATION\" \
          -v vm_size:\"$VM_SIZE\" \
          $TEST_SUITES"
