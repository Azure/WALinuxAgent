#!/usr/bin/env bash

set -euxo pipefail

echo "Hostname: $(hostname)"
echo "\$USER: $USER"

#
# UID of 'waagent' in the Docker container
#
WAAGENT_UID=1000

#
# Set the correct mode and owner for the private SSH key and generate the public key.
#
cd "$AGENT_TEMPDIRECTORY"
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
LOGS_DIRECTORY="$AGENT_TEMPDIRECTORY/logs"
echo "##vso[task.setvariable variable=logs_directory]$LOGS_DIRECTORY"
mkdir "$LOGS_DIRECTORY"
sudo chown "$WAAGENT_UID" "$LOGS_DIRECTORY"

#
# Give the current user access to the Docker daemon
#
sudo usermod -aG docker $USER
newgrp docker < /dev/null

#
# Pull the container image used to execute the tests
#
az acr login --name waagenttests --username "$CR_USER" --password "$CR_SECRET"

docker pull waagenttests.azurecr.io/waagenttests:latest

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

#
# Get the external IP address of the VM.
#
IP_ADDRESS=$(curl -4 ifconfig.io/ip)

# certificate location in the container
AZURE_CLIENT_CERTIFICATE_PATH="/home/waagent/app/cert.pem"

docker run --rm \
    --volume "$BUILD_SOURCESDIRECTORY:/home/waagent/WALinuxAgent" \
    --volume "$AGENT_TEMPDIRECTORY"/ssh:/home/waagent/.ssh \
    --volume "$AGENT_TEMPDIRECTORY"/app:/home/waagent/app \
    --volume "$LOGS_DIRECTORY":/home/waagent/logs \
    --env AZURE_CLIENT_ID \
    --env AZURE_TENANT_ID \
    --env AZURE_CLIENT_CERTIFICATE_PATH=$AZURE_CLIENT_CERTIFICATE_PATH \
    waagenttests.azurecr.io/waagenttests \
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
          -v allow_ssh:\"$IP_ADDRESS\" \
          $TEST_SUITES"
