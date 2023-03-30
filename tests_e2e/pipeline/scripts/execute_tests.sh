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
mkdir "$LOGS_DIRECTORY"
sudo chown "$WAAGENT_UID" "$LOGS_DIRECTORY"

#
# Pull the container image used to execute the tests
#
az acr login --name waagenttests --username "$CR_USER" --password "$CR_SECRET"

docker pull waagenttests.azurecr.io/waagenttests:latest

# Azure Pipelines does not allow an empty string as the value for a pipeline parameter; instead we use "-" to indicate
# an empty value. Change "-" to "" for the variables that capture the parameter values.
if [[ $IMAGE == "-" ]]; then
    IMAGE=""
fi
if [[ $LOCATION == "-" ]]; then
    LOCATION=""
fi
if [[ $VM_SIZE == "-" ]]; then
    VM_SIZE=""
fi

# A test failure will cause automation to exit with an error code and we don't want this script to stop so we force the command
# to succeed and capture the exit code to return it at the end of the script.
echo "exit 0" > /tmp/exit.sh

docker run --rm \
    --volume "$BUILD_SOURCESDIRECTORY:/home/waagent/WALinuxAgent" \
    --volume "$HOME"/ssh:/home/waagent/.ssh \
    --volume "$LOGS_DIRECTORY":/home/waagent/logs \
    --env AZURE_CLIENT_ID \
    --env AZURE_CLIENT_SECRET \
    --env AZURE_TENANT_ID \
    waagenttests.azurecr.io/waagenttests \
    bash --login -c \
      "lisa \
          --runbook \$HOME/WALinuxAgent/tests_e2e/orchestrator/runbook.yml \
          --log_path \$HOME/logs/lisa \
          --working_path \$HOME/tmp \
          -v cloud:$CLOUD \
          -v subscription_id:$SUBSCRIPTION_ID \
          -v identity_file:\$HOME/.ssh/id_rsa \
          -v test_suites:\"$TEST_SUITES\" \
          -v log_path:\$HOME/logs \
          -v collect_logs:\"$COLLECT_LOGS\" \
          -v keep_environment:\"$KEEP_ENVIRONMENT\" \
          -v image:\"$IMAGE\" \
          -v location:\"$LOCATION\" \
          -v vm_size:\"$VM_SIZE\"" \
|| echo "exit $?" > /tmp/exit.sh

#
# Re-take ownership of the logs directory
#
sudo find "$LOGS_DIRECTORY" -exec chown "$USER" {} \;

#
# Move the relevant logs to the staging directory
#
# Move the logs for failed tests to a temporary location
mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/tmp
for log in $(grep -l MARKER-LOG-WITH-ERRORS "$LOGS_DIRECTORY"/*.log); do
  mv "$log" "$BUILD_ARTIFACTSTAGINGDIRECTORY"/tmp
done
# Move the environment logs to "environment_logs"
if ls "$LOGS_DIRECTORY"/env-*.log > /dev/null 2>&1; then
  mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/environment_logs
  mv "$LOGS_DIRECTORY"/env-*.log "$BUILD_ARTIFACTSTAGINGDIRECTORY"/environment_logs
fi
# Move the rest of the logs to "test_logs"
if ls "$LOGS_DIRECTORY"/*.log > /dev/null 2>&1; then
  mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/test_logs
  mv "$LOGS_DIRECTORY"/*.log "$BUILD_ARTIFACTSTAGINGDIRECTORY"/test_logs
fi
# Move the logs for failed tests to the main directory
if ls "$BUILD_ARTIFACTSTAGINGDIRECTORY"/tmp/*.log > /dev/null 2>&1; then
  mv "$BUILD_ARTIFACTSTAGINGDIRECTORY"/tmp/*.log "$BUILD_ARTIFACTSTAGINGDIRECTORY"
fi
rmdir tmp
# Move the logs collected from the test VMs to vm_logs
if ls "$LOGS_DIRECTORY"/*.tgz > /dev/null 2>&1; then
  mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/vm_logs
  mv "$LOGS_DIRECTORY"/*.tgz "$BUILD_ARTIFACTSTAGINGDIRECTORY"/vm_logs
fi
# Files created by LISA are under .../lisa/<date>/<unique_name>"
mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/runbook_logs
mv "$LOGS_DIRECTORY"/lisa/*/*/lisa-*.log "$BUILD_ARTIFACTSTAGINGDIRECTORY"/runbook_logs
mv "$LOGS_DIRECTORY"/lisa/*/*/agent.junit.xml "$BUILD_ARTIFACTSTAGINGDIRECTORY"/runbook_logs

cat /tmp/exit.sh
bash /tmp/exit.sh
