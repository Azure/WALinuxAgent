#!/usr/bin/env bash
#
# Moves the relevant logs to the staging directory
#
set -euxo pipefail

#
# The execute_test.sh script gives ownership of the log directory to the 'waagent' user in
# the Docker container; re-take ownership
#
sudo find "$LOGS_DIRECTORY" -exec chown "$USER" {} \;

#
# Move the logs for failed tests to a temporary location
#
mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/tmp
for log in $(grep -l MARKER-LOG-WITH-ERRORS "$LOGS_DIRECTORY"/*.log); do
  mv "$log" "$BUILD_ARTIFACTSTAGINGDIRECTORY"/tmp
done

#
# Move the environment logs to "environment_logs"
#
if ls "$LOGS_DIRECTORY"/env-*.log > /dev/null 2>&1; then
  mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/environment_logs
  mv "$LOGS_DIRECTORY"/env-*.log "$BUILD_ARTIFACTSTAGINGDIRECTORY"/environment_logs
fi

#
# Move the rest of the logs to "test_logs"
#
if ls "$LOGS_DIRECTORY"/*.log > /dev/null 2>&1; then
  mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/test_logs
  mv "$LOGS_DIRECTORY"/*.log "$BUILD_ARTIFACTSTAGINGDIRECTORY"/test_logs
fi

#
# Move the logs for failed tests to the main directory
#
if ls "$BUILD_ARTIFACTSTAGINGDIRECTORY"/tmp/*.log > /dev/null 2>&1; then
  mv "$BUILD_ARTIFACTSTAGINGDIRECTORY"/tmp/*.log "$BUILD_ARTIFACTSTAGINGDIRECTORY"
fi
rmdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/tmp

#
# Move the logs collected from the test VMs to vm_logs
#
if ls "$LOGS_DIRECTORY"/*.tgz > /dev/null 2>&1; then
  mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/vm_logs
  mv "$LOGS_DIRECTORY"/*.tgz "$BUILD_ARTIFACTSTAGINGDIRECTORY"/vm_logs
fi

#
# Move the main LISA log and the JUnit report to "runbook_logs"
#
# Note that files created by LISA are under .../lisa/<date>/<unique_name>"
#
mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/runbook_logs
mv "$LOGS_DIRECTORY"/lisa/*/*/lisa-*.log "$BUILD_ARTIFACTSTAGINGDIRECTORY"/runbook_logs
mv "$LOGS_DIRECTORY"/lisa/*/*/agent.junit.xml "$BUILD_ARTIFACTSTAGINGDIRECTORY"/runbook_logs

#
# Move the rest of the LISA logs to "lisa_logs"
#
echo "COLLECT_LISA_LOGS=$COLLECT_LISA_LOGS"
if [[ $COLLECT_LISA_LOGS == 'true' ]]; then
  mkdir "$BUILD_ARTIFACTSTAGINGDIRECTORY"/lisa_logs
  mv "$LOGS_DIRECTORY"/lisa/*/*/* "$BUILD_ARTIFACTSTAGINGDIRECTORY"/lisa_logs
fi

