#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 || ! "$1" =~ ^2\.6|3\.4$ ]]; then
  echo "Usage: execute_tests.sh 2.6|3.4"
  exit 1
fi

EXIT_CODE=0
PYTHON_VERSION=$1
CONTAINER_IMAGE="waagenttests.azurecr.io/python$PYTHON_VERSION"
CONTAINER_LOGS_DIRECTORY="/home/waagent/logs"
CONTAINER_SOURCES_DIRECTORY="/home/waagent/WALinuxAgent"
NOSETESTS_OPTIONS="--verbose --with-xunit"

#
# Give ownership of the logs directory to 'waagent' (UID 1001)
#
sudo chown 1001 "$LOGS_DIRECTORY"

#
# Give the current user access to the Docker daemon
#
sudo usermod -aG docker $USER
newgrp docker < /dev/null

#
# Pull the container image and execute the tests
#
az acr login --name waagenttests --username "$CR_USER" --password "$CR_SECRET"

docker pull "$CONTAINER_IMAGE"

printf "\n***************************************** Running tests for Python $PYTHON_VERSION *****************************************\n\n"

TEST_SUITE_OPTIONS="--xunit-testsuite-name='Python $PYTHON_VERSION' --xunit-file=$CONTAINER_LOGS_DIRECTORY/waagent-$PYTHON_VERSION.junit.xml"

set -x
docker run --rm \
    --volume "$BUILD_SOURCESDIRECTORY":"$CONTAINER_SOURCES_DIRECTORY" \
    --volume "$LOGS_DIRECTORY":"$CONTAINER_LOGS_DIRECTORY" \
    "$CONTAINER_IMAGE" \
    bash --login -c "nosetests $NOSETESTS_OPTIONS $TEST_SUITE_OPTIONS --ignore-files test_cgroupconfigurator_sudo.py $CONTAINER_SOURCES_DIRECTORY/tests" \
|| EXIT_CODE=$(($EXIT_CODE || $?))
set +x

printf "\n************************************** Running tests for Python $PYTHON_VERSION [sudo] **************************************\n\n"

TEST_SUITE_OPTIONS="--xunit-testsuite-name='Python $PYTHON_VERSION [sudo]' --xunit-file=$CONTAINER_LOGS_DIRECTORY/waagent-sudo-$PYTHON_VERSION.junit.xml"

set -x
docker run --rm \
    --user root \
    --volume "$BUILD_SOURCESDIRECTORY":"$CONTAINER_SOURCES_DIRECTORY" \
    --volume "$LOGS_DIRECTORY":"$CONTAINER_LOGS_DIRECTORY" \
    "$CONTAINER_IMAGE" \
    bash --login -c "nosetests $NOSETESTS_OPTIONS $TEST_SUITE_OPTIONS $CONTAINER_SOURCES_DIRECTORY/tests/ga/test_cgroupconfigurator_sudo.py"\
|| EXIT_CODE=$(($EXIT_CODE || $?))
set +x

exit "$EXIT_CODE"
