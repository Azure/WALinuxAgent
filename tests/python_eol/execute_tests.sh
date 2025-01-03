#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: execute_tests.sh <python-version>"
  exit 1
fi
PYTHON_VERSION=$1

if [[ ! "$PYTHON_VERSION" =~ ^2\.6|3\.4$  ]]; then
  echo "Only versions 2.6 and 3.4 are supported"
fi

#
# Give ownership of the logs directory to 'waagent' (UID 1000)
#
sudo chown 1000 "$LOGS_DIRECTORY"

#
# Give the current user access to the Docker daemon
#
sudo usermod -aG docker $USER
newgrp docker < /dev/null

#
# Pull the container image and execute the tests
#
CONTAINER_IMAGE="waagenttests.azurecr.io/python$PYTHON_VERSION"
CONTAINER_LOGS_DIRECTORY="/home/waagent/logs"
CONTAINER_SOURCES_DIRECTORY="/home/waagent/WALinuxAgent"
NOSETESTS_OPTIONS="--verbose --with-xunit"


az acr login --name waagenttests --username "$CR_USER" --password "$CR_SECRET"

docker pull "$CONTAINER_IMAGE"

echo "***************************************** Running tests for Python $PYTHON_VERSION *****************************************"

TEST_SUITE_OPTIONS="--xunit-testsuite-name='Python $PYTHON_VERSION' --xunit-file=$CONTAINER_LOGS_DIRECTORY/waagent-$PYTHON_VERSION.junit.xml"

set -x
docker run --rm \
    --volume "$BUILD_SOURCESDIRECTORY":"$CONTAINER_SOURCES_DIRECTORY" \
    --volume "$LOGS_DIRECTORY":"$CONTAINER_LOGS_DIRECTORY" \
    "$CONTAINER_IMAGE" \
    bash --login -c "nosetests $NOSETESTS_OPTIONS $TEST_SUITE_OPTIONS --ignore-files test_cgroupconfigurator_sudo.py $CONTAINER_SOURCES_DIRECTORY/tests"
set +x

echo "************************************** Running tests for Python $PYTHON_VERSION [sudo] **************************************"

TEST_SUITE_OPTIONS="--xunit-testsuite-name='Python $PYTHON_VERSION [sudo]' --xunit-file=$CONTAINER_LOGS_DIRECTORY//waagent-sudo-$PYTHON_VERSION.junit.xml"

set -x
docker run --rm \
    --user root \
    --volume "$BUILD_SOURCESDIRECTORY":"$CONTAINER_SOURCES_DIRECTORY" \
    --volume "$LOGS_DIRECTORY":"$CONTAINER_LOGS_DIRECTORY" \
    "$CONTAINER_IMAGE" \
    bash --login -c "nosetests $NOSETESTS_OPTIONS $TEST_SUITE_OPTIONS $CONTAINER_SOURCES_DIRECTORY/tests/ga/test_cgroupconfigurator_sudo.py"
set +x
