#!/usr/bin/env bash

set -euxo pipefail

apt-get update
apt-get install python3-pip -y
pip3 install -U pytest

pytest agent-bvt/ --doctest-modules --junitxml="$BUILD_ARTIFACTSTAGINGDIRECTORY/test-results.xml"