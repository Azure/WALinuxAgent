#!/usr/bin/env bash

set -euxo pipefail

cd $BUILD_SOURCESDIRECTORY/lisa

./lisa.sh


#  --runbook ../WALinuxAgent/tests-e2e/lisa/runbook/local.yml --log_path $HOME/tmp --working_path $HOME/tmp

