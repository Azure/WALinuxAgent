#!/usr/bin/env bash

set -euxo pipefail

ls -l ~/.ssh
find ~ -name id_rsa
find $BUILD_SOURCESDIRECTORY -name id_rsa

export PYTHONPATH=$BUILD_SOURCESDIRECTORY

cd $BUILD_SOURCESDIRECTORY/lisa

./lisa.sh --runbook $BUILD_SOURCESDIRECTORY/tests_e2e/lisa/runbook/azure.yml \
  --log_path $HOME/tmp \
  --working_path $HOME/tmp \
  -v subscription_id:$SUBID \
  -v identity_file:$SSHKEY_SECUREFILEPATH

