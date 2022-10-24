#!/usr/bin/env bash

set -euxo pipefail

export PYTHONPATH=$BUILD_SOURCESDIRECTORY

cd $BUILD_SOURCESDIRECTORY/lisa

# LISA needs both the public and private keys; generate the former
chmod 700 $SSHKEY_SECUREFILEPATH
ssh-keygen -y -f $SSHKEY_SECUREFILEPATH > "$SSHKEY_SECUREFILEPATH".pub

./lisa.sh --runbook $BUILD_SOURCESDIRECTORY/tests_e2e/lisa/runbook/azure.yml \
  --log_path $HOME/tmp \
  --working_path $HOME/tmp \
  -v subscription_id:$SUBID \
  -v identity_file:$SSHKEY_SECUREFILEPATH

