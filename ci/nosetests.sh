#!/usr/bin/env bash

set -u

EXIT_CODE=0

echo "========================================="
echo "****     nosetests non-sudo tests    ****"
echo "========================================="
nosetests --ignore-files test_cgroupconfigurator_sudo.py --ignore-files test_signature_validation_sudo.py tests $NOSEOPTS || EXIT_CODE=$(($EXIT_CODE || $?))
echo EXIT_CODE no_sudo nosetests = $EXIT_CODE

[[ -f .coverage ]] && \
    sudo mv .coverage coverage.$(uuidgen).no_sudo.data

echo "========================================="
echo "****      nosetests sudo tests       ****"
echo "========================================="
sudo env "PATH=$PATH" nosetests tests/ga/test_cgroupconfigurator_sudo.py tests/ga/test_signature_validation_sudo.py $NOSEOPTS || EXIT_CODE=$(($EXIT_CODE || $?))
echo EXIT_CODE with_sudo nosetests = $EXIT_CODE

[[ -f .coverage ]] && \
    sudo mv .coverage coverage.$(uuidgen).with_sudo.data

exit "$EXIT_CODE"
