#!/usr/bin/env bash

set -u

EXIT_CODE=0

echo "========================================="
echo "nosetests -a '!requires_sudo' output"
echo "========================================="
nosetests -a '!requires_sudo' tests $NOSEOPTS || EXIT_CODE=$(($EXIT_CODE || $?))
echo EXIT_CODE no_sudo nosetests = $EXIT_CODE

[[ -f .coverage ]] && \
    sudo mv .coverage coverage.$(uuidgen).no_sudo.data

echo "========================================="
echo "nosetests -a 'requires_sudo' output"
echo "========================================="
sudo env "PATH=$PATH" nosetests -a 'requires_sudo' tests $NOSEOPTS || EXIT_CODE=$(($EXIT_CODE || $?))
echo EXIT_CODE with_sudo nosetests = $EXIT_CODE

[[ -f .coverage ]] && \
    sudo mv .coverage coverage.$(uuidgen).with_sudo.data

exit "$EXIT_CODE"
