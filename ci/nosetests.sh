#!/usr/bin/env bash

set -u

EXIT_CODE=0

echo "========================================="
echo "nosetests -a '!requires_sudo' output"
echo "========================================="
nosetests -a '!requires_sudo' tests $(echo "${NOSEOPTS/__uuid__/$(uuidgen)}") || EXIT_CODE=$(($EXIT_CODE || $?))
echo EXIT_CODE nosetests = $EXIT_CODE
sudo mv .coverage coverage.$(uuidgen).no_requires_sudo.data

echo "========================================="
echo "nosetests -a 'requires_sudo' output"
echo "========================================="
sudo env "PATH=$PATH" nosetests -a 'requires_sudo' tests $(echo "${NOSEOPTS/__uuid__/$(uuidgen)}") || EXIT_CODE=$(($EXIT_CODE || $?))
echo EXIT_CODE sudo nosetest = $EXIT_CODE
sudo mv .coverage coverage.$(uuidgen).requires_sudo.data

exit "$EXIT_CODE"