#!/usr/bin/env bash

set -u

EXIT_CODE=0

echo "========================================="
echo "****   pytest *** non-sudo tests     ****"
echo "========================================="
pytest --ignore-glob '*/test_cgroupconfigurator_sudo.py' --verbose tests || EXIT_CODE=$(($EXIT_CODE || $?))
echo EXIT_CODE pytests non-sudo = $EXIT_CODE

echo "========================================="
echo "****     pytest *** sudo tests       ****"
echo "========================================="
sudo env "PATH=$PATH" pytest --verbose tests/ga/test_cgroupconfigurator_sudo.py || EXIT_CODE=$(($EXIT_CODE || $?))
echo EXIT_CODE pytests sudo = $EXIT_CODE

exit "$EXIT_CODE"
