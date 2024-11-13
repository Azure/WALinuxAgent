#!/usr/bin/env bash

set -u

EXIT_CODE=0

echo "========================================="
echo "****   pytest *** non-sudo tests     ****"
echo "========================================="
pytest --verbose --config-file ci/pytest.ini --ignore-glob '*/test_cgroupconfigurator_sudo.py' tests || EXIT_CODE=$(($EXIT_CODE || $?))
echo EXIT_CODE pytests non-sudo = $EXIT_CODE

echo "========================================="
echo "****     pytest *** sudo tests       ****"
echo "========================================="
sudo env "PATH=$PATH" pytest --verbose --config-file ci/pytest.ini tests/ga/test_cgroupconfigurator_sudo.py || EXIT_CODE=$(($EXIT_CODE || $?))
echo EXIT_CODE pytests sudo = $EXIT_CODE

exit "$EXIT_CODE"
