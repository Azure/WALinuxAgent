#!/usr/bin/env bash

set -u

EXIT_CODE=0

echo
echo "========================================="
echo "nosetests -a '!requires_sudo' output"
echo "========================================="
nosetests -a '!requires_sudo' tests --with-xunit --xunit-prefix-with-testsuite-name || EXIT_CODE=$(($EXIT_CODE || $?))

echo "========================================="
echo "nosetests -a 'requires_sudo' output"
echo "========================================="
#sudo env "PATH=$PATH" nosetests -a 'requires_sudo' tests || EXIT_CODE=$(($EXIT_CODE || $?)) --with-xunit

exit "$EXIT_CODE"
