#!/usr/bin/env bash

set -u

pylint $PYLINTOPTS --jobs=0 $PYLINTFILES &> pylint.output & PYLINT_PID=$!
nosetests -a '!requires_sudo' tests &> nosetests_no_sudo.output & NOSETESTS_PID=$!
sudo env "PATH=$PATH" nosetests -a 'requires_sudo' tests &> nosetests_sudo.output & NOSETESTS_SUDO_PID=$!

EXIT_CODE=0
wait $PYLINT_PID || EXIT_CODE=$(($EXIT_CODE || $?))
wait $NOSETESTS_PID || EXIT_CODE=$(($EXIT_CODE || $?))
wait $NOSETESTS_SUDO_PID || EXIT_CODE=$(($EXIT_CODE || $?))

echo "========================================="
echo "pylint output:"
echo "========================================="

cat pylint.output

echo
echo "========================================="
echo "nosetests -a '!requires_sudo' output:"
echo "========================================="
cat nosetests_no_sudo.output

echo
echo "========================================="
echo "nosetests -a 'requires_sudo' output:"
echo "========================================="
cat nosetests_sudo.output

exit "$EXIT_CODE"