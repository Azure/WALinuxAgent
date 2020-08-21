#!/usr/bin/env bash

pylint --rcfile=3.6.pylintrc --jobs=0 azurelinuxagent tests setup.py makepkg.py &> pylint.output & PYLINT_PID=$!
nosetests -a '!requires_sudo' tests &> nosetests_no_sudo.output & NOSETESTS_PID=$!
sudo env "PATH=$PATH" nosetests -a 'requires_sudo' tests &> nosetests_sudo.output & NOSETESTS_SUDO_PID=$!

EXIT_CODE=0
wait $PYLINT_PID || EXIT_CODE=$(($EXIT_CODE || $?))
wait $NOSETESTS_PID || EXIT_CODE=$(($EXIT_CODE || $?))
wait $NOSETESTS_SUDO_PID || EXIT_CODE=$(($EXIT_CODE || $?))

echo "pylint output:"
cat pylint.output

echo
echo "nosetests -a '!requires_sudo' output:"
cat nosetests_no_sudo.output

echo
echo "nosetests -a 'requires_sudo' output:"
cat nosetests_sudo.output

exit "$EXIT_CODE"