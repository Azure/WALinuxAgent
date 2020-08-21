#!/usr/bin/env bash


echo "nosetests -a 'requires_sudo' output"
sudo env "PATH=$PATH" nosetests -a 'requires_sudo' tests

echo
echo "nosetests -a '!requires_sudo' output"
nosetests -a '!requires_sudo' tests