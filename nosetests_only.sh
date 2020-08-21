#!/usr/bin/env bash

echo "========================================="
echo "nosetests -a 'requires_sudo' output"
echo "========================================="
sudo env "PATH=$PATH" nosetests -a 'requires_sudo' tests

echo
echo "========================================="
echo "nosetests -a '!requires_sudo' output"
echo "========================================="
nosetests -a '!requires_sudo' tests