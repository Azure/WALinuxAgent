#!/usr/bin/env bash

set -euxo pipefail

#
# See https://mslisa.readthedocs.io/en/main/installation_linux.html
#

# Install dependencies
sudo apt install -y git gcc libgirepository1.0-dev libcairo2-dev qemu-utils libvirt-dev python3-venv

# Install Poetry
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/install-poetry.py | python3 -
export PATH="$HOME/.local/bin:$PATH"
echo "##vso[task.prependpath]$HOME/.local/bin"

# Install LISA
cd $BUILD_SOURCESDIRECTORY
git clone https://github.com/microsoft/lisa.git
cd lisa
make setup

# Verify LISA installation
./lisa.sh




