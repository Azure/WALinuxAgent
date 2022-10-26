#!/usr/bin/env bash

set -euxo pipefail

#
# Install LISA (see https://mslisa.readthedocs.io/en/main/installation_linux.html)
#

# Install LISA dependencies
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

#
# Install test dependencies
#
# NOTE: Need to review the test dependencies, they require module versions greater than the same modules used by LISA
#       and the version update adds a significant build delay. For the moment, just add the modules not included
#       already by LISA
#
# ===== DISABLED =====
## (make a copy of the requirements file removing comments since poetry-add-requirements does not support them)
##
#pip install poetry-add-requirements.txt
#sed '/^#/d' $BUILD_SOURCESDIRECTORY/tests_e2e/requirements.txt > WALinuxAgent-requirements.txt
#poetry-add-requirements.txt WALinuxAgent-requirements.txt
# ===== END DISABLED =====

poetry add msrestazure
poetry add python-dotenv

