#!/usr/bin/env bash

set -euxo pipefail

#apt-get update
#apt-get install python3-pip -y

curl "https://bootstrap.pypa.io/get-pip.py" -o "install-pip3-ubuntu.py"
python3 install-pip3-ubuntu.py
