#!/usr/bin/env bash

set -euxo pipefail


#           $1          $2          $3            $4              $5            $6                    $7
# Usage:  Artifact Dir

apt-get update
apt-get install python3-pip -y
pip3 install -U pytest

pytest agent-bvt/ --doctest-modules --junitxml="$1/test-results.xml"