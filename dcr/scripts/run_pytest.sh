#!/usr/bin/env bash

set -euxo pipefail


#           $1          $2          $3            $4              $5            $6                    $7
# Usage:  Artifact Dir  PyPypath
ls -al "$2"
$2 -m pytest "$1/dcr/scenario/" --doctest-modules --junitxml="$1/test-result.xml"