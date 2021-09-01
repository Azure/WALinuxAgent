#!/usr/bin/env bash

set -euxo pipefail


#           $1          $2          $3            $4              $5            $6                    $7
# Usage:  Artifact Dir

pytest ./**/agent-bvt/ --doctest-modules --junitxml="$1/test-result.xml"