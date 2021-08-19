#!/usr/bin/env bash

#            1          2           3
# Usage: <pypyPath>
set -euxo pipefail

$1 -m ensurepip
