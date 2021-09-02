#!/usr/bin/env bash

#            1          2           3
# Usage: <requirements.txt>
set -euxo pipefail

$PYPYPATH -m ensurepip
$PYPYPATH -m pip install -r "$1"
