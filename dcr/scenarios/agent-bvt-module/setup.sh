#!/usr/bin/env bash

#            1          2           3
# Usage: <pypyPath>
set -euxo pipefail

scenario_dir=$(dirname "$0")
$PYPYPATH -m pip install -r "$scenario_dir/requirements.txt"