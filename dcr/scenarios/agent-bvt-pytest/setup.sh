#!/usr/bin/env bash

#            1          2           3
# Usage: <pypyPath>
set -euxo pipefail

scenario_dir=$(dirname "$0")
$1 -m pip install -r "$scenario_dir/requirements.txt"