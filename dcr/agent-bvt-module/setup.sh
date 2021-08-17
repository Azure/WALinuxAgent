#!/usr/bin/env bash

set -euxo pipefail

scenario_dir=$(dirname "$0")
pip3 install -r "$scenario_dir/requirements.txt"