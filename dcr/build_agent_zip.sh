#!/usr/bin/env bash

set -euxo pipefail

version=$(grep '^AGENT_VERSION' "$BUILD_SOURCESDIRECTORY/azurelinuxagent/common/version.py" |  sed "s/.*'\([^']\+\)'.*/\1/")
echo "##vso[task.setvariable variable=agentVersion;isOutput=true]$version"
sudo ./makepkg.py
sudo cp ./eggs/WALinuxAgent-$version.zip "$BUILD_SOURCESDIRECTORY/dcr"
sudo cp -r ./eggs/WALinuxAgent-$version "$BUILD_SOURCESDIRECTORY/dcr"