#!/usr/bin/env bash

# https://linuxcommand.org/lc3_man_pages/seth.html
# -e  Exit immediately if a command exits with a non-zero status.
# -u  Treat unset variables as an error when substituting.
# -x  Print commands and their arguments as they are executed.
# -o pipefail     the return value of a pipeline is the status of the last command to exit with a non-zero status,
#                 or zero if no command exited with a non-zero status
set -euxo pipefail

version=$(grep '^AGENT_VERSION' "$BUILD_SOURCESDIRECTORY/azurelinuxagent/common/version.py" |  sed "s/.*'\([^']\+\)'.*/\1/")
# Azure Pipelines adds an extra quote at the end of the variable if we enable bash debugging as it prints an extra line - https://developercommunity.visualstudio.com/t/pipeline-variable-incorrectly-inserts-single-quote/375679
set +x; echo "##vso[task.setvariable variable=agentVersion]$version"; set -x
sudo ./makepkg.py
sudo cp ./eggs/WALinuxAgent-$version.zip "$BUILD_SOURCESDIRECTORY/dcr"
sudo cp -r ./eggs/WALinuxAgent-$version "$BUILD_SOURCESDIRECTORY/dcr"