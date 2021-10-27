#!/usr/bin/env bash

# https://linuxcommand.org/lc3_man_pages/seth.html
# -e  Exit immediately if a command exits with a non-zero status.
# -u  Treat unset variables as an error when substituting.
# -x  Print commands and their arguments as they are executed.
# -o pipefail     the return value of a pipeline is the status of the last command to exit with a non-zero status,
#                 or zero if no command exited with a non-zero status
set -euxo pipefail

# Delete all scenarios except for the one we're running in this VM
shopt -s extglob
pushd "$BUILD_SOURCESDIRECTORY/dcr/scenarios"
rm -rf !("$SCENARIONAME")
popd

# Move contents of the remaining scenario to a directory called scenario
# This is done to be able to import the yml easily as importing a yml template can only be static, it cant be dynamic
mkdir "$BUILD_SOURCESDIRECTORY/dcr/scenario"
cp -r "$BUILD_SOURCESDIRECTORY/dcr/scenarios/$SCENARIONAME"/* "$BUILD_SOURCESDIRECTORY/dcr/scenario/"
