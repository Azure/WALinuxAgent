#!/usr/bin/env bash

set -euxo pipefail

# Delete all scenarios except for the one we're running in this VM
shopt -s extglob
pushd "$BUILD_SOURCESDIRECTORY/dcr/scenarios"
rm -rf !("$SCENARIONAME")
ls -al
popd

# Move contents of the remaining scenario to a directory called scenario
# This is done to be able to import the yml easily as importing a yml template can only be static, it cant be dynamic
mkdir "$BUILD_SOURCESDIRECTORY/dcr/scenario"
cp -r "$BUILD_SOURCESDIRECTORY/dcr/scenarios/$SCENARIONAME/*" "$BUILD_SOURCESDIRECTORY/dcr/scenario/"
