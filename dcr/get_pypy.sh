#!/usr/bin/env bash

set -euxo pipefail

pushd "$BUILD_SOURCESDIRECTORY/dcr"
curl "https://downloads.python.org/pypy/pypy3.7-v7.3.5-linux64.tar.bz2" -o "pypy.tar.bz2"
mkdir "pypy"
tar xf "$BUILD_SOURCESDIRECTORY/dcr/pypy.tar.bz2" -C "pypy"
pypy_path=$(ls -d pypy/*/bin/pypy3)
popd
echo "##vso[task.setvariable variable=pypyPath;isOutput=true]/home/$ADMINUSERNAME/dcr/$pypy_path"