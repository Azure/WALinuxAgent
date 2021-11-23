#!/usr/bin/env bash

# https://linuxcommand.org/lc3_man_pages/seth.html
# -e  Exit immediately if a command exits with a non-zero status.
# -u  Treat unset variables as an error when substituting.
# -x  Print commands and their arguments as they are executed.
# -o pipefail     the return value of a pipeline is the status of the last command to exit with a non-zero status,
#                 or zero if no command exited with a non-zero status
set -euxo pipefail

pushd "$BUILD_SOURCESDIRECTORY/dcr"
curl "https://downloads.python.org/pypy/pypy3.7-v7.3.5-linux64.tar.bz2" -o "pypy.tar.bz2"
mkdir "pypy"
tar xf "$BUILD_SOURCESDIRECTORY/dcr/pypy.tar.bz2" -C "pypy"
pypy_path=$(ls -d pypy/*/bin/pypy3)
rm -rf "pypy.tar.bz2"
popd

# Azure Pipelines adds an extra quote at the end of the variable if we enable bash debugging as it prints an extra line - https://developercommunity.visualstudio.com/t/pipeline-variable-incorrectly-inserts-single-quote/375679
set +x
echo "##vso[task.setvariable variable=pypyPath]/home/$ADMINUSERNAME/dcr/$pypy_path"