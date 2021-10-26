#!/usr/bin/env bash

#            1          2           3
# Usage: <requirements.txt>

# https://linuxcommand.org/lc3_man_pages/seth.html
# -e  Exit immediately if a command exits with a non-zero status.
# -u  Treat unset variables as an error when substituting.
# -x  Print commands and their arguments as they are executed.
# -o pipefail     the return value of a pipeline is the status of the last command to exit with a non-zero status,
#                 or zero if no command exited with a non-zero status
set -euxo pipefail

$PYPYPATH -m ensurepip
$PYPYPATH -m pip install -r "$1"
