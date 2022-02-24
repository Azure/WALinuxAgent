#!/usr/bin/env bash
#
# Executes its arguments using the 'python' command, if it can be found, else using 'python3'.
#
python=$(command -v python 2> /dev/null)

if [ -z "$PYTHON" ]; then
  python=$(command -v python3)
fi

${python} "$@"