#!/usr/bin/env python3
import os
import sys

if len(sys.argv) != 4:
    sys.stderr.write("usage: {0} <stdout> <return_value> <stderr>".format(os.path.basename(__file__)))

# W0632: Possible unbalanced tuple unpacking with sequence: left side has 3 label(s), right side has 0 value(s) (unbalanced-tuple-unpacking)
# Disabled: Unpacking is balanced: there is a check for the length on line 5
stdout, return_value, stderr = sys.argv[1:]  # pylint: disable=W0632

if stdout != '':
    sys.stdout.write(stdout)
if stderr != '':
    sys.stderr.write(stderr)

sys.exit(int(return_value))
