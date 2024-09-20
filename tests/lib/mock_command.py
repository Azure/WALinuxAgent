#!/usr/bin/env python3
import os
import sys

if len(sys.argv) < 4:
    sys.stderr.write("usage: {0} <stdout> <return_value> <stderr>".format(os.path.basename(__file__)))

# W0632: Possible unbalanced tuple unpacking with sequence: left side has 3 label(s), right side has 0 value(s) (unbalanced-tuple-unpacking)
# Disabled: Unpacking is balanced: there is a check for the length on line 5

# This script will be used for mocking cgroups commands in test, when popen called this script will be executed instead of actual commands
# We pass stdout, return_value, stderr of the mocked command output as arguments to this script and this script will print them to stdout, stderr and exit with the return value
# So that popen gets the output of the mocked command. Ideally we should get 4 arguments in sys.argv, first one is the script name, next 3 are the actual command output
# But somehow when we run the tests from pycharm, it adds extra arguments next to the script name, so we need to handle that when reading the arguments
# ex: /home/nag/Documents/repos/WALinuxAgent/tests/lib/mock_command.py /snap/pycharm-professional/412/plugins/python-ce/helpers/py... +BLKID +ELFUTILS +KMOD -IDN2 +IDN -PCRE2 default-hierarchy=hybrid\n 0
stdout, return_value, stderr = sys.argv[-3:]  # pylint: disable=W0632

if stdout != '':
    sys.stdout.write(stdout)
if stderr != '':
    sys.stderr.write(stderr)

sys.exit(int(return_value))
