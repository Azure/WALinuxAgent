#!/usr/bin/env python

from __future__ import print_function

import subprocess
import sys


def main():
    print("Executing waagent --version")

    pipe = subprocess.Popen(['waagent', '-version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_lines = list(map(lambda s: s.decode('utf-8'), pipe.stdout.readlines()))
    exit_code = pipe.wait()

    for line in stdout_lines:
        print(line)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
