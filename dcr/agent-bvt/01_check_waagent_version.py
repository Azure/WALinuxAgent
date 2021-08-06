from __future__ import print_function

import os
import re
import subprocess
import sys
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--custom-vhd', dest='custom_vhd', default=False, action="store_true")
    args = parser.parse_args()

    pipe = subprocess.Popen(['waagent', '-version'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout_lines = list(map(lambda s: s.decode('utf-8'), pipe.stdout.readlines()))
    exit_code = pipe.wait()

    for line in stdout_lines:
        print(line)

    if args.custom_vhd:
        print("Skipping this test as this is a Custom Vhd")
        sys.exit(0)

    # release_file contains:
    # AGENT_VERSION = 'x.y.z'
    expected_version = 'unknown'
    release_file = '/etc/agent-release'
    release_pattern = "AGENT_VERSION = '(.*)'\n"
    if os.path.exists(release_file):
        with open(release_file, 'r') as rfh:
            expected_version = re.match(release_pattern, rfh.read()).groups()[0]

    expected_version_string = "WALinuxAgent-{0}".format(expected_version)

    if exit_code != 0:
        sys.exit(exit_code)
    elif expected_version_string in stdout_lines[0]:
        sys.exit(0)
    else:
        print('Expected: {0}'.format(expected_version_string))
        print('   Found: {0}'.format(stdout_lines[0]))
        sys.exit(1)


if __name__ == "__main__":
    main()
