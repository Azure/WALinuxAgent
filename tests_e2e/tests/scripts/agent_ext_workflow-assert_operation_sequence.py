#!/usr/bin/env pypy3

# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# The DcrTestExtension maintains an `operations-<VERSION_NO>.log` for every operation that the agent executes on that
# extension. This script asserts that the operations sequence in the log file matches the expected operations given as
# input to this script. We do this to confirm that the agent executed the correct sequence of operations.
#
# Sample operations-<version>.log file snippet -
# Date:2019-07-30T21:54:03Z; Operation:install; SeqNo:0
# Date:2019-07-30T21:54:05Z; Operation:enable; SeqNo:0
# Date:2019-07-30T21:54:37Z; Operation:enable; SeqNo:1
# Date:2019-07-30T21:55:20Z; Operation:disable; SeqNo:1
# Date:2019-07-30T21:55:22Z; Operation:uninstall; SeqNo:1
#
import argparse
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List

DELIMITER = ";"
OPS_FILE_DIR = "/var/log/azure/Microsoft.Azure.TestExtensions.Edp.GuestAgentDcrTest/"
OPS_FILE_PATTERN = ["operations-%s.log", "%s/operations-%s.log"]
MAX_RETRY = 5
SLEEP_TIMER = 30


def parse_ops_log(ops_version: str, input_ops: List[str], start_time: str):
    # input_ops are the expected operations that we expect to see in the operations log file
    ver = (ops_version,)
    ops_file_name = None
    for file_pat in OPS_FILE_PATTERN:
        ops_file_name = os.path.join(OPS_FILE_DIR, file_pat % ver)
        if not os.path.exists(ops_file_name):
            ver = ver + (ops_version,)
            ops_file_name = None
            continue
        break

    if not ops_file_name:
        raise IOError("Operations File %s not found" % os.path.join(OPS_FILE_DIR, OPS_FILE_PATTERN[0] % ops_version))

    ops = []
    with open(ops_file_name, 'r') as ops_log:
        # we get the last len(input_ops) from the log file and ensure they match with the input_ops
        # Example of a line in the log file - `Date:2019-07-30T21:54:03Z; Operation:install; SeqNo:0`
        content = ops_log.readlines()[-len(input_ops):]
        for op_log in content:
            data = op_log.split(DELIMITER)
            date = datetime.strptime(data[0].split("Date:")[1], "%Y-%m-%dT%H:%M:%SZ")
            op = data[1].split("Operation:")[1]
            seq_no = data[2].split("SeqNo:")[1].strip('\n')

            # We only capture the operations that > start_time of the test
            if start_time > date:
                continue

            ops.append({'date': date, 'op': op, 'seq_no': seq_no})
    return ops


def assert_ops_in_sequence(actual_ops: List[Dict[str, Any]], expected_ops: List[str]):
    exit_code = 0
    if len(actual_ops) != len(expected_ops):
        print("Operation sequence length doesn't match, exit code 2")
        exit_code = 2

    last_date = datetime(70, 1, 1)
    for idx, val in enumerate(actual_ops):
        if exit_code != 0:
            break

        if val['date'] < last_date or val['op'] != expected_ops[idx]:
            print("Operation sequence doesn't match, exit code 2")
            exit_code = 2

        last_date = val['date']

    return exit_code


def check_update_sequence(args):
    # old_ops_file_name = OPS_FILE_PATTERN % args.old_version
    # new_ops_file_name = OPS_FILE_PATTERN % args.new_version

    actual_ops = parse_ops_log(args.old_version, args.old_ops, args.start_time)
    actual_ops.extend(parse_ops_log(args.new_version, args.new_ops, args.start_time))
    actual_ops = sorted(actual_ops, key=lambda op: op['date'])

    exit_code = assert_ops_in_sequence(actual_ops, args.ops)

    return exit_code, actual_ops


def check_operation_sequence(args):
    # ops_file_name = OPS_FILE_PATTERN % args.version

    actual_ops = parse_ops_log(args.version, args.ops, args.start_time)
    exit_code = assert_ops_in_sequence(actual_ops, args.ops)

    return exit_code, actual_ops


def main():
    # There are 2 main ways you can call this file - normal_ops_sequence or update_sequence
    parser = argparse.ArgumentParser()
    cmd_parsers = parser.add_subparsers(help="sub-command help", dest="command")

    # We use start_time to make sure we're testing the correct test and not some other test
    parser.add_argument("--start-time", dest='start_time', required=True)

    # Normal_ops_sequence gets the version of the ext and parses the corresponding operations file to get the operation
    # sequence that were run on the extension
    normal_ops_sequence_parser = cmd_parsers.add_parser("normal_ops_sequence", help="Test the normal operation sequence")
    normal_ops_sequence_parser.add_argument('--version', dest='version')
    normal_ops_sequence_parser.add_argument('--ops', nargs='*', dest='ops', default=argparse.SUPPRESS)

    # Update_sequence mode is used to check for the update scenario. We get the expected old operations, expected
    # new operations and the final operation list and verify if the expected operations match the actual ones
    update_sequence_parser = cmd_parsers.add_parser("update_sequence", help="Test the update operation sequence")
    update_sequence_parser.add_argument("--old-version", dest="old_version")
    update_sequence_parser.add_argument("--new-version", dest="new_version")
    update_sequence_parser.add_argument("--old-ver-ops", nargs="*", dest="old_ops", default=argparse.SUPPRESS)
    update_sequence_parser.add_argument("--new-ver-ops", nargs="*", dest="new_ops", default=argparse.SUPPRESS)
    update_sequence_parser.add_argument("--final-ops", nargs="*", dest="ops", default=argparse.SUPPRESS)

    args, unknown = parser.parse_known_args()

    if unknown or len(unknown) > 0:
        # Print any unknown arguments passed to this script and fix them with low priority
        print("[Low Proiority][To-Fix] Found unknown args: %s" % ', '.join(unknown))

    args.start_time = datetime.strptime(args.start_time, "%Y-%m-%dT%H:%M:%SZ")

    exit_code = 999
    actual_ops = []

    for i in range(0, MAX_RETRY):
        if args.command == "update_sequence":
            exit_code, actual_ops = check_update_sequence(args)
        elif args.command == "normal_ops_sequence":
            exit_code, actual_ops = check_operation_sequence(args)
        else:
            print("No such command %s, exit code 5\n" % args.command)
            exit_code, actual_ops = 5, []
            break

        if exit_code == 0:
            break

        print("{0} test failed with exit code: {1}; Retry attempt: {2}; Retrying in {3} secs".format(args.command,
                                                                                                     exit_code, i,
                                                                                                     SLEEP_TIMER))
        time.sleep(SLEEP_TIMER)

    if exit_code != 0:
        print("Expected Operations: %s" % ", ".join(args.ops))
        print("Actual Operations: %s" %
              ','.join(["[%s, Date: %s]" % (op['op'], op['date'].strftime("%Y-%m-%dT%H:%M:%SZ")) for op in actual_ops]))

    print("Assertion completed, exiting with code: %s" % exit_code)
    sys.exit(exit_code)


if __name__ == "__main__":
    print("Asserting operations\n")
    main()
