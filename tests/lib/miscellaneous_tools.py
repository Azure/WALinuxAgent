# -*- coding: utf-8 -*-
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
# Requires Python 2.6+ and Openssl 1.0+
#

#
# Utility functions for the unit tests.
#
# This module is meant for simple, small tools that don't fit elsewhere.
#

import datetime
import os
import time

from azurelinuxagent.common.future import ustr


def format_processes(pid_list):
    """
    Formats the given PIDs as a sequence of PIDs and their command lines
    """
    def get_command_line(pid):
        try:
            cmdline = '/proc/{0}/cmdline'.format(pid)
            if os.path.exists(cmdline):
                with open(cmdline, "r") as cmdline_file:
                    return "[PID: {0}] {1}".format(pid, cmdline_file.read())
        except Exception:
            pass
        return "[PID: {0}] UNKNOWN".format(pid)

    return ustr([get_command_line(pid) for pid in pid_list])


def wait_for(predicate, timeout=10, frequency=0.01):
    """
    Waits until the given predicate is true or the given timeout elapses. Returns the last evaluation of the predicate.
    Both the timeout and frequency are in seconds; the latter indicates how often the predicate is evaluated.
    """
    def to_seconds(time_delta):
        return (time_delta.microseconds + (time_delta.seconds + time_delta.days * 24 * 3600) * 10 ** 6) / 10 ** 6

    start_time = datetime.datetime.now()
    while to_seconds(datetime.datetime.now() - start_time) < timeout:
        if predicate():
            return True
        time.sleep(frequency)
    return False
