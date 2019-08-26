# Microsoft Azure Linux Agent
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#
# You may not use this file except in compliance with the License.
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

from azurelinuxagent.common.exception import ExtensionError, ExtensionErrorCodes
from azurelinuxagent.common.future import ustr
import os
import signal
import subprocess
import time

TELEMETRY_MESSAGE_MAX_LEN = 3200


def wait_for_process_completion_or_timeout(process, timeout):
    while timeout > 0 and process.poll() is None:
        time.sleep(1)
        timeout -= 1

    return_code = None

    if timeout == 0:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    else:
        # process completed or forked; sleep 1 sec to give the child process (if any) a chance to start
        time.sleep(1)
        return_code = process.wait()

    return timeout == 0, return_code


def start_subprocess_and_wait_for_completion(command, timeout, shell, cwd, env, stdout, stderr, preexec_fn, error_code):
    process = subprocess.Popen(
        command,
        shell=shell,
        cwd=cwd,
        env=env,
        stdout=stdout,
        stderr=stderr,
        preexec_fn=preexec_fn)

    # Wait for process completion or timeout
    timed_out, return_code = wait_for_process_completion_or_timeout(process, timeout)
    process_output = read_output(stdout, stderr)

    if timed_out:
        raise ExtensionError("Timeout({0}): {1}\n{2}".format(timeout, command, process_output),
                             code=ExtensionErrorCodes.PluginHandlerScriptTimedout)

    if return_code != 0:
        raise ExtensionError("Non-zero exit code: {0}, {1}\n{2}".format(return_code, command, process_output),
                             code=error_code)

    return process_output


def read_output(stdout, stderr):
    try:
        stdout.seek(0)
        stderr.seek(0)

        stdout = ustr(stdout.read(TELEMETRY_MESSAGE_MAX_LEN), encoding='utf-8',
                      errors='backslashreplace')
        stderr = ustr(stderr.read(TELEMETRY_MESSAGE_MAX_LEN), encoding='utf-8',
                      errors='backslashreplace')

        return format_stdout_stderr(stdout, stderr)
    except Exception as e:
        return format_stdout_stderr("", "Cannot read stdout/stderr: {0}".format(ustr(e)))


def format_stdout_stderr(stdout, stderr, max_len=TELEMETRY_MESSAGE_MAX_LEN):
    """
    Format stdout and stderr's output to make it suitable in telemetry.
    The goal is to maximize the amount of output given the constraints
    of telemetry.

    For example, if there is more stderr output than stdout output give
    more buffer space to stderr.

    :param str stdout: characters captured from stdout
    :param str stderr: characters captured from stderr
    :param int max_len: maximum length of the string to return

    :return: a string formatted with stdout and stderr that is less than
    or equal to max_len.
    :rtype: str
    """
    template = "[stdout]\n{0}\n\n[stderr]\n{1}"
    # +6 == len("{0}") + len("{1}")
    max_len_each = int((max_len - len(template) + 6) / 2)

    if max_len_each <= 0:
        return ''

    def to_s(captured_stdout, stdout_offset, captured_stderr, stderr_offset):
        s = template.format(captured_stdout[stdout_offset:], captured_stderr[stderr_offset:])
        return s

    if len(stdout) + len(stderr) < max_len:
        return to_s(stdout, 0, stderr, 0)
    elif len(stdout) < max_len_each:
        bonus = max_len_each - len(stdout)
        stderr_len = min(max_len_each + bonus, len(stderr))
        return to_s(stdout, 0, stderr, -1*stderr_len)
    elif len(stderr) < max_len_each:
        bonus = max_len_each - len(stderr)
        stdout_len = min(max_len_each + bonus, len(stdout))
        return to_s(stdout, -1*stdout_len, stderr, 0)
    else:
        return to_s(stdout, -1*max_len_each, stderr, -1*max_len_each)

