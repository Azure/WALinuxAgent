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

import os
import re
import signal
import time

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common.exception import ExtensionErrorCodes, ExtensionOperationError, ExtensionError
from azurelinuxagent.common.future import ustr

TELEMETRY_MESSAGE_MAX_LEN = 3200


def wait_for_process_completion_or_timeout(process, timeout, cpu_cgroup):
    """
    Utility function that waits for the process to complete within the given time frame. This function will terminate
    the process if when the given time frame elapses.
    :param process: Reference to a running process
    :param timeout: Number of seconds to wait for the process to complete before killing it
    :return: Two parameters: boolean for if the process timed out and the return code of the process (None if timed out)
    """
    while timeout > 0 and process.poll() is None:
        time.sleep(1)
        timeout -= 1

    return_code = None
    throttled_time = 0

    if timeout == 0:
        throttled_time = get_cpu_throttled_time(cpu_cgroup)
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    else:
        # process completed or forked; sleep 1 sec to give the child process (if any) a chance to start
        time.sleep(1)
        return_code = process.wait()

    return timeout == 0, return_code, throttled_time


def handle_process_completion(process, command, timeout, stdout, stderr, error_code, cpu_cgroup=None):
    """
    Utility function that waits for process completion and retrieves its output (stdout and stderr) if it completed
    before the timeout period. Otherwise, the process will get killed and an ExtensionError will be raised.
    In case the return code is non-zero, ExtensionError will be raised.
    :param process: Reference to a running process
    :param command: The extension command to run
    :param timeout: Number of seconds to wait before killing the process
    :param stdout: Must be a file since we seek on it when parsing the subprocess output
    :param stderr: Must be a file since we seek on it when parsing the subprocess outputs
    :param error_code: The error code to set if we raise an ExtensionError
    :param cpu_cgroup: Reference the cpu cgroup name and path
    :return:
    """
    # Wait for process completion or timeout
    timed_out, return_code, throttled_time = wait_for_process_completion_or_timeout(process, timeout, cpu_cgroup)
    process_output = read_output(stdout, stderr)

    if timed_out:
        if cpu_cgroup is not None: # Report CPUThrottledTime when timeout happens
            raise ExtensionError("Timeout({0});CPUThrottledTime({1}secs): {2}\n{3}".format(timeout, throttled_time, command, process_output),
                                 code=ExtensionErrorCodes.PluginHandlerScriptTimedout)

        raise ExtensionError("Timeout({0}): {1}\n{2}".format(timeout, command, process_output),
                             code=ExtensionErrorCodes.PluginHandlerScriptTimedout)

    if return_code != 0:
        noexec_warning = ""
        if return_code == 126:  # Permission denied
            noexec_path = _check_noexec()
            if noexec_path is not None:
                noexec_warning = "\nWARNING: {0} is mounted with the noexec flag, which can prevent execution of VM Extensions.".format(noexec_path)
        raise ExtensionOperationError(
            "Non-zero exit code: {0}, {1}{2}\n{3}".format(return_code, command, noexec_warning, process_output),
            code=error_code,
            exit_code=return_code)

    return process_output


#
# Collect a sample of errors while checking for the noexec flag. Consider removing this telemetry after a few releases.
#
_COLLECT_NOEXEC_ERRORS = True


def _check_noexec():
    """
    Check if /var is mounted with the noexec flag.
    """
    try:
        agent_dir = conf.get_lib_dir()
        with open('/proc/mounts', 'r') as f:
            while True:
                line = f.readline()
                if line == "":  # EOF
                    break
                # The mount point is on the second column, and the flags are on the fourth. e.g.
                #
                #     # grep /var /proc/mounts
                #     /dev/mapper/rootvg-varlv /var xfs rw,seclabel,noexec,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota 0 0
                #
                columns = line.split()
                mount_point = columns[1]
                flags = columns[3]
                if agent_dir.startswith(mount_point) and "noexec" in flags:
                    message = "The noexec flag is set on {0}. This can prevent extensions from executing.".format(mount_point)
                    logger.warn(message)
                    add_event(op=WALAEventOperation.NoExec, is_success=False, message=message)
                    return mount_point
    except Exception as e:
        message = "Error while checking the noexec flag: {0}".format(e)
        logger.warn(message)
        if _COLLECT_NOEXEC_ERRORS:
            _COLLECT_NOEXEC_ERRORS = False
            add_event(op=WALAEventOperation.NoExec, is_success=False, log_event=False, message="Error while checking the noexec flag: {0}".format(e))
    return None


SAS_TOKEN_RE = re.compile(r'(https://\S+\?)((sv|st|se|sr|sp|sip|spr|sig)=\S+)+', flags=re.IGNORECASE)


def read_output(stdout, stderr):
    """
    Read the output of the process sent to stdout and stderr and trim them to the max appropriate length.
    :param stdout: File containing the stdout of the process
    :param stderr: File containing the stderr of the process
    :return: Returns the formatted concatenated stdout and stderr of the process
    """
    try:
        stdout.seek(0)
        stderr.seek(0)

        stdout = ustr(stdout.read(TELEMETRY_MESSAGE_MAX_LEN), encoding='utf-8',
                      errors='backslashreplace')
        stderr = ustr(stderr.read(TELEMETRY_MESSAGE_MAX_LEN), encoding='utf-8',
                      errors='backslashreplace')

        def redact(s):
            # redact query strings that look like SAS tokens
            return SAS_TOKEN_RE.sub(r'\1<redacted>', s)

        return format_stdout_stderr(redact(stdout), redact(stderr))
    except Exception as e:
        return format_stdout_stderr("", "Cannot read stdout/stderr: {0}".format(ustr(e)))


def format_stdout_stderr(stdout, stderr):
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
    max_len = TELEMETRY_MESSAGE_MAX_LEN
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


def get_cpu_throttled_time(cpu_cgroup):
    """
    return the throttled time for the given cgroup.
    """
    throttled_time = 0
    if cpu_cgroup is not None:
        try:
            throttled_time = cpu_cgroup.get_cpu_throttled_time(read_previous_throttled_time=False)
        except Exception as e:
            logger.warn("Failed to get cpu throttled time for the extension: {0}", ustr(e))

    return throttled_time
