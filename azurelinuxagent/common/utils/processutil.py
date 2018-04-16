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

import subprocess
import sys
import os
import time
import signal
from errno import ESRCH
from multiprocessing import Process

from azurelinuxagent.common.exception import ExtensionError
from azurelinuxagent.common.future import ustr

TELEMETRY_MESSAGE_MAX_LEN = 3200


def sanitize(s):
    return ustr(s, encoding='utf-8', errors='backslashreplace')


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


def _destroy_process(process, signal_to_send=signal.SIGKILL):
    """
    Completely destroy the target process. Close the stdout/stderr pipes, kill the process, reap the zombie.
    If process is the leader of a process group, kill the entire process group.

    :param Popen process: Process to be sent a signal
    :param int signal_to_send: Signal number to be sent
    """
    process.stdout.close()
    process.stderr.close()
    try:
        pid = process.pid
        if os.getpgid(pid) == pid:
            os.killpg(pid, signal_to_send)
        else:
            os.kill(pid, signal_to_send)
        process.wait()
    except OSError as e:
        if e.errno != ESRCH:
            raise
        pass    # If the process is already gone, that's fine


def capture_from_process_modern(process, cmd, timeout):
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Just kill the process. The .communicate method will gather stdout/stderr, close those pipes, and reap
        # the zombie process. That is, .communicate() does all the other stuff that _destroy_process does.
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        stdout, stderr = process.communicate()
        msg = format_stdout_stderr(sanitize(stdout), sanitize(stderr))
        raise ExtensionError("Timeout({0}): {1}\n{2}".format(timeout, cmd, msg))
    except OSError as e:
        _destroy_process(process, signal.SIGKILL)
        raise ExtensionError("Error while running '{0}': {1}".format(cmd, e.strerror))
    except ValueError:
        _destroy_process(process, signal.SIGKILL)
        raise ExtensionError("Invalid timeout ({0}) specified for '{1}'".format(timeout, cmd))
    except Exception as e:
        _destroy_process(process, signal.SIGKILL)
        raise ExtensionError("Exception while running '{0}': {1}".format(cmd, e))

    return stdout, stderr


def capture_from_process_pre_33(process, cmd, timeout):
    """
    Can't use process.communicate(timeout=), so do it the hard way.
    """
    watcher_process_exited = 0
    watcher_process_timed_out = 1

    def kill_on_timeout(pid, watcher_timeout):
        """
        Check for the continued existence of pid once per second. If pid no longer exists, exit with code 0.
        If timeout (in seconds) elapses, kill pid and exit with code 1.
        """
        for iteration in range(watcher_timeout):
            time.sleep(1)
            try:
                os.kill(pid, 0)
            except OSError as ex:
                if ESRCH == ex.errno:   # Process no longer exists
                    exit(watcher_process_exited)
        os.killpg(os.getpgid(pid), signal.SIGKILL)
        exit(watcher_process_timed_out)

    watcher = Process(target=kill_on_timeout, args=(process.pid, timeout))
    watcher.start()

    try:
        # Now, block "forever" waiting on process. If the timeout-limited Event wait in the watcher pops,
        # it will kill the process and Popen.communicate() will return
        stdout, stderr = process.communicate()
    except OSError as e:
        _destroy_process(process, signal.SIGKILL)
        raise ExtensionError("Error while running '{0}': {1}".format(cmd, e.strerror))
    except Exception as e:
        _destroy_process(process, signal.SIGKILL)
        raise ExtensionError("Exception while running '{0}': {1}".format(cmd, e))

    timeout_happened = False
    watcher.join(1)
    if watcher.is_alive():
        watcher.terminate()
    else:
        timeout_happened = (watcher.exitcode == watcher_process_timed_out)

    if timeout_happened:
        msg = format_stdout_stderr(sanitize(stdout), sanitize(stderr))
        raise ExtensionError("Timeout({0}): {1}\n{2}".format(timeout, cmd, msg))

    return stdout, stderr


def capture_from_process_no_timeout(process, cmd):
    try:
        stdout, stderr = process.communicate()
    except OSError as e:
        _destroy_process(process, signal.SIGKILL)
        raise ExtensionError("Error while running '{0}': {1}".format(cmd, e.strerror))
    except Exception as e:
        _destroy_process(process, signal.SIGKILL)
        raise ExtensionError("Exception while running '{0}': {1}".format(cmd, e))

    return stdout, stderr


def capture_from_process_raw(process, cmd, timeout):
    """
    Captures stdout and stderr from an already-created process.

    :param subprocess.Popen process: Created by subprocess.Popen()
    :param str cmd: The command string to be included in any exceptions
    :param int timeout: Number of seconds the process is permitted to run
    :return: The stdout and stderr captured from the process
    :rtype: (str, str)
    :raises ExtensionError: if a timeout occurred or if anything was raised by Popen.communicate()
    """
    if not timeout:
        stdout, stderr = capture_from_process_no_timeout(process, cmd)
    else:
        if os.getpgid(process.pid) != process.pid:
            _destroy_process(process, signal.SIGKILL)
            raise ExtensionError("Subprocess was not root of its own process group")

        if sys.version_info < (3, 3):
            stdout, stderr = capture_from_process_pre_33(process, cmd, timeout)
        else:
            stdout, stderr = capture_from_process_modern(process, cmd, timeout)

    return stdout, stderr


def capture_from_process(process, cmd, timeout=0):
    """
    Captures stdout and stderr from an already-created process. The output is "cooked"
    into a string of reasonable length.

    :param subprocess.Popen process: Created by subprocess.Popen()
    :param str cmd: The command string to be included in any exceptions
    :param int timeout: Number of seconds the process is permitted to run
    :return: The stdout and stderr captured from the process
    :rtype: (str, str)
    :raises ExtensionError: if a timeout occurred or if anything was raised by Popen.communicate()
    """
    stdout, stderr = capture_from_process_raw(process, cmd, timeout)
    return format_stdout_stderr(sanitize(stdout), sanitize(stderr))
