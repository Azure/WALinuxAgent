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
# Requires Python 2.6+ and Openssl 1.0+
#

import subprocess
import tempfile
import threading

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr


if not hasattr(subprocess, 'check_output'):
    def check_output(*popenargs, **kwargs):
        r"""Backport from subprocess module from python 2.7"""
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, '
                             'it will be overridden.')
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise subprocess.CalledProcessError(retcode, cmd, output=output)
        return output


    # Exception classes used by this module.
    class CalledProcessError(Exception):
        def __init__(self, returncode, cmd, output=None):  # pylint: disable=W0231
            self.returncode = returncode
            self.cmd = cmd
            self.output = output

        def __str__(self):
            return ("Command '{0}' returned non-zero exit status {1}"
                    "").format(self.cmd, self.returncode)


    subprocess.check_output = check_output
    subprocess.CalledProcessError = CalledProcessError

# pylint: disable=W0105
"""
Shell command util functions
""" 
# pylint: enable=W0105


def has_command(cmd):
    """
    Return True if the given command is on the path
    """
    return not run(cmd, False)


def run(cmd, chk_err=True, expected_errors=None):
    """
    Note: Deprecating in favour of `azurelinuxagent.common.utils.shellutil.run_command` function.
    Calls run_get_output on 'cmd', returning only the return code.
    If chk_err=True then errors will be reported in the log.
    If chk_err=False then errors will be suppressed from the log.
    """
    if expected_errors is None:
        expected_errors = []
    retcode, out = run_get_output(cmd, chk_err=chk_err, expected_errors=expected_errors)  # pylint: disable=W0612
    return retcode


def run_get_output(cmd, chk_err=True, log_cmd=True, expected_errors=None):
    """
    Wrapper for subprocess.check_output.
    Execute 'cmd'.  Returns return code and STDOUT, trapping expected
    exceptions.
    Reports exceptions to Error if chk_err parameter is True

    For new callers, consider using run_command instead as it separates stdout from stderr,
    returns only stdout on success, logs both outputs and return code on error and raises an exception.
    """
    if expected_errors is None:
        expected_errors = []
    if log_cmd:
        logger.verbose(u"Command: [{0}]", cmd)

    try:
        process = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

        output, _ = process.communicate()
        _on_command_completed(process.pid)

        output = __encode_command_output(output)

        if process.returncode != 0:
            if chk_err:
                msg = u"Command: [{0}], " \
                      u"return code: [{1}], " \
                      u"result: [{2}]".format(cmd, process.returncode, output)
                if process.returncode in expected_errors:
                    logger.info(msg)
                else:
                    logger.error(msg)
            return process.returncode, output
    except Exception as exception:
        if chk_err:
            logger.error(u"Command [{0}] raised unexpected exception: [{1}]"
                         .format(cmd, ustr(exception)))
        return -1, ustr(exception)
    return 0, output


def __format_command(command):
    """
    Formats the command taken by run_command/run_pipe.

    Examples:
        > __format_command("sort")
        'sort'
        > __format_command(["sort", "-u"])
        'sort -u'
        > __format_command([["sort"], ["unique", "-n"]])
        'sort | unique -n'
    """
    if isinstance(command, list):
        if command and isinstance(command[0], list):
            return " | ".join([" ".join(cmd) for cmd in command])
        return " ".join(command)
    return command


def __encode_command_output(output):
    """
    Encodes the stdout/stderr returned by subprocess.communicate()
    """
    return ustr(output if output is not None else b'', encoding='utf-8', errors="backslashreplace")


class CommandError(Exception):
    """
    Exception raised by run_command/run_pipe when the command returns an error
    """
    @staticmethod
    def _get_message(command, return_code, stderr):
        command_name = command[0] if isinstance(command, list) and len(command) > 0 else command
        return "'{0}' failed: {1} ({2})".format(command_name, return_code, stderr.rstrip())

    def __init__(self, command, return_code, stdout, stderr):
        super(Exception, self).__init__(CommandError._get_message(command, return_code, stderr))  # pylint: disable=E1003
        self.command = command
        self.returncode = return_code
        self.stdout = stdout
        self.stderr = stderr


def __run_command(command_action, command, log_error, encode_output):
    """
    Executes the given command_action and returns its stdout. The command_action is a function that executes a command/pipe
    and returns its exit code, stdout, and stderr.

    If there are any errors executing the command it raises a RunCommandException; if 'log_error'
    is True, it also logs details about the error.

    If encode_output is True the stdout is returned as a string, otherwise it is returned as a bytes object.
    """
    try:
        return_code, stdout, stderr = command_action()

        if encode_output:
            stdout = __encode_command_output(stdout)
            stderr = __encode_command_output(stderr)

        if return_code != 0:
            if log_error:
                logger.error(
                    "Command: [{0}], return code: [{1}], stdout: [{2}] stderr: [{3}]",
                    __format_command(command),
                    return_code,
                    stdout,
                    stderr)
            raise CommandError(command=__format_command(command), return_code=return_code, stdout=stdout, stderr=stderr)

        return stdout

    except CommandError:
        raise
    except Exception as exception:
        if log_error:
            logger.error(u"Command [{0}] raised unexpected exception: [{1}]", __format_command(command), ustr(exception))
        raise


# W0622: Redefining built-in 'input'  -- disabled: the parameter name mimics subprocess.communicate()
def run_command(command, input=None, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, log_error=False, encode_input=True, encode_output=True, track_process=True):  # pylint:disable=W0622
    """
        Executes the given command and returns its stdout.

        If there are any errors executing the command it raises a RunCommandException; if 'log_error'
        is True, it also logs details about the error.

        If encode_output is True the stdout is returned as a string, otherwise it is returned as a bytes object.

        If track_process is False the command is not added to list of running commands

        This function is a thin wrapper around Popen/communicate in the subprocess module:
           * The 'input' parameter corresponds to the same parameter in communicate
           * The 'stdin' parameter corresponds to the same parameters in Popen
           * Only one of 'input' and 'stdin' can be specified
           * The 'stdout' and 'stderr' parameters correspond to the same parameters in Popen, except that they
             default to subprocess.PIPE instead of None
           * If the output of the command is redirected using the 'stdout' or 'stderr' parameters (i.e. if the
             value for these parameters is anything other than the default (subprocess.PIPE)), then the corresponding
             values returned by this function or the CommandError exception will be empty strings.

        Note: This is the preferred method to execute shell commands over `azurelinuxagent.common.utils.shellutil.run` function.
    """
    if input is not None and stdin is not None:
        raise ValueError("The input and stdin arguments are mutually exclusive")

    def command_action():
        popen_stdin = communicate_input = None
        if input is not None:
            popen_stdin = subprocess.PIPE
            communicate_input = input.encode() if encode_input and isinstance(input, str) else input  # communicate() needs an array of bytes
        if stdin is not None:
            popen_stdin = stdin
            communicate_input = None

        if track_process:
            process = _popen(command, stdin=popen_stdin, stdout=stdout, stderr=stderr, shell=False)
        else:
            process = subprocess.Popen(command, stdin=popen_stdin, stdout=stdout, stderr=stderr, shell=False)

        command_stdout, command_stderr = process.communicate(input=communicate_input)
        if track_process:
            _on_command_completed(process.pid)

        return process.returncode, command_stdout, command_stderr

    return __run_command(command_action=command_action, command=command, log_error=log_error, encode_output=encode_output)


def run_pipe(pipe, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, log_error=False, encode_output=True): 
    """
        Executes the given commands as a pipe and returns its stdout as a string.

        The pipe is a list of commands, which in turn are a list of strings, e.g.

            [["sort"], ["uniq", "-n"]] represents 'sort | unique -n'

        If there are any errors executing the command it raises a RunCommandException; if 'log_error'
        is True, it also logs details about the error.

        If encode_output is True the stdout is returned as a string, otherwise it is returned as a bytes object.

        This function is a thin wrapper around Popen/communicate in the subprocess module:
           * The 'stdin' parameter is used as input for the first command in the pipe
           * The 'stdout', and 'stderr' can be used to redirect the output of the pipe
           * If the output of the pipe is redirected using the 'stdout' or 'stderr' parameters (i.e. if the
             value for these parameters is anything other than the default (subprocess.PIPE)), then the corresponding
             values returned by this function or the CommandError exception will be empty strings.
    """
    if len(pipe) < 2:
        raise ValueError("The pipe must consist of at least 2 commands")

    def command_action():
        stderr_file = None

        try:
            popen_stdin = stdin
            # If stderr is subprocess.PIPE each call to Popen would create a new pipe. We want to collect the stderr of all the
            # commands in the pipe so we replace stderr with a temporary file that we read once the pipe completes.
            if stderr == subprocess.PIPE:
                stderr_file = tempfile.TemporaryFile()
                popen_stderr = stderr_file
            else:
                popen_stderr = stderr

            processes = []
            i = 0
            while i < len(pipe) - 1:
                processes.append(_popen(pipe[i], stdin=popen_stdin, stdout=subprocess.PIPE, stderr=popen_stderr))
                popen_stdin = processes[i].stdout
                i += 1

            processes.append(_popen(pipe[i], stdin=popen_stdin, stdout=stdout, stderr=popen_stderr))

            i = 0
            while i < len(processes) - 1:
                processes[i].stdout.close()  # see https://docs.python.org/2/library/subprocess.html#replacing-shell-pipeline
                i += 1

            pipe_stdout, pipe_stderr = processes[i].communicate()

            for proc in processes:
                _on_command_completed(proc.pid)

            if stderr_file is not None:
                stderr_file.seek(0)
                pipe_stderr = stderr_file.read()

            return processes[i].returncode, pipe_stdout, pipe_stderr
        finally:
            if stderr_file is not None:
                stderr_file.close()

    return __run_command(command_action=command_action, command=pipe, log_error=log_error, encode_output=encode_output)


def quote(word_list):
    """
    Quote a list or tuple of strings for Unix Shell as words, using the
    byte-literal single quote.

    The resulting string is safe for use with ``shell=True`` in ``subprocess``,
    and in ``os.system``. ``assert shlex.split(ShellQuote(wordList)) == wordList``.

    See POSIX.1:2013 Vol 3, Chap 2, Sec 2.2.2:
    http://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_02_02
    """
    if not isinstance(word_list, (tuple, list)):
        word_list = (word_list,)

    return " ".join(list("'{0}'".format(s.replace("'", "'\\''")) for s in word_list))


#
# The run_command/run_pipe/run/run_get_output functions maintain a list of the commands that they are currently executing.
#
#
_running_commands = []
_running_commands_lock = threading.RLock()


def _popen(*args, **kwargs):
    with _running_commands_lock:
        process = subprocess.Popen(*args, **kwargs)
        _running_commands.append(process.pid)
        return process


def _on_command_completed(pid):
    with _running_commands_lock:
        _running_commands.remove(pid)


def get_running_commands():
    """
    Returns the commands started by run/run_get_output/run_command/run_pipe that are currently running.

    NOTE: This function is not synchronized with process completion, so the returned array may include processes that have
    already completed. Also, keep in mind that by the time this function returns additional processes may have
    started or completed.
    """
    with _running_commands_lock:
        return _running_commands[:]  # return a copy, since the call may originate on another thread


