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
        def __init__(self, returncode, cmd, output=None):
            self.returncode = returncode
            self.cmd = cmd
            self.output = output

        def __str__(self):
            return ("Command '{0}' returned non-zero exit status {1}"
                    "").format(self.cmd, self.returncode)


    subprocess.check_output = check_output
    subprocess.CalledProcessError = CalledProcessError

"""
Shell command util functions
"""

def has_command(cmd):
    """
    Return True if the given command is on the path
    """
    return not run(cmd, False)

def run(cmd, chk_err=True, expected_errors=[]):
    """
    Calls run_get_output on 'cmd', returning only the return code.
    If chk_err=True then errors will be reported in the log.
    If chk_err=False then errors will be suppressed from the log.
    """
    retcode, out = run_get_output(cmd, chk_err=chk_err, expected_errors=expected_errors)
    return retcode


def run_get_output(cmd, chk_err=True, log_cmd=True, expected_errors=[]):
    """
    Wrapper for subprocess.check_output.
    Execute 'cmd'.  Returns return code and STDOUT, trapping expected
    exceptions.
    Reports exceptions to Error if chk_err parameter is True

    For new callers, consider using run_command instead as it separates stdout from stderr,
    returns only stdout on success, logs both outputs and return code on error and raises an exception.
    """
    if log_cmd:
        logger.verbose(u"Command: [{0}]", cmd)
    try:
        output = subprocess.check_output(cmd,
                                         stderr=subprocess.STDOUT,
                                         shell=True)
        output = _encode_command_output(output)
    except subprocess.CalledProcessError as e:
        output = _encode_command_output(e.output)

        if chk_err:
            msg = u"Command: [{0}], " \
                  u"return code: [{1}], " \
                  u"result: [{2}]".format(cmd, e.returncode, output)
            if e.returncode in expected_errors:
                logger.info(msg)
            else:
                logger.error(msg)
        return e.returncode, output
    except Exception as e:
        if chk_err:
            logger.error(u"Command [{0}] raised unexpected exception: [{1}]"
                         .format(cmd, ustr(e)))
        return -1, ustr(e)
    return 0, output


def _encode_command_output(output):
    return ustr(output, encoding='utf-8', errors="backslashreplace")


class CommandError(Exception):
    """
    Exception raised by run_command when the command returns an error
    """
    @staticmethod
    def _get_message(command, returncode):
        command_name = command[0] if isinstance(command, list) and len(command) > 0 else command
        return "'{0}' failed: {1}".format(command_name, returncode)

    def __init__(self, command, returncode, stdout, stderr):
        super(Exception, self).__init__(CommandError._get_message(command, returncode))
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run_command(command, log_error=False):
    """
    Executes the given command and returns its stdout as a string.
    If there are any errors executing the command it logs details about the failure and raises a RunCommandException;
    if 'log_error' is True, it also logs details about the error.
    """
    def format_command(cmd):
        return " ".join(cmd) if isinstance(cmd, list) else command

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        stdout, stderr = process.communicate()
        returncode = process.returncode
    except Exception as e:
        if log_error:
            logger.error(u"Command [{0}] raised unexpected exception: [{1}]", format_command(command), ustr(e))
        raise

    if returncode != 0:
        encoded_stdout = _encode_command_output(stdout)
        encoded_stderr = _encode_command_output(stderr)
        if log_error:
            logger.error(
                "Command: [{0}], return code: [{1}], stdout: [{2}] stderr: [{3}]",
                format_command(command),
                returncode,
                encoded_stdout,
                encoded_stderr)
        raise CommandError(command=command, returncode=returncode, stdout=encoded_stdout, stderr=encoded_stderr)

    return _encode_command_output(stdout)


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

# End shell command util functions
