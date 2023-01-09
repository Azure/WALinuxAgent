#!/usr/bin/env python3

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
from subprocess import Popen, PIPE
from typing import Any


class CommandError(Exception):
    """
    Exception raised by run_command when the command returns an error
    """
    def __init__(self, command: Any, exit_code: int, stdout: str, stderr: str):
        super().__init__(f"'{command}' failed (exit code: {exit_code}): {stderr}")
        self.command: Any = command
        self.exit_code: int = exit_code
        self.stdout: str = stdout
        self.stderr: str = stderr


def run_command(command: Any, shell=False) -> str:
    """
    This function is a thin wrapper around Popen/communicate in the subprocess module. It executes the given command
    and returns its stdout. If the command returns a non-zero exit code, the function raises a RunCommandException.

    Similarly to Popen, the 'command' can be a string or a list of strings, and 'shell' indicates whether to execute
    the command through the shell.

    NOTE: The command's stdout and stderr are read as text streams.
    """
    process = Popen(command, stdout=PIPE, stderr=PIPE, shell=shell, text=True)

    stdout, stderr = process.communicate()

    if process.returncode != 0:
        raise CommandError(command, process.returncode, stdout, stderr)

    return stdout

