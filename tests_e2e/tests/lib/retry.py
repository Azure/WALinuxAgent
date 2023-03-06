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
import time

from typing import Callable, Any

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError


def execute_with_retry(operation: Callable[[], Any]) -> Any:
    """
    Some Azure errors (e.g. throttling) are retryable; this method attempts the given operation retrying a few times
    (after a short delay) if the error includes the string "RetryableError"
    """
    attempts = 3
    while attempts > 0:
        attempts -= 1
        try:
            return operation()
        except Exception as e:
            # TODO: Do we need to retry on msrestazure.azure_exceptions.CloudError?
            if "RetryableError" not in str(e) or attempts == 0:
                raise
        log.warning("The operation failed with a RetryableError, retrying in 30 secs. Error: %s", e)
        time.sleep(30)


def retry_ssh_run(operation: Callable[[], Any]) -> Any:
    """
    This method attempts to retry ssh run command a few times if operation failed with connection time out
    """
    attempts = 3
    while attempts > 0:
        attempts -= 1
        try:
            return operation()
        except Exception as e:
            # We raise CommandError on !=0 exit codes in the called method
            if isinstance(e, CommandError):
                # Instance of 'Exception' has no 'exit_code' member (no-member) - Disabled: e is actually an CommandError
                if e.exit_code != 255 or attempts == 0:  # pylint: disable=no-member
                    raise
            log.warning("The operation failed with %s, retrying in 30 secs.", e)
        time.sleep(30)


def retry_if_not_found(operation: Callable[[], bool], attempts: int = 5) -> bool:
    """
    This method attempts the given operation retrying a few times
    (after a short delay)
    Note: Method used for operations which are return True or False
    """
    found: bool = False
    while attempts > 0 and not found:
        attempts -= 1
        try:
            found = operation()
        except Exception:
            if attempts == 0:
                raise
        if not found:
            log.info("Current execution didn't find it, retrying in 30 secs.")
        time.sleep(30)
    return found
