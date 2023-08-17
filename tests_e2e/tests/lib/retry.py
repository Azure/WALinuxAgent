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


def retry_ssh_run(operation: Callable[[], Any], attempts: int, attempt_delay: int) -> Any:
    """
    This method attempts to retry ssh run command a few times if operation failed with connection time out
    """
    i = 0
    while True:
        i += 1
        try:
            return operation()
        except CommandError as e:
            retryable = e.exit_code == 255 and ("Connection timed out" in e.stderr or "Connection refused" in e.stderr)
            if not retryable or i >= attempts:
                raise
            log.warning("The SSH operation failed, retrying in %s secs [Attempt %s/%s].\n%s", attempt_delay, i, attempts, e)
        time.sleep(attempt_delay)


def retry_if_false(operation: Callable[[], bool], attempts: int = 5, delay: int = 30) -> bool:
    """
    This method attempts the given operation retrying a few times
    (after a short delay)
    Note: Method used for operations which are return True or False
    """
    success: bool = False
    while attempts > 0 and not success:
        attempts -= 1
        try:
            success = operation()
        except Exception as e:
            log.warning("Error in operation: %s", e)
            if attempts == 0:
                raise
        if not success and attempts != 0:
            log.info("Current operation failed, retrying in %s secs.", delay)
            time.sleep(delay)
    return success


def retry(operation: Callable[[], Any], attempts: int = 5, delay: int = 30) -> Any:
    """
    This method attempts the given operation retrying a few times on exceptions. Returns the value returned by the operation.
    """
    while attempts > 0:
        attempts -= 1
        try:
            return operation()
        except Exception as e:
            if attempts == 0:
                raise
            log.warning("Error in operation, retrying in %s secs: %s", delay, e)
            time.sleep(delay)
