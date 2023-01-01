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

from tests_e2e.scenarios.lib.logging import log


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


