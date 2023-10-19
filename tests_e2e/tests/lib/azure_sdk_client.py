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

from typing import Any, Callable

from azure.identity import DefaultAzureCredential
from azure.core.polling import LROPoller

from tests_e2e.tests.lib.azure_clouds import AZURE_CLOUDS
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import execute_with_retry


class AzureSdkClient:
    """
    Base class for classes implementing clients of the Azure SDK.
    """
    _DEFAULT_TIMEOUT = 10 * 60  # (in seconds)

    @staticmethod
    def create(client_type: type, cloud: str, subscription_id: str):
        """
        Creates an SDK client of the given 'client_type'
        """
        azure_cloud = AZURE_CLOUDS[cloud]
        return client_type(
            base_url=azure_cloud.endpoints.resource_manager,
            credential=DefaultAzureCredential(authority=azure_cloud.endpoints.active_directory),
            credential_scopes=[azure_cloud.endpoints.resource_manager + "/.default"],
            subscription_id=subscription_id)

    @staticmethod
    def _execute_async_operation(operation: Callable[[], LROPoller], operation_name: str, timeout: int) -> Any:
        """
        Starts an async operation and waits its completion. Returns the operation's result.
        """
        log.info("Starting [%s]", operation_name)
        poller: LROPoller = execute_with_retry(operation)
        log.info("Waiting for [%s]", operation_name)
        poller.wait(timeout=timeout)
        if not poller.done():
            raise TimeoutError(f"[{operation_name}] did not complete within {timeout} seconds")
        log.info("[%s] completed", operation_name)
        return poller.result()

