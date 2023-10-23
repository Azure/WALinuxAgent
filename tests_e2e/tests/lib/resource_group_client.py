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

#
# This module includes facilities to create a resource group and deploy an arm template to it
#
from typing import Dict, Any

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import DeploymentProperties, DeploymentMode

from tests_e2e.tests.lib.azure_sdk_client import AzureSdkClient
from tests_e2e.tests.lib.logging import log


class ResourceGroupClient(AzureSdkClient):
    """
    Provides operations on resource groups (create, template deployment, etc).
    """
    def __init__(self, cloud: str, subscription: str, name: str, location: str = ""):
        super().__init__()
        self.cloud: str = cloud
        self.location = location
        self.subscription: str = subscription
        self.name: str = name
        self._compute_client = AzureSdkClient.create_client(ComputeManagementClient, cloud, subscription)
        self._resource_client = AzureSdkClient.create_client(ResourceManagementClient, cloud, subscription)

    def create_client(self) -> None:
        """
        Creates a resource group
        """
        log.info("Creating resource group %s", self)
        self._resource_client.resource_groups.create_or_update(self.name, {"location": self.location})

    def deploy_template(self, template: Dict[str, Any], parameters: Dict[str, Any] = None):
        """
        Deploys an ARM template to the resource group
        """
        if parameters:
            properties = DeploymentProperties(template=template, parameters=parameters, mode=DeploymentMode.incremental)
        else:
            properties = DeploymentProperties(template=template, mode=DeploymentMode.incremental)

        log.info("Deploying template to resource group %s...", self)
        self._execute_async_operation(
            operation=lambda: self._resource_client.deployments.begin_create_or_update(self.name, 'TestDeployment',  {'properties': properties}),
            operation_name=f"Deploy template to resource group {self}",
            timeout=AzureSdkClient._DEFAULT_TIMEOUT)

    def delete(self) -> None:
        """
        Deletes the resource group
        """
        log.info("Deleting resource group %s (no wait)", self)
        self._resource_client.resource_groups.begin_delete(self.name)  # Do not wait for the deletion to complete

    def __str__(self):
        return f"{self.name}"
