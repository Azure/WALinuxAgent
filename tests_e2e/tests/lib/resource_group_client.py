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
import datetime
import time
from typing import Dict, Any, List

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import DeploymentProperties, DeploymentMode
from msrestazure.azure_cloud import Cloud

from tests_e2e.tests.lib.azure_client import AzureClient
from tests_e2e.tests.lib.azure_clouds import AZURE_CLOUDS
from tests_e2e.tests.lib.identifiers import RgIdentifier
from tests_e2e.tests.lib.logging import log


class ResourceGroupClient(AzureClient):
    """
    Provides operations on resource group (create, template deployment, etc).
    """

    def __init__(self, rg: RgIdentifier):
        super().__init__()
        self._identifier: RgIdentifier = rg
        cloud: Cloud = AZURE_CLOUDS[rg.cloud]
        credential: DefaultAzureCredential = DefaultAzureCredential(authority=cloud.endpoints.active_directory)
        self._compute_client = ComputeManagementClient(
            credential=credential,
            subscription_id=rg.subscription,
            base_url=cloud.endpoints.resource_manager,
            credential_scopes=[cloud.endpoints.resource_manager + "/.default"])
        self._resource_client = ResourceManagementClient(
            credential=credential,
            subscription_id=rg.subscription,
            base_url=cloud.endpoints.resource_manager,
            credential_scopes=[cloud.endpoints.resource_manager + "/.default"])

    def create(self) -> None:
        self._resource_client.resource_groups.create_or_update(
            self._identifier.name, {"location": self._identifier.location})

        timeout = datetime.datetime.now() + datetime.timedelta(seconds=AzureClient._DEFAULT_TIMEOUT)
        rg_created = False
        while datetime.datetime.now() < timeout and not rg_created:
            if self._resource_client.resource_groups.check_existence(self._identifier.name):
                log.info(f"Resource group {self._identifier} created")
                rg_created = True
            else:
                log.info(f"Resource group {self._identifier} creation not yet completed, waiting 30s...")
                time.sleep(30)
        if not rg_created:
            raise Exception(f"Resource group {self._identifier} creation timed out")

    def deploy_template(self, template: Dict[str, Any], parameters: Dict[str, Any]):
        props = DeploymentProperties(template=template,
                                     parameters=parameters,
                                     mode=DeploymentMode.incremental)
        self._execute_async_operation(
            lambda: self._resource_client.deployments.begin_create_or_update(
                self._identifier.name, 'TestDeployment',  {'properties': props}),
            operation_name=f"Deploy template to resource group {self._identifier}",
            timeout=AzureClient._DEFAULT_TIMEOUT)

    def delete_if_exists(self):
        rg_exists = self._resource_client.resource_groups.check_existence(
            self._identifier.name
        )
        if rg_exists:
            self._execute_async_operation(
                lambda: self._resource_client.resource_groups.begin_delete(
                    self._identifier.name),
                operation_name=f"Delete resource group {self._identifier}",
                timeout=AzureClient._DEFAULT_TIMEOUT)

    def get_virtual_machine_names(self) -> List[str]:
        virtual_machine_resources = self._resource_client.resources.list_by_resource_group(
            resource_group_name=self._identifier.name,
            filter="resourceType eq 'Microsoft.Compute/virtualMachines'"
        )
        return [vm.name for vm in virtual_machine_resources]

    def __str__(self):
        return f"{self._identifier}"
