import re
import uuid
from datetime import datetime
from time import sleep

from azure.mgmt.resource.resources.models import DeploymentMode, DeploymentProperties, Deployment
from msrestazure.azure_exceptions import CloudError

from dcr.scenario_utils.azure_models import ComputeManager
from dcr.scenario_utils.logging_utils import LoggingHandler
from dcr.scenario_utils.models import get_vm_data_from_env


class ExtensionSequencingTestClass(LoggingHandler):

    # This is the base ARM template that's used for deploying extensions for this scenario. These templates build on
    # top of each other. i.e., 01_test runs first, then 02_test builds on top of it and so on and so forth.
    extension_template = {
        "$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": "Microsoft.Compute/virtualMachineScaleSets",
                "name": "",
                "location": "[resourceGroup().location]",
                "apiVersion": "2018-06-01",
                "properties": {
                    "virtualMachineProfile": {
                        "extensionProfile": {
                            "extensions": []
                        }
                    }
                }
            }
        ]
    }

    def __init__(self):
        super().__init__()
        self.__vm_data = get_vm_data_from_env()
        self.__compute_manager = ComputeManager().compute_manager

        # Update the VMSS name
        ExtensionSequencingTestClass.extension_template['resources'][0]['name'] = self.__vm_data.name

    def deploy_extensions(self, ext_json):
        self.log.info(f"Deploying extension template: {ext_json}")

        retry = 0
        max_retry = 5
        while retry < max_retry:
            try:
                props = DeploymentProperties(template=ext_json,
                                             mode=DeploymentMode.incremental)
                poller = self.__compute_manager.resource_client.deployments.begin_create_or_update(
                    self.__vm_data.rg_name, 'TestDeployment', Deployment(properties=props))
                # Wait a max of 10 mins
                poller.wait(timeout=10 * 60)
                if poller.done():
                    break
                else:
                    raise TimeoutError("Extension deployment timed out after 10 mins")
            except CloudError as ce:
                self.log.warning(f"Cloud Error: {ce}", exc_info=True)
                retry += 1
                err_msg = str(ce)
                if "'code': 'Conflict'" in err_msg and retry < max_retry:
                    self.log.warning(
                        "({0}/{1}) Conflict Error when deploying extension in VMSS, trying again in 1 sec (Error: {2})".format(
                            retry, max_retry, ce))
                    # Since this was a conflicting operation, sleeping for a second before retrying
                    sleep(1)
                else:
                    raise

        self.log.info("Successfully deployed extensions")

    @staticmethod
    def get_dependency_map(ext_json) -> dict:
        dependency_map = dict()

        vmss = ext_json['resources'][0]
        extensions = vmss['properties']['virtualMachineProfile']['extensionProfile']['extensions']

        for ext in extensions:
            ext_name = ext['name']
            provisioned_after = ext['properties'].get('provisionAfterExtensions')
            dependency_map[ext_name] = provisioned_after

        return dependency_map

    @staticmethod
    def __get_time(ext, test_guid):
        if ext.statuses[0].time is not None:
            # This is populated if `configurationAppliedTime` is provided in the status file of extension
            return ext.statuses[0].time

        if ext.statuses[0].message is not None:
            # In our tests, for CSE and RunCommand, we would execute this command to get the time when it was enabled -
            # echo 'GUID: $(date +%Y-%m-%dT%H:%M:%S.%3NZ)'
            match = re.search(r"{0}: ([\d-]+T[\d:.]+Z)".format(test_guid), ext.statuses[0].message)
            if match is not None:
                return datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")

        # If nothing else works, just return the minimum datetime
        return datetime.min
    
    def get_sorted_extension_names(self, test_guid):
        # Retrieve the VMSS extension instances
        vmss_vm_extensions = self.__compute_manager.get_vm_instance_view().extensions
        
        # Log the extension enabled datetime
        for ext in vmss_vm_extensions:
            ext.time = self.__get_time(ext, test_guid)
            self.log.info("Extension {0} Status: {1}".format(ext.name, ext.statuses[0]))
        
        # sort the extensions based on their enabled datetime
        sorted_extensions = sorted(vmss_vm_extensions, key=lambda ext_: ext_.time)
        self.log.info("Sorted extension names with time: {0}".format(
            ', '.join(["{0}: {1}".format(ext.name, ext.time) for ext in sorted_extensions])))
        return [ext.name for ext in sorted_extensions]

    def validate_extension_sequencing(self, dependency_map, sorted_extension_names):
        installed_ext = dict()

        # Iterate through the extensions in the enabled order and validate if their depending
        # extensions are already enabled prior to that.
        for ext in sorted_extension_names:
            # Check if the depending extension are already installed
            if ext not in dependency_map:
                # Some extensions might be installed by policy, continue in this case
                self.log.info("Unwanted extension found in Instance view: {0}".format(ext))
                continue
            if dependency_map[ext] is not None:
                for dep in dependency_map[ext]:
                    if installed_ext.get(dep) is None:
                        # The depending extension is not installed prior to the current extension
                        raise Exception("{0} is not installed prior to {1}".format(dep, ext))

            # Mark the current extension as installed
            installed_ext[ext] = ext
        
        self.log.info("Validated extension sequencing")
    
    def run(self, extension_template):

        # Update the settings for each extension to make sure they're always unique to force CRP to generate a new
        # sequence number each time
        ext_json = ExtensionSequencingTestClass.extension_template.copy()
        test_guid = str(uuid.uuid4())
        for ext in extension_template:
            ext["properties"]["settings"].update({
                "commandToExecute": "echo \"{0}: $(date +%Y-%m-%dT%H:%M:%S.%3NZ)\"".format(test_guid)
            })

        # We update the extensions here, they are specific to the scenario that we want to test out (01_test, 02_test..)
        ext_json['resources'][0]['properties']['virtualMachineProfile']['extensionProfile'][
            'extensions'] = extension_template

        # Deploy VMSS extensions with sequence
        self.deploy_extensions(ext_json)

        # Build the dependency map from the list of extensions in the extension profile
        dependency_map = self.get_dependency_map(ext_json)
        self.log.info("Dependency map: {0}".format(dependency_map))

        # Get the extensions sorted based on their enabled datetime
        sorted_extension_names = self.get_sorted_extension_names(test_guid)
        self.log.info("Sorted extensions: {0}".format(sorted_extension_names))

        self.validate_extension_sequencing(dependency_map, sorted_extension_names)
