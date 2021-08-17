import os

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineExtension

__CSE_PUBLISHER = 'Microsoft.Azure.Extensions'
__CSE_TYPE = 'CustomScript'
__CSE_VERSION = "2.0"


def __get_props(location, script):
    extension_props = VirtualMachineExtension(
        location=location,
        publisher=__CSE_PUBLISHER,
        virtual_machine_extension_type=__CSE_TYPE,
        type_handler_version=__CSE_VERSION,
        auto_upgrade_minor_version=True,
        settings={
            'commandToExecute': script
        }
    )
    return extension_props


def add_cse(compute_client, rg_name, vm_name, extension_name, location):
    # Create vm extension
    extension = compute_client.virtual_machine_extensions.begin_create_or_update(
        rg_name,
        vm_name,
        extension_name,
        __get_props(location, "echo \'Hello World!\'")
    )
    
    print("Add extension: {0}".format(extension.result(timeout=5*60)))


def update_cse(compute_client, rg_name, vm_name, extension_name, location):
    extension = compute_client.virtual_machine_extensions.begin_update(
        rg_name,
        vm_name,
        extension_name,
        __get_props(location, "echo 'Yolo Word!'")
    ).result()
    print("Update vm extension: {0}".format(extension))


def delete_cse(compute_client, rg_name, vm_name, extension_name):
    deletion = compute_client.virtual_machine_extensions.begin_delete(
        rg_name,
        vm_name,
        extension_name
    ).result()
    print("Delete vm extension: {0}".format(deletion))


def execute_cse_tests():

    rg_name = "{0}-{1}-{2}".format(os.environ['RGNAME'], os.environ['SCENARIONAME'], os.environ['DISTRONAME'])
    vm_name = os.environ['VMNAME']
    extension_name = "testCse"
    location = os.environ['LOCATION']

    compute_client = ComputeManagementClient(
        credentials=DefaultAzureCredential(),
        subscription_id=os.environ["SUBID"]
    )
    
    add_cse(compute_client, rg_name, vm_name, extension_name, location)
    update_cse(compute_client, rg_name, vm_name, extension_name, location)
    delete_cse(compute_client, rg_name, vm_name, extension_name)
