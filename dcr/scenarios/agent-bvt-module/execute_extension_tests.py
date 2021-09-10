import os

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineExtension

__CSE_PUBLISHER = 'Microsoft.Azure.Extensions'
__CSE_TYPE = 'CustomScript'
__CSE_VERSION = "2.1"


def __get_ext_props(location, publisher, ext_type, version, settings):
    return VirtualMachineExtension(
        location=location,
        publisher=publisher,
        type_properties_type=ext_type,
        type_handler_version=version,
        auto_upgrade_minor_version=True,
        settings=settings
    )


def __get_cse_props(location, script):
    settings = {
            'commandToExecute': script
        }
    return __get_ext_props(location, __CSE_PUBLISHER, __CSE_TYPE, __CSE_VERSION, settings)


def add_cse(compute_client, rg_name, vm_name, extension_name, location):
    # Create vm extension
    extension = compute_client.virtual_machine_extensions.begin_create_or_update(
        rg_name,
        vm_name,
        extension_name,
        __get_cse_props(location, "echo \'Hello World!\'")
    )
    
    print("Add extension: {0}".format(extension.result(timeout=5*60)))


def update_cse(compute_client, rg_name, vm_name, extension_name, location):
    extension = compute_client.virtual_machine_extensions.begin_update(
        rg_name,
        vm_name,
        extension_name,
        __get_cse_props(location, "echo 'Yolo Word!'")
    ).result()
    print("Update vm extension: {0}".format(extension))


def delete_cse(compute_client, rg_name, vm_name, extension_name):
    deletion = compute_client.virtual_machine_extensions.begin_delete(
        rg_name,
        vm_name,
        extension_name
    ).result()
    print("Delete vm extension: {0}".format(deletion))


def __get_compute_client():
    return ComputeManagementClient(
        credential=DefaultAzureCredential(),
        subscription_id=os.environ["SUBID"]
    )


def execute_cse_tests():

    rg_name = os.environ['RGNAME']
    vm_name = os.environ['VMNAME']
    extension_name = "testCse"
    location = os.environ['LOCATION']

    compute_client = __get_compute_client()
    
    add_cse(compute_client, rg_name, vm_name, extension_name, location)
    update_cse(compute_client, rg_name, vm_name, extension_name, location)
    delete_cse(compute_client, rg_name, vm_name, extension_name)
    return "Successfully executed CSE"


# def execute_vmaccess_tests():
