from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineExtension

from dcr.scenario_utils.models import ExtensionMetaData, VMMetaData


def _get_compute_client(sub_id) -> ComputeManagementClient:
    return ComputeManagementClient(
        credential=DefaultAzureCredential(),
        subscription_id=sub_id
    )


def _get_ext_props(location, publisher, ext_type, version, settings) -> VirtualMachineExtension:
    return VirtualMachineExtension(
        location=location,
        publisher=publisher,
        type_properties_type=ext_type,
        type_handler_version=version,
        auto_upgrade_minor_version=True,
        settings=settings
    )


class BaseExtensionTestClass:

    def __init__(self, extension_data: ExtensionMetaData, vm_data: VMMetaData):
        self.__extension_data = extension_data
        self.__vm_data = vm_data
        self.__compute_client = _get_compute_client(self.__vm_data.sub_id)

    def run(self, settings: list, remove: bool = True, continue_on_error: bool = False):
        try:
            for setting in settings:
                try:
                    ext_props = _get_ext_props(self.__vm_data.location,
                                               self.__extension_data.publisher,
                                               self.__extension_data.ext_type,
                                               self.__extension_data.version,
                                               setting)
                    extension = self.__compute_client.virtual_machine_extensions.begin_create_or_update(
                                    self.__vm_data.rg_name,
                                    self.__vm_data.name,
                                    self.__extension_data.name,
                                    ext_props
                                )

                    print("Add extension: {0}".format(extension.result(timeout=5*60)))
                except Exception as err:
                    if continue_on_error:
                        print("Ran into error but ignoring it as asked: {0}".format(err))
                        continue
                    else:
                        raise
        finally:
            # Always try to delete extensions if asked to remove even on errors
            if remove:
                deletion = self.__compute_client.virtual_machine_extensions.begin_delete(
                    self.__vm_data.rg_name,
                    self.__vm_data.name,
                    self.__extension_data.name
                ).result()
                print("Delete vm extension: {0}".format(deletion))


