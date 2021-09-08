import logging
import time
from typing import List

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineExtension
from msrestazure.azure_exceptions import CloudError

from dcr.scenario_utils.logging_utils import LoggingHandler
from dcr.scenario_utils.models import ExtensionMetaData, VMMetaData


def _get_compute_client(sub_id) -> ComputeManagementClient:
    return ComputeManagementClient(
        credential=DefaultAzureCredential(),
        subscription_id=sub_id
    )


class BaseExtensionTestClass(LoggingHandler):

    def __init__(self, extension_data: ExtensionMetaData, vm_data: VMMetaData, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__extension_data = extension_data
        self.__vm_data = vm_data
        self.__compute_client = _get_compute_client(self.__vm_data.sub_id)

    def get_ext_props(self, settings=None, protected_settings=None, auto_upgrade_minor_version=True,
                      force_update_tag=None) -> VirtualMachineExtension:
        return VirtualMachineExtension(
            location=self.__vm_data.location,
            publisher=self.__extension_data.publisher,
            type_properties_type=self.__extension_data.ext_type,
            type_handler_version=self.__extension_data.version,
            auto_upgrade_minor_version=auto_upgrade_minor_version,
            settings=settings,
            protected_settings=protected_settings,
            force_update_tag=force_update_tag
        )

    def run(self, ext_props: List[VirtualMachineExtension], remove: bool = True, continue_on_error: bool = False):
        try:
            for ext_prop in ext_props:
                try:
                    extension = self.__compute_client.virtual_machine_extensions.begin_create_or_update(
                        self.__vm_data.rg_name,
                        self.__vm_data.name,
                        self.__extension_data.name,
                        ext_prop
                    )
                    self.log.info("Add extension: {0}".format(extension.result(timeout=5*60)))

                    # Validate success from instance view
                    self.validate_ext()

                except Exception as err:
                    if continue_on_error:
                        self.log.exception("Ran into error but ignoring it as asked: {0}".format(err))
                        continue
                    else:
                        self.log.exception(f"Ran into error when trying to execute extensions: {err}")
                        raise
        finally:
            # Always try to delete extensions if asked to remove even on errors
            if remove:
                deletion = self.__compute_client.virtual_machine_extensions.begin_delete(
                    self.__vm_data.rg_name,
                    self.__vm_data.name,
                    self.__extension_data.name
                ).result()
                self.log.info("Delete vm extension: {0}".format(deletion))

    def validate_ext(self):
        """
        Validate if the extension operation was successful from the Instance View
        :raises: Exception if either unable to fetch instance view or if extension not successful
        """
        retry = 0
        max_retry = 3
        ext = None
        status = None

        while retry < max_retry:
            try:
                ext = self.get_instance_view()
                if ext is None:
                    raise Exception("Extension not found")
                elif not ext.instance_view:
                    raise Exception("Instance view not present")
                elif not ext.instance_view.statuses or len(ext.instance_view.statuses) < 1:
                    raise Exception("Instance view status not present")
                else:
                    status = ext.instance_view.statuses[0].code
                    status_message = ext.instance_view.statuses[0].message
                    self.log.info('Extension Status: \n\tCode: [{0}]\n\tMessage: {1}'.format(status, status_message))
                    break
            except Exception as err:
                self.log.exception(f"Ran into error: {err}")
                retry += 1
                if retry < max_retry:
                    self.log.info("Retrying in 30 secs")
                    time.sleep(30)
                raise

        if 'succeeded' not in status:
            raise Exception(f"Extension did not succeed. Last Instance view: {ext}")

    def get_instance_view(self) -> VirtualMachineExtension:
        max_retries = 3
        retries = max_retries
        while retries > 0:
            try:
                ext = self.__compute_client.virtual_machine_extensions.get(
                    resource_group_name=self.__vm_data.rg_name,
                    vm_name=self.__vm_data.name,
                    vm_extension_name=self.__extension_data.name,
                    expand="instanceView"
                )
                return ext
            except CloudError as ce:
                if retries > 0:
                    self.log.exception(f"Get extension error: {ce}")
                    self.log.warning("...retrying [{0} attempts remaining]".format(retries))
                    retries -= 1
                    time.sleep(30 * (max_retries - retries))
                else:
                    raise
