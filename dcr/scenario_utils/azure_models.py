import time
from abc import ABC, abstractmethod

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import VirtualMachineExtension, VirtualMachineScaleSetExtension, \
    VirtualMachineInstanceView, VirtualMachineScaleSetInstanceView, VirtualMachineExtensionInstanceView
from azure.mgmt.resource import ResourceManagementClient
from msrestazure.azure_exceptions import CloudError

from dcr.scenario_utils.logging_utils import LoggingHandler
from dcr.scenario_utils.models import get_vm_data_from_env, VMModelType, VMMetaData


class AzureComputeBaseClass(ABC, LoggingHandler):

    def __init__(self):
        super().__init__()
        self.__vm_data = get_vm_data_from_env()
        self.__compute_client = None
        self.__resource_client = None

    @property
    def vm_data(self) -> VMMetaData:
        return self.__vm_data

    @property
    def compute_client(self) -> ComputeManagementClient:
        if self.__compute_client is None:
            self.__compute_client = ComputeManagementClient(
                credential=DefaultAzureCredential(),
                subscription_id=self.vm_data.sub_id
            )
        return self.__compute_client

    @property
    def resource_client(self) -> ResourceManagementClient:
        if self.__resource_client is None:
            self.__resource_client = ResourceManagementClient(
                credential=DefaultAzureCredential(),
                subscription_id=self.vm_data.sub_id
            )
        return self.__resource_client

    @property
    @abstractmethod
    def vm_func(self):
        pass

    @property
    @abstractmethod
    def extension_func(self):
        pass

    @abstractmethod
    def get_vm_instance_view(self):
        pass

    @abstractmethod
    def get_extension_instance_view(self, extension_name):
        pass

    @abstractmethod
    def get_ext_props(self, extension_data, settings=None, protected_settings=None, auto_upgrade_minor_version=True,
                      force_update_tag=None):
        pass

    def _get_instance_view_with_retry(self, get_func):
        max_retries = 3
        retries = max_retries
        while retries > 0:
            try:
                ext = get_func()
                return ext
            except CloudError as ce:
                if retries > 0:
                    self.log.exception(f"Got Azure error: {ce}")
                    self.log.warning("...retrying [{0} attempts remaining]".format(retries))
                    retries -= 1
                    time.sleep(30 * (max_retries - retries))
                else:
                    raise


class VirtualMachineHelper(AzureComputeBaseClass):

    def __init__(self):
        super().__init__()

    @property
    def vm_func(self):
        return self.compute_client.virtual_machines

    @property
    def extension_func(self):
        return self.compute_client.virtual_machine_extensions

    def get_vm_instance_view(self) -> VirtualMachineInstanceView:
        return self._get_instance_view_with_retry(lambda: self.vm_func.get(
            resource_group_name=self.__vm_data.rg_name,
            vm_name=self.__vm_data.name,
            expand="instanceView"
        ))

    def get_extension_instance_view(self, extension_name) -> VirtualMachineExtensionInstanceView:
        return self._get_instance_view_with_retry(lambda: self.extension_func.get(
            resource_group_name=self.__vm_data.rg_name,
            vm_name=self.__vm_data.name,
            vm_extension_name=extension_name,
            expand="instanceView"
        ))

    def get_ext_props(self, extension_data, settings=None, protected_settings=None, auto_upgrade_minor_version=True,
                      force_update_tag=None) -> VirtualMachineExtension:
        return VirtualMachineExtension(
            location=self.__vm_data.location,
            publisher=extension_data.publisher,
            type_properties_type=extension_data.ext_type,
            type_handler_version=extension_data.version,
            auto_upgrade_minor_version=auto_upgrade_minor_version,
            settings=settings,
            protected_settings=protected_settings,
            force_update_tag=force_update_tag
        )


class VirtualMachineScaleSetHelper(AzureComputeBaseClass):

    def __init__(self):
        super().__init__()

    @property
    def vm_func(self):
        return self.compute_client.virtual_machine_scale_sets

    @property
    def extension_func(self):
        return self.compute_client.virtual_machine_scale_set_extensions

    def get_vm_instance_view(self) -> VirtualMachineScaleSetInstanceView:
        return self._get_instance_view_with_retry(lambda: self.vm_func.get(
            resource_group_name=self.__vm_data.rg_name,
            vm_scale_set_name=self.__vm_data.name,
            expand="instanceView"
        ))

    def get_extension_instance_view(self, extension_name) -> VirtualMachineExtensionInstanceView:
        return self._get_instance_view_with_retry(lambda: self.extension_func.get(
            resource_group_name=self.__vm_data.rg_name,
            vm_scale_set_name=self.__vm_data.name,
            vmss_extension_name=extension_name,
            expand="instanceView"
        ))

    def get_ext_props(self, extension_data, settings=None, protected_settings=None, auto_upgrade_minor_version=True,
                      force_update_tag=None) -> VirtualMachineScaleSetExtension:
        return VirtualMachineScaleSetExtension(
            publisher=extension_data.publisher,
            type_properties_type=extension_data.ext_type,
            type_handler_version=extension_data.version,
            auto_upgrade_minor_version=auto_upgrade_minor_version,
            settings=settings,
            protected_settings=protected_settings
        )


class ComputeManager:
    def __init__(self):
        self.__vm_data = get_vm_data_from_env()
        self.__compute_manager = None

    @property
    def is_vm(self) -> bool:
        return self.__vm_data.model_type == VMModelType.VM

    @property
    def compute_manager(self):
        if self.__compute_manager is None:
            self.__compute_manager = VirtualMachineHelper() if self.is_vm else VirtualMachineScaleSetHelper()
        return self.__compute_manager
