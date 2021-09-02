from dcr.scenario_utils.extensions.BaseExtensionTestClass import BaseExtensionTestClass
from dcr.scenario_utils.models import ExtensionMetaData, VMMetaData


class CustomScriptExtension(BaseExtensionTestClass):
    def __init__(self, extension_name: str, vm_data: VMMetaData):
        extension_data = ExtensionMetaData(
            publisher='Microsoft.Azure.Extensions',
            ext_type='CustomScript',
            version="2.1",
            ext_name=extension_name
        )
        super().__init__(extension_data, vm_data)

