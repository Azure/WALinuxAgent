import uuid

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


def add_cse(vm_data):
    # Install and remove CSE
    cse = CustomScriptExtension(extension_name="testEtpCse", vm_data=vm_data)

    ext_props = [
        cse.get_ext_props(settings={'commandToExecute': f"echo \'Hello World! {uuid.uuid4()} \'"}),
        cse.get_ext_props(settings={'commandToExecute': "echo \'Hello again\'"})
    ]

    cse.run(ext_props=ext_props)