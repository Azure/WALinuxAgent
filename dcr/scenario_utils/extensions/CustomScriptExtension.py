import uuid

from dcr.scenario_utils.extensions.BaseExtensionTestClass import BaseExtensionTestClass
from dcr.scenario_utils.models import ExtensionMetaData


class CustomScriptExtension(BaseExtensionTestClass):
    def __init__(self, extension_name: str):
        extension_data = ExtensionMetaData(
            publisher='Microsoft.Azure.Extensions',
            ext_type='CustomScript',
            version="2.1",
            ext_name=extension_name
        )
        super().__init__(extension_data)


def add_cse():
    # Install and remove CSE
    cse = CustomScriptExtension(extension_name="testCSE")

    ext_props = [
        cse.get_ext_props(settings={'commandToExecute': f"echo \'Hello World! {uuid.uuid4()} \'"}),
        cse.get_ext_props(settings={'commandToExecute': "echo \'Hello again\'"})
    ]

    cse.run(ext_props=ext_props)