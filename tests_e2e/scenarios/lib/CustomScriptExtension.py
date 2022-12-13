import uuid

from tests_e2e.scenarios.lib.BaseExtensionTestClass import BaseExtensionTestClass
from tests_e2e.scenarios.lib.models import ExtensionMetaData


class CustomScriptExtension(BaseExtensionTestClass):
    META_DATA = ExtensionMetaData(
        publisher='Microsoft.Azure.Extensions',
        ext_type='CustomScript',
        version="2.1"
    )

    def __init__(self, extension_name: str):
        extension_data = self.META_DATA
        extension_data.name = extension_name
        super().__init__(extension_data)


def add_cse():
    # Install and remove CSE
    cse = CustomScriptExtension(extension_name="testCSE")

    ext_props = [
        cse.get_ext_props(settings={'commandToExecute': f"echo \'Hello World! {uuid.uuid4()} \'"}),
        cse.get_ext_props(settings={'commandToExecute': "echo \'Hello again\'"})
    ]

    cse.run(ext_props=ext_props)