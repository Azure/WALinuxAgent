import uuid

from dcr.scenario_utils.extensions.BaseExtensionTestClass import BaseExtensionTestClass
from dcr.scenario_utils.models import ExtensionMetaData


class RunCommandExtension(BaseExtensionTestClass):
    def __init__(self, extension_name: str):
        extension_data = ExtensionMetaData(
            publisher='Microsoft.CPlat.Core',
            ext_type='RunCommandLinux',
            version="1.0",
            ext_name=extension_name
        )
        super().__init__(extension_data)


def add_rc():
    # Install and remove RC
    rc = RunCommandExtension(extension_name="testRC")

    ext_props = [
        rc.get_ext_props(settings={'commandToExecute': f"echo \'Hello World! {uuid.uuid4()} \'"}),
        rc.get_ext_props(settings={'commandToExecute': "echo \'Hello again\'"})
    ]

    rc.run(ext_props=ext_props)
