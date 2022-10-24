from typing import List

from azure.mgmt.compute.models import VirtualMachineExtension

from dcr.scenario_utils.extensions.BaseExtensionTestClass import BaseExtensionTestClass
from dcr.scenario_utils.models import ExtensionMetaData


class GATestExtGoExtension(BaseExtensionTestClass):
    def __init__(self, extension_name: str):
        extension_data = ExtensionMetaData(
            publisher='Microsoft.Azure.Extensions.Edp',
            ext_type='GATestExtGo',
            version="1.0",
            ext_name=extension_name
        )
        super().__init__(extension_data)

    def run(self, ext_props: List[VirtualMachineExtension], remove: bool = True, continue_on_error: bool = False):
        for ext_prop in ext_props:
            if 'name' not in ext_prop.settings:
                # GATestExtGo expects name to always be there, making sure we send it always
                ext_prop.settings['name'] = "Enabling GA Test Extension"

        super().run(ext_props, remove, continue_on_error)

