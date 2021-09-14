import asyncio
import os

from dcr.scenario_utils.common_utils import random_alphanum, execute_commands_concurrently_on_test_vms
from dcr.scenario_utils.crypto import generate_ssh_key_pair
from dcr.scenario_utils.extensions.BaseExtensionTestClass import BaseExtensionTestClass
from dcr.scenario_utils.models import ExtensionMetaData


class VMAccessExtension(BaseExtensionTestClass):

    def __init__(self, extension_name: str):
        extension_data = ExtensionMetaData(
            publisher='Microsoft.OSTCExtensions',
            ext_type='VMAccessForLinux',
            version="1.5",
            ext_name=extension_name
        )
        super().__init__(extension_data)
        self.public_key, self.private_key_file = generate_ssh_key_pair('dcr_py')
        self.user_name = f'dcr{random_alphanum(length=8)}'

    def verify(self):
        os.chmod(self.private_key_file, 0o600)
        ssh_cmd = f'ssh -o StrictHostKeyChecking=no -i {self.private_key_file} {self.user_name}@{{ip}} ' \
                  f'"echo script was executed successfully on remote vm"'
        print(asyncio.run(execute_commands_concurrently_on_test_vms([ssh_cmd])))


def add_and_verify_vmaccess():
    vmaccess = VMAccessExtension(extension_name="testVmAccessExt")
    ext_props = [
        vmaccess.get_ext_props(protected_settings={'username': vmaccess.user_name, 'ssh_key': vmaccess.public_key,
                                                   'reset_ssh': 'false'})
    ]
    vmaccess.run(ext_props=ext_props)
    vmaccess.verify()
