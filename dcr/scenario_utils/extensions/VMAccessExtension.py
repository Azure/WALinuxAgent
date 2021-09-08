import os
import sys

from dcr.scenario_utils.common_utils import random_alphanum, execute_command_and_raise_on_error
from dcr.scenario_utils.crypto import generate_ssh_key_pair
from dcr.scenario_utils.extensions.BaseExtensionTestClass import BaseExtensionTestClass
from dcr.scenario_utils.models import ExtensionMetaData, VMMetaData


class VMAccessExtension(BaseExtensionTestClass):

    def __init__(self, extension_name: str, vm_data: VMMetaData):
        extension_data = ExtensionMetaData(
            publisher='Microsoft.OSTCExtensions',
            ext_type='VMAccessForLinux',
            version="1.5",
            ext_name=extension_name
        )
        super().__init__(extension_data, vm_data)
        self.public_key, self.private_key_file = generate_ssh_key_pair('dcr_py')
        self.user_name = f'dcr{random_alphanum(length=8)}'

    def verify(self):
        os.chmod(self.private_key_file, 0o600)
        ip = os.environ['ARMDEPLOYMENTOUTPUT_HOSTNAME_VALUE']
        ssh_cmd = 'echo script was executed successfully on remote vm'

        ssh_args = ['ssh', '-o', 'StrictHostKeyChecking no', '-i',
                    self.private_key_file,
                    '{0}@{1}'.format(self.user_name, ip),
                    ssh_cmd]

        execute_command_and_raise_on_error(ssh_args, stdout=sys.stdout, stderr=sys.stderr)


def add_and_verify_vmaccess(vm_data):
    vmaccess = VMAccessExtension(extension_name="testVmAccessExt", vm_data=vm_data)
    ext_props = [
        vmaccess.get_ext_props(protected_settings={'username': vmaccess.user_name, 'ssh_key': vmaccess.public_key,
                                                   'reset_ssh': 'false'})
    ]
    vmaccess.run(ext_props=ext_props)
    vmaccess.verify()
