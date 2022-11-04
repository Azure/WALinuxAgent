import json
import os
import re
import subprocess
from enum import Enum, auto
from typing import List

from dotenv import load_dotenv


class VMModelType(Enum):
    VM = auto()
    VMSS = auto()


class ExtensionMetaData:
    def __init__(self, publisher: str, ext_type: str, version: str, ext_name: str = ""):
        self.__publisher = publisher
        self.__ext_type = ext_type
        self.__version = version
        self.__ext_name = ext_name

    @property
    def publisher(self) -> str:
        return self.__publisher

    @property
    def ext_type(self) -> str:
        return self.__ext_type

    @property
    def version(self) -> str:
        return self.__version

    @property
    def name(self):
        return self.__ext_name

    @name.setter
    def name(self, ext_name):
        self.__ext_name = ext_name

    @property
    def handler_name(self):
        return f"{self.publisher}.{self.ext_type}"


class VMMetaData:

    def __init__(self, vm_name: str, rg_name: str, sub_id: str, location: str, admin_username: str,
                 ips: List[str] = None):
        self.__vm_name = vm_name
        self.__rg_name = rg_name
        self.__sub_id = sub_id
        self.__location = location
        self.__admin_username = admin_username

        vm_ips = self._get_ips()
        # By default assume the test is running on a VM
        self.__type = VMModelType.VM
        self.__ips = vm_ips

        if ips is not None:
            self.__ips = ips

        print(f"IPs: {self.__ips}")

    @property
    def name(self) -> str:
        return self.__vm_name

    @property
    def rg_name(self) -> str:
        return self.__rg_name

    @property
    def location(self) -> str:
        return self.__location

    @property
    def sub_id(self) -> str:
        return self.__sub_id

    @property
    def admin_username(self):
        return self.__admin_username

    @property
    def ips(self) -> List[str]:
        return self.__ips

    @property
    def model_type(self):
        return self.__type

    def _get_ips(self) -> (list):
        self._az_login()

        details_text = _execute_command([
            'az', 'vm', 'show', '--show-details',
            '--subscription', self.sub_id,
            '--resource-group', self.rg_name,
            '--name', self.name
        ])
        details = json.loads(details_text)
        try:
            public_ip = details['publicIps']
        except KeyError:
            print("Can't find publicIps in vm details.\n%s", json.dumps(details, indent=2))
            raise
        # currently we support only 1 ip address; error out if that is not the case
        if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', public_ip) is None:
            print("Unexpected format for publicIps in vm details.\n%s", json.dumps(details, indent=2))
            raise Exception("Unexpected format for publicIps in vm details: {0}".format(public_ip))
        return [public_ip]

    def _az_login(self):
        if VMMetaData.__logged_in:
            return

        print("Executing [az cloud set]...")
        _execute_command(['az', 'cloud', 'set', '--name', 'AzureCloud'])

        print("Executing [az login]...")
        _execute_command([
            'az', 'login',
            '--service-principal',
            '--username', os.environ['AZURE_CLIENT_ID'],
            '--password', os.environ['AZURE_CLIENT_SECRET'],
            '--tenant', os.environ['AZURE_TENANT_ID']
        ])
        VMMetaData.__logged_in = True

    __logged_in = False


def _execute_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = process.communicate()
    stdout = bytes.decode(output[0])
    stderr = bytes.decode(output[1])
    if process.returncode != 0:
        raise Exception("Error return code {0} : {1}".format(process.returncode, stderr))
    return stdout


def get_vm_data_from_env() -> VMMetaData:
    if get_vm_data_from_env.__instance is None:
        load_dotenv()
        get_vm_data_from_env.__instance = VMMetaData(vm_name=os.environ["VMNAME"],
                                                     rg_name=os.environ['RGNAME'],
                                                     sub_id=os.environ["SUBID"],
                                                     location=os.environ['LOCATION'],
                                                     admin_username=os.environ['ADMINUSERNAME'])

    return get_vm_data_from_env.__instance


get_vm_data_from_env.__instance = None
