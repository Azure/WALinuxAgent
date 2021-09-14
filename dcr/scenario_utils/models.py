import os
from typing import List


class ExtensionMetaData:
    def __init__(self, publisher: str, ext_type: str, version: str, ext_name: str):
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
    def name(self) -> str:
        return self.__ext_name


class VMMetaData:

    def __init__(self, vm_name: str, rg_name: str, sub_id: str, location: str, admin_username: str,
                 ips: List[str] = None):
        self.__vm_name = vm_name
        self.__rg_name = rg_name
        self.__sub_id = sub_id
        self.__location = location
        self.__admin_username = admin_username
        if ips is None:
            ips = _get_ips()
        self.__ips = ips

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


def _get_ips() -> list:

    if os.path.exists(f"{os.environ['BUILD_SOURCESDIRECTORY']}/dcr/.vm_ips"):
        with open(f"{os.environ['BUILD_SOURCESDIRECTORY']}/dcr/.vm_ips", 'r') as vm_ips:
            vms = [ip.strip() for ip in vm_ips.readlines()]

    if os.path.exists(f"{os.environ['BUILD_SOURCESDIRECTORY']}/dcr/.vmss_ips"):
        with open(f"{os.environ['BUILD_SOURCESDIRECTORY']}/dcr/.vmss_ips", 'r') as vmss_ips:
            vmss = [ip.strip() for ip in vmss_ips.readlines()]

    return vms + vmss


def get_vm_data_from_env() -> VMMetaData:
    if get_vm_data_from_env.__instance is None:
        get_vm_data_from_env.__instance = VMMetaData(vm_name=os.environ["VMNAME"],
                                                     rg_name=os.environ['RGNAME'],
                                                     sub_id=os.environ["SUBID"],
                                                     location=os.environ['LOCATION'],
                                                     admin_username=os.environ['ADMINUSERNAME'])

    return get_vm_data_from_env.__instance


get_vm_data_from_env.__instance = None

