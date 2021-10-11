import os
from enum import Enum, auto
from typing import List

from dotenv import load_dotenv


class VMModelType(Enum):
    VM = auto()
    VMSS = auto()


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

        vm_ips, vmss_ips = _get_ips(admin_username)
        # By default assume the test is running on a VM
        self.__type = VMModelType.VM
        self.__ips = vm_ips
        if any(vmss_ips):
            self.__type = VMModelType.VMSS
            self.__ips = vmss_ips

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


def _get_ips(username) -> (list, list):
    """
    Try fetching Ips from the files that we create via az-cli.
    We do a best effort to fetch this from both orchestrator or the test VM. Its located in different locations on both
    scenarios.
    Returns: Tuple of (VmIps, VMSSIps).
    """

    vms, vmss = [], []
    orchestrator_path = os.path.join(os.environ['BUILD_SOURCESDIRECTORY'], "dcr")
    test_vm_path = os.path.join("/home", username, "dcr")

    for ip_path in [orchestrator_path, test_vm_path]:

        vm_ip_path = os.path.join(ip_path, ".vm_ips")
        if os.path.exists(vm_ip_path):
            with open(vm_ip_path, 'r') as vm_ips:
                vms.extend(ip.strip() for ip in vm_ips.readlines())

        vmss_ip_path = os.path.join(ip_path, ".vmss_ips")
        if os.path.exists(vmss_ip_path):
            with open(vmss_ip_path, 'r') as vmss_ips:
                vmss.extend(ip.strip() for ip in vmss_ips.readlines())

    return vms, vmss


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

