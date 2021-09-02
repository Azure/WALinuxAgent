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
    def __init__(self, vm_name: str, rg_name: str, sub_id: str, location: str):
        self.__vm_name = vm_name
        self.__rg_name = rg_name
        self.__sub_id = sub_id
        self.__location = location

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
