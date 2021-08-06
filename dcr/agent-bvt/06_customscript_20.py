from dungeon_crawler.scenarios.interfaces import BaseExtensionTestClass
from tank.unique import Unique


class TestClass(BaseExtensionTestClass):

    def __init__(self, metadata):
        super(TestClass, self).__init__(metadata)

    def get_extension_tuple_list(self):
        ext_name = 'CustomScript'
        publisher = 'Microsoft.Azure.Extensions'
        ext_type = 'CustomScript'
        ext_version = '2.0'
        settings = {'commandToExecute': "echo \'Hello World! {0} \'".format(Unique.unique(5))}
        settings_2 = {'commandToExecute': "echo \'Updated ext\'"}

        ext_prop_1 = self.create_vm_extension_properties(publisher=publisher,
                                                         extension_type=ext_type,
                                                         version=ext_version,
                                                         settings=settings,
                                                         allow_auto_upgrade_minor_version=False)

        ext_prop_2 = self.create_vm_extension_properties(publisher=publisher,
                                                         extension_type=ext_type,
                                                         version=ext_version,
                                                         settings=settings_2,
                                                         allow_auto_upgrade_minor_version=False)

        return [(ext_name, ext_prop_1), (ext_name, ext_prop_2)]


