def add_extensions_with_dependency_template():
    return [
        {
            "name": "GATestExt",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions.Edp",
                "type": "GATestExtGo",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "name": "Enabling GA Test Extension"
                }
            }
        },
        {
            "name": "RunCommand",
            "properties": {
                "provisionAfterExtensions": ["GATestExt"],
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        },
        {
            "name": "CSE",
            "properties": {
                "provisionAfterExtensions": ["RunCommand", "GATestExt"],
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        }
    ]


def remove_dependent_extension_template():
    return [
        {
            "name": "GATestExt",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions.Edp",
                "type": "GATestExtGo",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "name": "Enabling GA Test Extension"
                }
            }
        },
        {
            "name": "CSE",
            "properties": {
                "provisionAfterExtensions": ["GATestExt"],
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        }
    ]


def remove_all_dependencies_template():
    return [
        {
            "name": "GATestExt",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions.Edp",
                "type": "GATestExtGo",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "name": "Enabling GA Test Extension"
                }
            }
        },
        {
            "name": "RunCommand",
            "properties": {
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        },
        {
            "name": "CSE",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        }
    ]


def add_more_dependencies_template():
    return [
        {
            "name": "GATestExt",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions.Edp",
                "type": "GATestExtGo",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "name": "Enabling GA Test Extension"
                }
            }
        },
        {
            "name": "RunCommand",
            "properties": {
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        },
        {
            "name": "CSE",
            "properties": {
                "provisionAfterExtensions": ["RunCommand", "GATestExt"],
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        }
    ]


def single_dependencies_template():
    return [
        {
            "name": "GATestExt",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions.Edp",
                "type": "GATestExtGo",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "name": "Enabling GA Test Extension"
                }
            }
        },
        {
            "name": "RunCommand",
            "properties": {
                "provisionAfterExtensions": ["CSE"],
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        },
        {
            "name": "CSE",
            "properties": {
                "provisionAfterExtensions": ["GATestExt"],
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        }
    ]


def delete_extensions_template():
    return [
        {
            "name": "GATestExt",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions.Edp",
                "type": "GATestExtGo",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "name": "Enabling GA Test Extension"
                }
            }
        }
    ]
