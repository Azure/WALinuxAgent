def add_one_dependent_ext_without_settings():
    # Dependent extensions without settings should be enabled with dependencies
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "provisionAfterExtensions": ["CustomScript"],
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        }
    ]


def add_two_extensions_with_dependencies():
    # Checks that extensions are enabled in the correct order when there is only one valid sequence
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "provisionAfterExtensions": [],
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True
            }
        },
        {
            "name": "RunCommandLinux",
            "properties": {
                "provisionAfterExtensions": ["AzureMonitorLinuxAgent"],
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "provisionAfterExtensions": ["RunCommandLinux", "AzureMonitorLinuxAgent"],
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        }
    ]


def remove_one_dependent_extension():
    # Checks that remaining extensions with dependencies are enabled in the correct order after removing a dependent
    # extension
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "provisionAfterExtensions": ["AzureMonitorLinuxAgent"],
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        }
    ]


def remove_all_dependencies():
    # Checks that extensions are enabled after adding and removing dependencies
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True
            }
        },
        {
            "name": "RunCommandLinux",
            "properties": {
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        }
    ]


def add_one_dependent_extension():
    # Checks that a valid enable sequence occurs when only one extension has dependencies
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "provisionAfterExtensions": ["RunCommandLinux", "CustomScript"],
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True
            }
        },
        {
            "name": "RunCommandLinux",
            "properties": {
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        }
    ]


def add_single_dependencies():
    # Checks that extensions are enabled in the correct order when there is only one valid sequence and each extension
    # has no more than one dependency
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "provisionAfterExtensions": [],
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True
            }
        },
        {
            "name": "RunCommandLinux",
            "properties": {
                "provisionAfterExtensions": ["CustomScript"],
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "provisionAfterExtensions": ["AzureMonitorLinuxAgent"],
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        }
    ]


def remove_all_dependent_extensions():
    # Checks that remaining extensions with dependencies are enabled in the correct order after removing all dependent
    # extension
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True
            }
        }
    ]


def add_failing_dependent_extension_with_one_dependency():
    # This case tests that extensions dependent on a failing extensions are skipped, but extensions that are not
    # dependent on the failing extension still get enabled
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "provisionAfterExtensions": ["CustomScript"],
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        },
        {
            "name": "RunCommandLinux",
            "properties": {
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "exit 1"
                }
            }
        }
    ]


def add_failing_dependent_extension_with_two_dependencies():
    # This case tests that all extensions dependent on a failing extensions are skipped
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "provisionAfterExtensions": ["CustomScript"],
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True
            }
        },
        {
            "name": "RunCommandLinux",
            "properties": {
                "provisionAfterExtensions": ["CustomScript"],
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "exit 1"
                }
            }
        }
    ]
