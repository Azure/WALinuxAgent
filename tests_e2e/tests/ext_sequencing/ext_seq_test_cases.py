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
                "settings": {}
            }
        }
    ]


def add_two_extensions_with_dependencies():
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True,
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
                "settings": {}
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
                "settings": {}
            }
        }
    ]


def remove_one_dependent_extension():
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True,
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
                "settings": {}
            }
        }
    ]


def remove_all_dependencies():
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True,
            }
        },
        {
            "name": "RunCommandLinux",
            "properties": {
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        }
    ]


def add_one_dependent_extension():
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "provisionAfterExtensions": ["RunCommandLinux", "CustomScript"],
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True,
            }
        },
        {
            "name": "RunCommandLinux",
            "properties": {
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        }
    ]


def add_single_dependencies():
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True,
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
                "settings": {}
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
                "settings": {}
            }
        }
    ]


def remove_all_dependent_extensions():
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True,
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
            }
        },
        {
            "name": "RunCommandLinux",
            "properties": {
                "publisher": "Microsoft.CPlat.Core",
                "type": "RunCommandLinux",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {}
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
                    # script contents are base-64 encoded:
                    # #!/bin/bash
                    #
                    # echo "Exit script with non-zero exit code"
                    # exit 1
                    "script": "IyEvYmluL2Jhc2gKCmVjaG8gIkV4aXQgc2NyaXB0IHdpdGggbm9uLXplcm8gZXhpdCBjb2RlIgpleGl0IDEK"
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
                "autoUpgradeMinorVersion": True,
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
                "settings": {}
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
                    # script contents are base-64 encoded:
                    # #!/bin/bash
                    #
                    # echo "Exit script with non-zero exit code"
                    # exit 2
                    "script": "IyEvYmluL2Jhc2gKCmVjaG8gIkV4aXQgc2NyaXB0IHdpdGggbm9uLXplcm8gZXhpdCBjb2RlIgpleGl0IDIK"
                }
            }
        }
    ]
