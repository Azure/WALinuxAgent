

from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds, VmExtensionIdentifier
import uuid


def __get_extension_template(extension_id: VmExtensionIdentifier, depends_on=None):
    template = {
            "name": extension_id.type,
            "properties": {
                "provisionAfterExtensions": depends_on,
                "publisher": extension_id.publisher,
                "type": extension_id.type,
                "typeHandlerVersion": extension_id.version,
                "autoUpgradeMinorVersion": True
            }
        }

    if depends_on is not None and len(depends_on) > 0:
        template["properties"]["provisionAfterExtensions"] = depends_on

    # Update template properties for each extension type
    if extension_id == VmExtensionIds.AzureMonitorLinuxAgent:
        # For compliance with S360, enable automatic upgrade for AzureMonitorLinuxAgent
        template["properties"]["enableAutomaticUpgrade"] = True
    elif extension_id == VmExtensionIds.CustomScript:
        template["properties"]["settings"] = {"commandToExecute": "date"}
        template["properties"]["protectedSettings"] = {}
    elif extension_id == VmExtensionIds.RunCommandHandler:
        # Each time, we generate a RunCommand template with different settings
        unique = str(uuid.uuid4())
        test_file = f"waagent-test.{unique}"
        unique_command = f"echo '{unique}' > /tmp/{test_file}"
        template["properties"]["settings"] = {"commandToExecute": unique_command}
    elif extension_id == VmExtensionIds.VmAccess:
        template["properties"]["settings"] = {}
        template["properties"]["protectedSettings"] = {"username": "testuser"}
    else:
        raise ValueError("invalid value '{0}' for 'extension_id'".format(extension_id))

    return template


def _should_fail_single_config_depends_on_disallowed_single_config():
    template = [
        __get_extension_template(VmExtensionIds.VmAccess),
        __get_extension_template(VmExtensionIds.CustomScript, depends_on=["VMAccessForLinux"])
    ]
    policy = \
        {
            "policyVersion": "0.1.0",
            "extensionPolicies": {
                "allowListedExtensionsOnly": True,
                "extensions": {
                    "Microsoft.Azure.Extensions.CustomScript": {},
                    # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                    "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                }
            }
        }
    expected_errors = [
        "Extension will not be processed: failed to run extension 'Microsoft.OSTCExtensions.VMAccessForLinux' because it is not specified as an allowed extension",
        "'CustomScript' is marked as failed since it depends upon the VM Extension 'VMAccessForLinux' which has failed"
    ]
    deletion_order = [VmExtensionIds.CustomScript, VmExtensionIds.VmAccess]
    return policy, template, expected_errors, deletion_order


def _should_fail_single_config_depends_on_disallowed_no_config():
    template = [
        __get_extension_template(VmExtensionIds.AzureMonitorLinuxAgent),
        __get_extension_template(VmExtensionIds.CustomScript, depends_on=["AzureMonitorLinuxAgent"])
    ]
    policy = \
        {
            "policyVersion": "0.1.0",
            "extensionPolicies": {
                "allowListedExtensionsOnly": True,
                "extensions": {
                    "Microsoft.Azure.Extensions.CustomScript": {},
                    # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                    "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                }
            }
        }
    expected_errors = [
        "Extension will not be processed: failed to run extension 'Microsoft.Azure.Monitor.AzureMonitorLinuxAgent' because it is not specified as an allowed extension",
        "'CustomScript' is marked as failed since it depends upon the VM Extension 'AzureMonitorLinuxAgent' which has failed"
    ]
    deletion_order = [VmExtensionIds.CustomScript, VmExtensionIds.AzureMonitorLinuxAgent]
    return policy, template, expected_errors, deletion_order


def _should_fail_single_config_depends_on_disallowed_multi_config():
    template = [
        __get_extension_template(VmExtensionIds.RunCommandHandler),
        __get_extension_template(VmExtensionIds.CustomScript, depends_on=["RunCommandHandlerLinux"])
    ]
    policy = \
        {
            "policyVersion": "0.1.0",
            "extensionPolicies": {
                "allowListedExtensionsOnly": True,
                "extensions": {
                    "Microsoft.Azure.Extensions.CustomScript": {},
                    # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                    "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                }
            }
        }
    expected_errors = [
        "Extension will not be processed: failed to run extension 'Microsoft.CPlat.Core.RunCommandHandlerLinux' because it is not specified as an allowed extension",
        "'CustomScript' is marked as failed since it depends upon the VM Extension 'RunCommandHandlerLinux' which has failed"
    ]
    deletion_order = [VmExtensionIds.CustomScript, VmExtensionIds.RunCommandHandler]
    return policy, template, expected_errors, deletion_order


def _should_fail_multi_config_depends_on_disallowed_single_config():
    template = [
        __get_extension_template(VmExtensionIds.CustomScript),
        __get_extension_template(VmExtensionIds.RunCommandHandler, depends_on=["CustomScript"])
    ]
    policy = \
        {
            "policyVersion": "0.1.0",
            "extensionPolicies": {
                "allowListedExtensionsOnly": True,
                "extensions": {
                    "Microsoft.CPlat.Core.RunCommandHandlerLinux": {},
                    # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                    "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                }
            }
        }
    expected_errors = [
        "Extension will not be processed: failed to run extension 'Microsoft.Azure.Extensions.CustomScript' because it is not specified as an allowed extension",
        "VM has reported a failure when processing extension 'RunCommandHandlerLinux' (publisher 'Microsoft.CPlat.Core' and type 'RunCommandHandlerLinux'). Error message: 'Skipping processing of extensions since execution of dependent extension Microsoft.Azure.Extensions.CustomScript failed'."
    ]
    deletion_order = [VmExtensionIds.RunCommandHandler, VmExtensionIds.CustomScript]
    return policy, template, expected_errors, deletion_order


def _should_fail_multi_config_depends_on_disallowed_no_config():
    template = [
        __get_extension_template(VmExtensionIds.AzureMonitorLinuxAgent),
        __get_extension_template(VmExtensionIds.RunCommandHandler, depends_on=["AzureMonitorLinuxAgent"])
    ]
    policy = \
        {
            "policyVersion": "0.1.0",
            "extensionPolicies": {
                "allowListedExtensionsOnly": True,
                "extensions": {
                    "Microsoft.CPlat.Core.RunCommandHandlerLinux": {},
                    # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                    "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                }
            }
        }
    expected_errors = [
        "Extension will not be processed: failed to run extension 'Microsoft.Azure.Monitor.AzureMonitorLinuxAgent' because it is not specified as an allowed extension",
        "VM has reported a failure when processing extension 'RunCommandHandlerLinux' (publisher 'Microsoft.CPlat.Core' and type 'RunCommandHandlerLinux'). Error message: 'Skipping processing of extensions since execution of dependent extension Microsoft.Azure.Monitor.AzureMonitorLinuxAgent failed'."
    ]
    deletion_order = [VmExtensionIds.RunCommandHandler, VmExtensionIds.AzureMonitorLinuxAgent]
    return policy, template, expected_errors, deletion_order


def _should_succeed_single_config_depends_on_no_config():
    template = [
        __get_extension_template(VmExtensionIds.AzureMonitorLinuxAgent),
        __get_extension_template(VmExtensionIds.CustomScript, depends_on=["AzureMonitorLinuxAgent"])

    ]
    policy = \
        {
            "policyVersion": "0.1.0",
            "extensionPolicies": {
                "allowListedExtensionsOnly": True,
                "extensions": {
                    "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent": {},
                    "Microsoft.Azure.Extensions.CustomScript": {},
                    # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                    "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                }
            }
        }
    expected_errors = []
    deletion_order = [VmExtensionIds.CustomScript, VmExtensionIds.AzureMonitorLinuxAgent]
    return policy, template, expected_errors, deletion_order


def _should_succeed_single_config_depends_on_single_config():
    template = [
        __get_extension_template(VmExtensionIds.CustomScript),
        __get_extension_template(VmExtensionIds.VmAccess, depends_on=["CustomScript"])
    ]
    policy = \
        {
            "policyVersion": "0.1.0",
            "extensionPolicies": {
                "allowListedExtensionsOnly": True,
                "extensions": {
                    "Microsoft.Azure.Extensions.CustomScript": {},
                    "Microsoft.OSTCExtensions.VMAccessForLinux": {},
                    # GuestConfiguration is added to all VMs for security requirements, so we always allow it.
                    "Microsoft.GuestConfiguration.ConfigurationforLinux": {}
                }
            }
        }
    expected_errors = []
    deletion_order = [VmExtensionIds.VmAccess, VmExtensionIds.CustomScript]
    return policy, template, expected_errors, deletion_order