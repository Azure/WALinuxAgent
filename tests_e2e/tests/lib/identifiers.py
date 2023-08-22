# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


class VmIdentifier(object):
    def __init__(self, cloud: str, location: str, subscription: str, resource_group: str, name: str):
        """
        Represents the information that identifies a VM to the ARM APIs
        """
        self.cloud: str = cloud
        self.location = location
        self.subscription: str = subscription
        self.resource_group: str = resource_group
        self.name: str = name

    def __str__(self):
        return f"{self.resource_group}:{self.name}"


class VmExtensionIdentifier(object):
    def __init__(self, publisher: str, ext_type: str, version: str):
        """
        Represents the information that identifies an extension to the ARM APIs

            publisher - e.g. Microsoft.Azure.Extensions
            type      - e.g. CustomScript
            version   - e.g. 2.1, 2.*
            name      - arbitrary name for the extension ARM resource
        """
        self.publisher: str = publisher
        self.type: str = ext_type
        self.version: str = version

    def __str__(self):
        return f"{self.publisher}.{self.type}"


class VmExtensionIds(object):
    """
    A set of extensions used by the tests, listed here for convenience (easy to reference them by name).

    Only the major version is specified, and the minor version is set to 0 (set autoUpgradeMinorVersion to True in the call to enable
    to use the latest version)
    """
    CustomScript: VmExtensionIdentifier = VmExtensionIdentifier(publisher='Microsoft.Azure.Extensions', ext_type='CustomScript', version="2.0")
    # Older run command extension, still used by the Portal as of Dec 2022
    RunCommand: VmExtensionIdentifier = VmExtensionIdentifier(publisher='Microsoft.CPlat.Core', ext_type='RunCommandLinux', version="1.0")
    # New run command extension, with support for multi-config
    RunCommandHandler: VmExtensionIdentifier = VmExtensionIdentifier(publisher='Microsoft.CPlat.Core', ext_type='RunCommandHandlerLinux', version="1.0")
    VmAccess: VmExtensionIdentifier = VmExtensionIdentifier(publisher='Microsoft.OSTCExtensions', ext_type='VMAccessForLinux', version="1.0")
    GuestAgentDcrTestExtension: VmExtensionIdentifier = VmExtensionIdentifier(publisher='Microsoft.Azure.TestExtensions.Edp', ext_type='GuestAgentDcrTest', version='1.0')
    AzureMonitorLinuxAgent: VmExtensionIdentifier = VmExtensionIdentifier(publisher='Microsoft.Azure.Monitor', ext_type='AzureMonitorLinuxAgent', version="1.5")
    GATestExtension: VmExtensionIdentifier = VmExtensionIdentifier(publisher='Microsoft.Azure.Extensions.Edp', ext_type='GATestExtGo', version="1.2")
