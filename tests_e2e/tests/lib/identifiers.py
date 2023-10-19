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

from typing import Dict, List


class VmExtensionIdentifier(object):
    """
    Represents the information that identifies an extension to the ARM APIs

        publisher - e.g. Microsoft.Azure.Extensions
        type      - e.g. CustomScript
        version   - e.g. 2.1, 2.*
        name      - arbitrary name for the extension ARM resource
    """
    def __init__(self, publisher: str, ext_type: str, version: str):
        self.publisher: str = publisher
        self.type: str = ext_type
        self.version: str = version

    unsupported_distros: Dict[str, List[str]] = {
        "Microsoft.OSTCExtensions.VMAccessForLinux": ["flatcar"]
    }

    def supports_distro(self, system_info: str) -> bool:
        """
        Returns true if an unsupported distro name for the extension is found in the provided system info
        """
        ext_unsupported_distros = VmExtensionIdentifier.unsupported_distros.get(self.publisher + "." + self.type)
        if ext_unsupported_distros is not None and any(distro in system_info for distro in ext_unsupported_distros):
            return False
        return True

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
