# Compose Content for: L3-flows/distro-deprovision-workflows.md

Total files: 4

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction`
- `%REPO%/azurelinuxagent/pa/deprovision/arch.py.ArchDeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/arch.py.ArchDeprovisionHandler.__init__`
- `%REPO%/azurelinuxagent/pa/deprovision/arch.py.ArchDeprovisionHandler.__init__.self`
- `%REPO%/azurelinuxagent/pa/deprovision/arch.py.ArchDeprovisionHandler.setup`
- `%REPO%/azurelinuxagent/pa/deprovision/arch.py.ArchDeprovisionHandler.setup.self`
- `%REPO%/azurelinuxagent/pa/deprovision/arch.py.ArchDeprovisionHandler.setup.deluser`

### Source excerpt

````
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
# Requires Python 2.6+ and Openssl 1.0+
#

import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.pa.deprovision.default import DeprovisionHandler, \
                                                   DeprovisionAction

class ArchDeprovisionHandler(DeprovisionHandler):
    def __init__(self):  # pylint: disable=W0235
        super(ArchDeprovisionHandler, self).__init__()

    def setup(self, deluser):
        warnings, actions = super(ArchDeprovisionHandler, self).setup(deluser)
        warnings.append("WARNING! /etc/machine-id will be removed.")
        files_to_del = ['/etc/machine-id']
        actions.append(DeprovisionAction(fileutil.rm_files, files_to_del))
        return warnings, actions

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction`
- `%REPO%/azurelinuxagent/pa/deprovision/clearlinux.py.ClearLinuxDeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/clearlinux.py.ClearLinuxDeprovisionHandler.__init__`
- `%REPO%/azurelinuxagent/pa/deprovision/clearlinux.py.ClearLinuxDeprovisionHandler.__init__.self`
- `%REPO%/azurelinuxagent/pa/deprovision/clearlinux.py.ClearLinuxDeprovisionHandler.__init__.distro`
- `%REPO%/azurelinuxagent/pa/deprovision/clearlinux.py.ClearLinuxDeprovisionHandler.setup`
- `%REPO%/azurelinuxagent/pa/deprovision/clearlinux.py.ClearLinuxDeprovisionHandler.setup.self`
- `%REPO%/azurelinuxagent/pa/deprovision/clearlinux.py.ClearLinuxDeprovisionHandler.setup.deluser`

### Source excerpt

````
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
# Requires Python 2.6+ and Openssl 1.0+
#

# pylint: disable=W0611
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.pa.deprovision.default import DeprovisionHandler, \
                                                   DeprovisionAction
# pylint: enable=W0611

class ClearLinuxDeprovisionHandler(DeprovisionHandler):
    def __init__(self, distro):  # pylint: disable=W0231
        self.distro = distro

    def setup(self, deluser):
        warnings, actions = super(ClearLinuxDeprovisionHandler, self).setup(deluser)
        # Probably should just wipe /etc and /var here
        return warnings, actions

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction`
- `%REPO%/azurelinuxagent/pa/deprovision/coreos.py.CoreOSDeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/coreos.py.CoreOSDeprovisionHandler.__init__`
- `%REPO%/azurelinuxagent/pa/deprovision/coreos.py.CoreOSDeprovisionHandler.__init__.self`
- `%REPO%/azurelinuxagent/pa/deprovision/coreos.py.CoreOSDeprovisionHandler.setup`
- `%REPO%/azurelinuxagent/pa/deprovision/coreos.py.CoreOSDeprovisionHandler.setup.self`
- `%REPO%/azurelinuxagent/pa/deprovision/coreos.py.CoreOSDeprovisionHandler.setup.deluser`

### Source excerpt

````
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
# Requires Python 2.6+ and Openssl 1.0+
#

import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.pa.deprovision.default import DeprovisionHandler, \
                                                   DeprovisionAction

class CoreOSDeprovisionHandler(DeprovisionHandler):
    def __init__(self):  # pylint: disable=W0235
        super(CoreOSDeprovisionHandler, self).__init__()

    def setup(self, deluser):
        warnings, actions = super(CoreOSDeprovisionHandler, self).setup(deluser)
        warnings.append("WARNING! /etc/machine-id will be removed.")
        files_to_del = ['/etc/machine-id']
        actions.append(DeprovisionAction(fileutil.rm_files, files_to_del))
        return warnings, actions


````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.UbuntuDeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.UbuntuDeprovisionHandler.__init__`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.UbuntuDeprovisionHandler.__init__.self`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.UbuntuDeprovisionHandler.del_resolv`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.UbuntuDeprovisionHandler.del_resolv.self`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.UbuntuDeprovisionHandler.del_resolv.warnings`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.UbuntuDeprovisionHandler.del_resolv.actions`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.Ubuntu1804DeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.Ubuntu1804DeprovisionHandler.__init__`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.Ubuntu1804DeprovisionHandler.__init__.self`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.Ubuntu1804DeprovisionHandler.del_resolv`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.Ubuntu1804DeprovisionHandler.del_resolv.self`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.Ubuntu1804DeprovisionHandler.del_resolv.warnings`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.Ubuntu1804DeprovisionHandler.del_resolv.actions`

### Source excerpt

````
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
# Requires Python 2.6+ and Openssl 1.0+
#

import os
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.pa.deprovision.default import DeprovisionHandler, \
    DeprovisionAction


class UbuntuDeprovisionHandler(DeprovisionHandler):
    def __init__(self):  # pylint: disable=W0235
        super(UbuntuDeprovisionHandler, self).__init__()

    def del_resolv(self, warnings, actions):
        if os.path.realpath(
                '/etc/resolv.conf') != '/run/resolvconf/resolv.conf':
            warnings.append("WARNING! /etc/resolv.conf will be deleted.")
            files_to_del = ["/etc/resolv.conf"]
            actions.append(DeprovisionAction(fileutil.rm_files, files_to_del))
        else:
            warnings.append("WARNING! /etc/resolvconf/resolv.conf.d/tail "
                            "and /etc/resolvconf/resolv.conf.d/original will "
                            "be deleted.")
            files_to_del = ["/etc/resolvconf/resolv.conf.d/tail",
                            "/etc/resolvconf/resolv.conf.d/original"]
            actions.append(DeprovisionAction(fileutil.rm_files, files_to_del))


class Ubuntu1804DeprovisionHandler(UbuntuDeprovisionHandler):
    def __init__(self):  # pylint: disable=W0235
        super(Ubuntu1804DeprovisionHandler, self).__init__()

    def del_resolv(self, warnings, actions):
        # no changes will be made to /etc/resolv.conf
        warnings.append("WARNING! /etc/resolv.conf will NOT be removed, this is a behavior change to earlier "
                        "versions of Ubuntu.")

````

---
