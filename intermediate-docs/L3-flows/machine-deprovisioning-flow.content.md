# Compose Content for: L3-flows/machine-deprovisioning-flow.md

Total files: 1

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py._AGENT_DROP_IN_FILE_SLICE`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py._DROP_IN_FILE_CPU_ACCOUNTING`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py._DROP_IN_FILE_CPU_QUOTA`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py._DROP_IN_FILE_MEMORY_ACCOUNTING`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py.LOGCOLLECTOR_SLICE`
- `%REPO%/azurelinuxagent/common/exception.py.ProtocolError`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler`
- `%REPO%/azurelinuxagent/common/protocol/util.py.get_protocol_util`
- `%REPO%/azurelinuxagent/ga/exthandlers.py.HANDLER_COMPLETE_NAME_PATTERN`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.read_input`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.read_input.message`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction.__init__`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction.__init__.self`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction.__init__.func`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction.__init__.args`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction.__init__.kwargs`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionAction.invoke`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py

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

import glob
import os.path
import re
import signal
import sys

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common import version
from azurelinuxagent.ga.cgroupconfigurator import _AGENT_DROP_IN_FILE_SLICE, _DROP_IN_FILE_CPU_ACCOUNTING, \
    _DROP_IN_FILE_CPU_QUOTA, _DROP_IN_FILE_MEMORY_ACCOUNTING, LOGCOLLECTOR_SLICE
from azurelinuxagent.common.exception import ProtocolError
from azurelinuxagent.common.osutil import get_osutil, systemd
from azurelinuxagent.ga.persist_firewall_rules import PersistFirewallRulesHandler
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.ga.exthandlers import HANDLER_COMPLETE_NAME_PATTERN


def read_input(message):
    if sys.version_info[0] >= 3:
        return input(message)
    else:
        # This is not defined in python3, and the linter will thus
        # throw an undefined-variable<E0602> error on this line.
        # Suppress it here.
        return raw_input(message)  # pylint: disable=E0602


class DeprovisionAction(object):
    def __init__(self, func, args=None, kwargs=None):
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def invoke(self):
        self.func(*self.args, **self.kwargs)


class DeprovisionHandler(object):
    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()

````

---
