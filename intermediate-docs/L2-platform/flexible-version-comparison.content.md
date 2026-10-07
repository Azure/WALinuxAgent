# Compose Content for: L2-platform/flexible-version-comparison.md

Total files: 2

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion.__init__`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion.__init__.self`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion.__init__.vstring`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion.__init__.sep`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion.__init__.prerel_tags`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion._compile_pattern`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion._parse`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion._nn_version`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion._nn_prerel_sep`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion._nn_prerel_tag`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion._nn_prerel_num`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion._re_prerel_sep`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion.major`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion.major.self`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion.minor`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion.minor.self`
- `%

### Source excerpt

````
# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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

import re


class FlexibleVersion(object):
    """
    A more flexible implementation of distutils.version.StrictVersion.

    NOTE: Use this class for generic version comparisons, e.g. extension and Agent
          versions. Distro versions can be very arbitrary and should be handled
          using the DistroVersion class.

    The implementation allows to specify:
    - an arbitrary number of version numbers:
        not only '1.2.3' , but also '1.2.3.4.5'
    - the separator between version numbers:
        '1-2-3' is allowed when '-' is specified as separator
    - a flexible pre-release separator:
        '1.2.3.alpha1', '1.2.3-alpha1', and '1.2.3alpha1' are considered equivalent
    - an arbitrary ordering of pre-release tags:
        1.1alpha3 < 1.1beta2 < 1.1rc1 < 1.1
        when ["alpha", "beta", "rc"] is specified as pre-release tag list

    Inspiration from this discussion at StackOverflow:
        http://stackoverflow.com/questions/12255554/sort-versions-in-python
    """

    def __init__(self, vstring=None, sep='.', prerel_tags=('alpha', 'beta', 'rc')):
        if sep is None:
            sep = '.'
        if prerel_tags is None:
            prerel_tags = ()

        self.sep = sep
        self.prerel_sep = ''
        self.prerel_tags = tuple(prerel_tags) if prerel_tags is not None else ()

        self._compile_pattern()

        self.prerelease = None
        self.version = ()
        if vstring:
            self._parse(str(vstring))
        return

    _nn_version = 'version'
    _nn_prerel_se
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/future.py.get_linux_distribution`
- `%REPO%/azurelinuxagent/common/version.py.__DAEMON_VERSION_ENV_VARIABLE`
- `%REPO%/azurelinuxagent/common/version.py.set_daemon_version`
- `%REPO%/azurelinuxagent/common/version.py.set_daemon_version.version`
- `%REPO%/azurelinuxagent/common/version.py.get_daemon_version`
- `%REPO%/azurelinuxagent/common/version.py.get_f5_platform`
- `%REPO%/azurelinuxagent/common/version.py.get_checkpoint_platform`
- `%REPO%/azurelinuxagent/common/version.py.get_distro`
- `%REPO%/azurelinuxagent/common/version.py.COMMAND_ABSENT`
- `%REPO%/azurelinuxagent/common/version.py.COMMAND_FAILED`
- `%REPO%/azurelinuxagent/common/version.py.get_lis_version`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_command`
- `%REPO%/azurelinuxagent/common/version.py.has_logrotate`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_LONG_NAME`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_LONG_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_DESCRIPTION`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_DIR_GLOB`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_PKG_GLOB`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_PATTERN`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME_PATTERN`
- `%REPO%/azurelinuxagent/common/version.py.A

### Source excerpt

````
# Copyright 2019 Microsoft Corporation
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
import re
import platform
import sys

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.future import ustr, get_linux_distribution

__DAEMON_VERSION_ENV_VARIABLE = '_AZURE_GUEST_AGENT_DAEMON_VERSION_'
"""
    The daemon process sets this variable's value to the daemon's version number.
    The variable is set only on versions >= 2.2.53
"""


def set_daemon_version(version):
    """
    Sets the value of the _AZURE_GUEST_AGENT_DAEMON_VERSION_ environment variable.

    The given 'version' can be a FlexibleVersion or a string that can be parsed into a FlexibleVersion
    """
    flexible_version = version if isinstance(version, FlexibleVersion) else FlexibleVersion(version)
    os.environ[__DAEMON_VERSION_ENV_VARIABLE] = ustr(flexible_version)


def get_daemon_version():
    """
    Retrieves the value of the _AZURE_GUEST_AGENT_DAEMON_VERSION_ environment variable.
    The value indicates the version of the daemon that started the current agent process or, if the current
    process is the daemon, the version of the current process.
    If the variable is not set (because the agent is < 2.2.53, or the process was not started by the daemon and
    the process is not the daemon itself) the function returns "0.0.0.0"
    """
    if __DAEMON_VERSION_ENV_VARIABLE in os.environ:
        return FlexibleVersion(os.environ[__DAEMON_VERSION_ENV_VARIABLE])
    return FlexibleVersion("0.0.0.0")



````

---
