# Compose Content for: L1-conceptual/os-service-management.md

Total files: 2

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`

### Source excerpt

````
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

from azurelinuxagent.common.osutil.factory import get_osutil

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py._get_os_util`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.is_systemd`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.get_version`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_command`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.get_unit_file_install_path`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.get_agent_unit_name`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.get_agent_unit_file`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.get_agent_drop_in_path`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.get_unit_property`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.get_unit_property.unit_name`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.get_unit_property.property_name`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.set_unit_run_time_property`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.set_unit_run_time_property.unit_name`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.set_unit_run_time_property.property_name`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.set_unit_run_time_property.value`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.set_unit_run_time_properties`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.set_unit_run_time_properties.unit_name`
- `%REPO%/azurelinuxagent/common/osutil/systemd.py.set_unit_run_time_properties.property_names`
- `%REPO%/azurelinuxagent/common/o

### Source excerpt

````
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
import re

from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.ga.extensionprocessutil import TELEMETRY_MESSAGE_MAX_LEN
from azurelinuxagent.common.future import ustr


def _get_os_util():
    if _get_os_util.value is None:
        _get_os_util.value = get_osutil()
    return _get_os_util.value
_get_os_util.value = None


def is_systemd():
    """
    Determine if systemd is managing system services; the implementation follows the same strategy as, for example,
    sd_booted() in libsystemd, or /usr/sbin/service
    """
    return os.path.exists("/run/systemd/system/")


def get_version():
    # the output is similar to
    #    $ systemctl --version
    #    systemd 245 (245.4-4ubuntu3)
    #    +PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP etc
    #
    # return fist line systemd 245 (245.4-4ubuntu3)
    try:
        output = shellutil.run_command(['systemctl', '--version'])
        version = output.split('\n')[0]
        return version
    except Exception:
        return "unknown"


def get_unit_file_install_path():
    """
    e.g. /lib/systemd/system
    """
    return _get_os_util().get_systemd_unit_file_install_path()


def get_agent_unit_name():
    """
    e.g. walinuxagent.service
    """
    return _get_os_util().get_service_name() + ".service"


def get_agent_unit_file():
    """
    e.g. /lib/systemd/system/walinuxagent.service
    """
    return os.path.join(get_unit_file_install_path(), get_agent_unit_name())


def get_agent_drop_in_
````

---
