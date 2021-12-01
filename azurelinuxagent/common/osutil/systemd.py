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
    return shellutil.run_command(['systemctl', '--version'])


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


def get_agent_drop_in_path():
    """
    e.g. /lib/systemd/system/walinuxagent.service.d
    """
    return os.path.join(get_unit_file_install_path(), "{0}.d".format(get_agent_unit_name()))


def get_unit_property(unit_name, property_name):
    output = shellutil.run_command(["systemctl", "show", unit_name, "--property", property_name])
    # Output is similar to
    #     # systemctl show walinuxagent.service --property CPUQuotaPerSecUSec
    #     CPUQuotaPerSecUSec=50ms
    match = re.match("[^=]+=(?P<value>.+)", output)
    if match is None:
        raise ValueError("Can't find property {0} of {1}".format(property_name, unit_name))
    return match.group('value')

