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


def set_unit_run_time_property(unit_name, property_name, value):
    """
    Set a property of a unit at runtime

    Note: --runtime settings only apply until the next reboot
    """
    try:
        # Ex: systemctl set-property foobar.service CPUWeight=200 --runtime
        shellutil.run_command(["systemctl", "set-property", unit_name, "{0}={1}".format(property_name, value), "--runtime"])
    except shellutil.CommandError as e:
        raise ValueError("Can't set property {0} of {1}: {2}".format(property_name, unit_name, e))


def set_unit_run_time_properties(unit_name, property_names, values):
    """
    Set multiple properties of a unit at runtime

    Note: --runtime settings only apply until the next reboot
    """
    if len(property_names) != len(values):
        raise ValueError("The number of property names:{0} and values:{1} must be the same".format(property_names, values))

    properties = ["{0}={1}".format(name, value) for name, value in zip(property_names, values)]

    try:
        # Ex: systemctl set-property foobar.service CPUWeight=200 MemoryMax=2G IPAccounting=yes --runtime
        shellutil.run_command(["systemctl", "set-property", unit_name] + properties + ["--runtime"])
    except shellutil.CommandError as e:
        raise ValueError("Can't set properties {0} of {1}: {2}".format(properties, unit_name, e))


def is_unit_loaded(unit_name):
    """
    Determine if a unit is loaded
    """
    try:
        value = get_unit_property(unit_name, "LoadState")
        return value.lower() == "loaded"
    except shellutil.CommandError:
        return False