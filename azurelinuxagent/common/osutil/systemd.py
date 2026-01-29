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


def is_systemd_run_failure(unit_name, stderr):
    """
    Determines if stderr from a systemd-run command indicates a systemd-run infrastructure failure
    (as opposed to a failure of the command being executed).
    
    This method distinguishes between two types of failures:
    1. systemd-run infrastructure failures: systemd-run itself failed to execute the command
       (e.g., D-Bus errors, systemd not available, unit configuration issues)
    2. Command execution failures: systemd-run successfully executed the command, but the command
       itself failed or produced errors
    
    The determination is made by examining the stderr output:
    - If stderr contains "Unit {unit_name} not found", it indicates systemd-run couldn't find/create
      the unit, which is a systemd-run failure
    - If stderr does NOT contain the unit_name at all, it suggests systemd-run failed before even
      attempting to run the command (e.g., D-Bus connection failures, systemd not running), which
      is a systemd-run failure
    - If stderr contains the unit_name (but not the "not found" message), it means systemd-run
      successfully started the command in the unit, so any errors are from the command itself,
      not from systemd-run
    
    This distinction is important because:
    - systemd-run failures should trigger fallback mechanisms (e.g., disable cgroups, run command directly)
    - Command failures should be propagated to the caller for proper error handling

    :param unit_name: The name of the systemd unit/scope that was used with systemd-run
    :param stderr: Error output from the systemd-run command, expected to be a file-like object or a string.
    :return: True if this is a systemd-run failure, False if it's a command execution failure
    """
    if isinstance(stderr, ustr):
        stderr_str = stderr
    else:
        stderr.seek(0)
        stderr_str = ustr(stderr.read(TELEMETRY_MESSAGE_MAX_LEN), encoding='utf-8', errors='backslashreplace')

    unit_not_found = "Unit {0} not found.".format(unit_name)
    return unit_not_found in stderr_str or unit_name not in stderr_str
