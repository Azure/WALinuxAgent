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
import subprocess
import sys

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.future import ustr, get_linux_distribution, is_file_not_found_error

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


def get_f5_platform():
    """
    Add this workaround for detecting F5 products because BIG-IP/IQ/etc do
    not show their version info in the /etc/product-version location. Instead,
    the version and product information is contained in the /VERSION file.
    """
    result = [None, None, None, None]
    f5_version = re.compile("^Version: (\d+\.\d+\.\d+)")  # pylint: disable=W1401
    f5_product = re.compile("^Product: ([\w-]+)")  # pylint: disable=W1401

    with open('/VERSION', 'r') as fh:
        content = fh.readlines()
        for line in content:
            version_matches = f5_version.match(line)
            product_matches = f5_product.match(line)
            if version_matches:
                result[1] = version_matches.group(1)
            elif product_matches:
                result[3] = product_matches.group(1)
                if result[3] == "BIG-IP":
                    result[0] = "bigip"
                    result[2] = "bigip"
                elif result[3] == "BIG-IQ":
                    result[0] = "bigiq"
                    result[2] = "bigiq"
                elif result[3] == "iWorkflow":
                    result[0] = "iworkflow"
                    result[2] = "iworkflow"
    return result


def get_checkpoint_platform():
    take = build = release = ""
    full_name = open("/etc/cp-release").read().strip()
    with open("/etc/cloud-version") as f:
        for line in f:
            k, _, v = line.partition(": ")
            v = v.strip()
            if k == "release":
                release = v
            elif k == "take":
                take = v
            elif k == "build":
                build = v
    return ["gaia", take + "." + build, release, full_name]


def get_distro():
    if 'FreeBSD' in platform.system():
        release = re.sub('\-.*\Z', '', ustr(platform.release()))  # pylint: disable=W1401
        osinfo = ['freebsd', release, '', 'freebsd']
    elif 'OpenBSD' in platform.system():
        release = re.sub('\-.*\Z', '', ustr(platform.release()))  # pylint: disable=W1401
        osinfo = ['openbsd', release, '', 'openbsd']
    elif 'Linux' in platform.system():
        osinfo = get_linux_distribution(0, 'alpine')
    elif 'NS-BSD' in platform.system():
        release = re.sub('\-.*\Z', '', ustr(platform.release()))  # pylint: disable=W1401
        osinfo = ['nsbsd', release, '', 'nsbsd']
    else:
        try:
            # dist() removed in Python 3.8
            osinfo = list(platform.dist()) + ['']  # pylint: disable=W1505,E1101
        except Exception:
            osinfo = ['UNKNOWN', 'FFFF', '', '']

    # The platform.py lib has issue with detecting oracle linux distribution.
    # Merge the following patch provided by oracle as a temporary fix.
    if os.path.exists("/etc/oracle-release"):
        osinfo[2] = "oracle"
        osinfo[3] = "Oracle Linux"

    if os.path.exists("/etc/euleros-release"):
        osinfo[0] = "euleros"

    if os.path.exists("/etc/mariner-release"):
        osinfo[0] = "mariner"

    # The platform.py lib has issue with detecting BIG-IP linux distribution.
    # Merge the following patch provided by F5.
    if os.path.exists("/shared/vadc"):
        osinfo = get_f5_platform()

    if os.path.exists("/etc/cp-release"):
        osinfo = get_checkpoint_platform()

    if os.path.exists("/home/guestshell/azure"):
        osinfo = ['iosxe', 'csr1000v', '', 'Cisco IOSXE Linux']

    # Remove trailing whitespace and quote in distro name
    osinfo[0] = osinfo[0].strip('"').strip(' ').lower()
    return osinfo

COMMAND_ABSENT = ustr("Absent")
COMMAND_FAILED = ustr("Failed")


def get_lis_version():
    """
    This uses the Linux kernel's 'modinfo' command to retrieve the
    "version" field for the "hv_vmbus" kernel module (the LIS
    drivers). This is the documented method to retrieve the LIS module
    version. Every Linux guest on Hyper-V will have this driver, but
    it may not be installed as a module (it could instead be built
    into the kernel). In that case, this will return "Absent" instead
    of the version, indicating the driver version can be deduced from
    the kernel version. It will only return "Failed" in the presence
    of an exception.

    This function is used to generate telemetry for the version of the
    LIS drivers installed on the VM. The function and associated
    telemetry can be removed after a few releases.
    """
    try:
        modinfo_output = shellutil.run_command(["modinfo", "-F", "version", "hv_vmbus"])
        if modinfo_output:
            return modinfo_output
        # If the system doesn't have LIS drivers, 'modinfo' will
        # return nothing on stdout, which will cause 'run_command'
        # to return an empty string.
        return COMMAND_ABSENT
    except Exception:
        # Ignore almost every possible exception because this is in a
        # critical code path. Unfortunately the logger isn't already
        # imported in this module or we'd log this too.
        return COMMAND_FAILED

def has_logrotate():
    basic_version_regex = r"\d(?:\.\d+)*"
    regex = r"logrotate (?P<version>{ver})".format(ver=basic_version_regex)

    try:
        cmd_output = shellutil.run_command(["logrotate", "--version"], stderr=subprocess.STDOUT)
        match = re.search(regex, cmd_output)
        if match:
            return match.group("version")

    except Exception as e:
        if is_file_not_found_error(e):
            # run_command actually throws a FileNotFound if there
            # is no executable corresponding to the command given.
            return COMMAND_ABSENT

    return COMMAND_FAILED


AGENT_NAME = "WALinuxAgent"
AGENT_LONG_NAME = "Azure Linux Agent"
AGENT_VERSION = '2.2.54.1'
AGENT_LONG_VERSION = "{0}-{1}".format(AGENT_NAME, AGENT_VERSION)
AGENT_DESCRIPTION = """
The Azure Linux Agent supports the provisioning and running of Linux
VMs in the Azure cloud. This package should be installed on Linux disk
images that are built to run in the Azure environment.
"""

AGENT_DIR_GLOB = "{0}-*".format(AGENT_NAME)
AGENT_PKG_GLOB = "{0}-*.zip".format(AGENT_NAME)

AGENT_PATTERN = "{0}-(.*)".format(AGENT_NAME)
AGENT_NAME_PATTERN = re.compile(AGENT_PATTERN)
AGENT_PKG_PATTERN = re.compile(AGENT_PATTERN+"\.zip")  # pylint: disable=W1401
AGENT_DIR_PATTERN = re.compile(".*/{0}".format(AGENT_PATTERN))

# The execution mode of the VM - IAAS or PAAS. Linux VMs are only executed in IAAS mode.
AGENT_EXECUTION_MODE = "IAAS"

EXT_HANDLER_PATTERN = b".*/WALinuxAgent-(\d+.\d+.\d+[.\d+]*).*-run-exthandlers"  # pylint: disable=W1401
EXT_HANDLER_REGEX = re.compile(EXT_HANDLER_PATTERN)

__distro__ = get_distro()
DISTRO_NAME = __distro__[0]
DISTRO_VERSION = __distro__[1]
DISTRO_CODE_NAME = __distro__[2]
DISTRO_FULL_NAME = __distro__[3]

PY_VERSION = sys.version_info
PY_VERSION_MAJOR = sys.version_info[0]
PY_VERSION_MINOR = sys.version_info[1]
PY_VERSION_MICRO = sys.version_info[2]


# Set the CURRENT_AGENT and CURRENT_VERSION to match the agent directory name
# - This ensures the agent will "see itself" using the same name and version
#   as the code that downloads agents.
def set_current_agent():
    path = os.getcwd()
    lib_dir = conf.get_lib_dir()
    if lib_dir[-1] != os.path.sep:
        lib_dir += os.path.sep
    agent = path[len(lib_dir):].split(os.path.sep)[0]
    match = AGENT_NAME_PATTERN.match(agent)
    if match:
        version = match.group(1)
    else:
        agent = AGENT_LONG_VERSION
        version = AGENT_VERSION
    return agent, FlexibleVersion(version)


def is_agent_package(path):
    path = os.path.basename(path)
    return not re.match(AGENT_PKG_PATTERN, path) is None


def is_agent_path(path):
    path = os.path.basename(path)
    return not re.match(AGENT_NAME_PATTERN, path) is None


CURRENT_AGENT, CURRENT_VERSION = set_current_agent()


def set_goal_state_agent():
    agent = None
    if os.path.isdir("/proc"):
        pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    else:
        pids = []
    for pid in pids:
        try:
            pname = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read()
            match = EXT_HANDLER_REGEX.match(pname)
            if match:
                agent = match.group(1)
                if PY_VERSION_MAJOR > 2:
                    agent = agent.decode('UTF-8')
                break
        except IOError:
            continue
    if agent is None:
        agent = CURRENT_VERSION
    return agent


GOAL_STATE_AGENT_VERSION = set_goal_state_agent()


def is_current_agent_installed():
    return CURRENT_AGENT == AGENT_LONG_VERSION
