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
import platform
import sys

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.future import ustr, get_linux_distribution


def get_f5_platform():
    """
    Add this workaround for detecting F5 products because BIG-IP/IQ/etc do
    not show their version info in the /etc/product-version location. Instead,
    the version and product information is contained in the /VERSION file.
    """
    result = [None, None, None, None]
    f5_version = re.compile("^Version: (\d+\.\d+\.\d+)")
    f5_product = re.compile("^Product: ([\w-]+)")

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
        release = re.sub('\-.*\Z', '', ustr(platform.release()))
        osinfo = ['freebsd', release, '', 'freebsd']
    elif 'OpenBSD' in platform.system():
        release = re.sub('\-.*\Z', '', ustr(platform.release()))
        osinfo = ['openbsd', release, '', 'openbsd']
    elif 'Linux' in platform.system():
        osinfo = get_linux_distribution(0, 'alpine')
    else:
        try:
            # dist() removed in Python 3.7
            osinfo = platform.dist()
        except:
            osinfo = ('UNKNOWN', 'FFFF', '')

    # The platform.py lib has issue with detecting oracle linux distribution.
    # Merge the following patch provided by oracle as a temporary fix.
    if os.path.exists("/etc/oracle-release"):
        osinfo[2] = "oracle"
        osinfo[3] = "Oracle Linux"

    if os.path.exists("/etc/euleros-release"):
        osinfo[0] = "euleros"

    # The platform.py lib has issue with detecting BIG-IP linux distribution.
    # Merge the following patch provided by F5.
    if os.path.exists("/shared/vadc"):
        osinfo = get_f5_platform()

    if os.path.exists("/etc/cp-release"):
        osinfo = get_checkpoint_platform()

    # Remove trailing whitespace and quote in distro name
    osinfo[0] = osinfo[0].strip('"').strip(' ').lower()
    return osinfo


AGENT_NAME = "WALinuxAgent"
AGENT_LONG_NAME = "Azure Linux Agent"
AGENT_VERSION = '2.2.27'
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
AGENT_PKG_PATTERN = re.compile(AGENT_PATTERN+"\.zip")
AGENT_DIR_PATTERN = re.compile(".*/{0}".format(AGENT_PATTERN))

EXT_HANDLER_PATTERN = b".*/WALinuxAgent-(\d+.\d+.\d+[.\d+]*).*-run-exthandlers"
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


def is_snappy():
    """
    Add this workaround for detecting Snappy Ubuntu Core temporarily,
    until ubuntu fixed this bug: https://bugs.launchpad.net/snappy/+bug/1481086
    """
    if os.path.exists("/etc/motd"):
        motd = fileutil.read_file("/etc/motd")
        if "snappy" in motd:
            return True
    return False


if is_snappy():
    DISTRO_FULL_NAME = "Snappy Ubuntu Core"
