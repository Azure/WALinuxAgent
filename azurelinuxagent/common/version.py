# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#

import os
import re
import platform
import sys

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.future import ustr


def get_distro():
    if 'FreeBSD' in platform.system():
        release = re.sub('\-.*\Z', '', ustr(platform.release()))
        osinfo = ['freebsd', release, '', 'freebsd']
    elif 'linux_distribution' in dir(platform):
        osinfo = list(platform.linux_distribution(full_distribution_name=0))
        full_name = platform.linux_distribution()[0].strip()
        osinfo.append(full_name)
    else:
        osinfo = platform.dist()

    # The platform.py lib has issue with detecting oracle linux distribution.
    # Merge the following patch provided by oracle as a temparory fix.
    if os.path.exists("/etc/oracle-release"):
        osinfo[2] = "oracle"
        osinfo[3] = "Oracle Linux"

    # Remove trailing whitespace and quote in distro name
    osinfo[0] = osinfo[0].strip('"').strip(' ').lower()
    return osinfo


AGENT_NAME = "WALinuxAgent"
AGENT_LONG_NAME = "Azure Linux Agent"
AGENT_VERSION = '2.1.5'
AGENT_LONG_VERSION = "{0}-{1}".format(AGENT_NAME, AGENT_VERSION)
AGENT_DESCRIPTION = """\
The Azure Linux Agent supports the provisioning and running of Linux
VMs in the Azure cloud. This package should be installed on Linux disk
images that are built to run in the Azure environment.
"""

AGENT_DIR_GLOB = "{0}-*".format(AGENT_NAME)
AGENT_PKG_GLOB = "{0}-*.zip".format(AGENT_NAME)

AGENT_PATTERN = "{0}-(.*)".format(AGENT_NAME)
AGENT_NAME_PATTERN = re.compile(AGENT_PATTERN)
AGENT_DIR_PATTERN = re.compile(".*/{0}".format(AGENT_PATTERN))


# Set the CURRENT_AGENT and CURRENT_VERSION to match the agent directory name
# - This ensures the agent will "see itself" using the same name and version
#   as the code that downloads agents.
def set_current_agent():
    path = os.getcwd()
    lib_dir = conf.get_lib_dir()
    if lib_dir[-1] != os.path.sep:
        lib_dir += os.path.sep
    if path[:len(lib_dir)] != lib_dir:
        agent = AGENT_LONG_VERSION
        version = AGENT_VERSION
    else:
        agent = path[len(lib_dir):].split(os.path.sep)[0]
        version = AGENT_NAME_PATTERN.match(agent).group(1)
    return agent, FlexibleVersion(version)
CURRENT_AGENT, CURRENT_VERSION = set_current_agent()

def is_current_agent_installed():
    return CURRENT_AGENT == AGENT_LONG_VERSION


__distro__ = get_distro()
DISTRO_NAME = __distro__[0]
DISTRO_VERSION = __distro__[1]
DISTRO_CODE_NAME = __distro__[2]
DISTRO_FULL_NAME = __distro__[3]

PY_VERSION = sys.version_info
PY_VERSION_MAJOR = sys.version_info[0]
PY_VERSION_MINOR = sys.version_info[1]
PY_VERSION_MICRO = sys.version_info[2]

"""
Add this workaround for detecting Snappy Ubuntu Core temporarily, until ubuntu
fixed this bug: https://bugs.launchpad.net/snappy/+bug/1481086
"""


def is_snappy():
    if os.path.exists("/etc/motd"):
        motd = fileutil.read_file("/etc/motd")
        if "snappy" in motd:
            return True
    return False


if is_snappy():
    DISTRO_FULL_NAME = "Snappy Ubuntu Core"
