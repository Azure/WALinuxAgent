# Compose Content for: L2-platform/agent-packaging-factories.md

Total files: 6

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/version.py.DISTRO_NAME`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_CODE_NAME`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_FULL_NAME`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion`
- `%REPO%/azurelinuxagent/common/osutil/alpine.py.AlpineOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/arch.py.ArchUtil`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/clearlinux.py.ClearLinuxUtil`
- `%REPO%/azurelinuxagent/common/osutil/coreos.py.CoreOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/chainguard.py.ChainguardOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSBaseUtil`
- `%REPO%/azurelinuxagent/common/osutil/debian.py.DebianOSModernUtil`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/devuan.py.DevuanOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/iosxe.py.IosxeOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/mariner.py.MarinerOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/openwrt.py.OpenWRTOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.RedhatOSUtil`
- `%REPO%/azurelinu

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


import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_CODE_NAME, DISTRO_VERSION, DISTRO_FULL_NAME
from azurelinuxagent.common.utils.distro_version import DistroVersion
from .acl import AclOSUtil
from .alpine import AlpineOSUtil
from .arch import ArchUtil
from .bigip import BigIpOSUtil
from .clearlinux import ClearLinuxUtil
from .coreos import CoreOSUtil
from .chainguard import ChainguardOSUtil
from .debian import DebianOSBaseUtil, DebianOSModernUtil
from .default import DefaultOSUtil
from .devuan import DevuanOSUtil
from .freebsd import FreeBSDOSUtil
from .gaia import GaiaOSUtil
from .iosxe import IosxeOSUtil
from .mariner import MarinerOSUtil
from .nsbsd import NSBSDOSUtil
from .openbsd import OpenBSDOSUtil
from .openwrt import OpenWRTOSUtil
from .redhat import RedhatOSUtil, Redhat6xOSUtil, RedhatOSModernUtil
from .suse import SUSEOSUtil, SUSE11OSUtil
from .photonos import PhotonOSUtil
from .ubuntu import UbuntuOSUtil, Ubuntu12OSUtil, Ubuntu14OSUtil, \
    UbuntuSnappyOSUtil, Ubuntu16OSUtil, Ubuntu18OSUtil
from .fedora import FedoraOSUtil


def get_osutil(distro_name=DISTRO_NAME,
               distro_code_name=DISTRO_CODE_NAME,
               distro_version=DISTRO_VERSION,
               distro_full_name=DISTRO_FULL_NAME):

    # We are adding another layer of abstraction here since we want to be able to mock the final result of the
    # function call. Since the get_osutil function is imported in various places in our tests, we can't mock
    # it globally. Instead, we add _get_osutil
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/version.py.DISTRO_NAME`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_FULL_NAME`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openwrt.py.OpenWRTResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/factory.py.get_resourcedisk_handler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/factory.py.get_resourcedisk_handler.distro_name`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/factory.py.get_resourcedisk_handler.distro_version`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/factory.py.get_resourcedisk_handler.distro_full_name`

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

from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, DISTRO_FULL_NAME
from .default import ResourceDiskHandler
from .freebsd import FreeBSDResourceDiskHandler
from .openbsd import OpenBSDResourceDiskHandler
from .openwrt import OpenWRTResourceDiskHandler


def get_resourcedisk_handler(distro_name=DISTRO_NAME,
                             distro_version=DISTRO_VERSION,  # pylint: disable=W0613
                             distro_full_name=DISTRO_FULL_NAME):  # pylint: disable=W0613
    if distro_name == "freebsd":
        return FreeBSDResourceDiskHandler()

    if distro_name == "openbsd":
        return OpenBSDResourceDiskHandler()

    if distro_name == "openwrt":
        return OpenWRTResourceDiskHandler()

    return ResourceDiskHandler()


````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/version.py.DISTRO_NAME`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_FULL_NAME`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion`
- `%REPO%/azurelinuxagent/pa/deprovision/arch.py.ArchDeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/clearlinux.py.ClearLinuxDeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/coreos.py.CoreOSDeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/default.py.DeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.UbuntuDeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/ubuntu.py.Ubuntu1804DeprovisionHandler`
- `%REPO%/azurelinuxagent/pa/deprovision/factory.py.get_deprovision_handler`
- `%REPO%/azurelinuxagent/pa/deprovision/factory.py.get_deprovision_handler.distro_name`
- `%REPO%/azurelinuxagent/pa/deprovision/factory.py.get_deprovision_handler.distro_version`
- `%REPO%/azurelinuxagent/pa/deprovision/factory.py.get_deprovision_handler.distro_full_name`

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


from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, DISTRO_FULL_NAME
from azurelinuxagent.common.utils.distro_version import DistroVersion
from .arch import ArchDeprovisionHandler
from .clearlinux import ClearLinuxDeprovisionHandler
from .coreos import CoreOSDeprovisionHandler
from .default import DeprovisionHandler
from .ubuntu import UbuntuDeprovisionHandler, Ubuntu1804DeprovisionHandler


def get_deprovision_handler(distro_name=DISTRO_NAME,
                            distro_version=DISTRO_VERSION,
                            distro_full_name=DISTRO_FULL_NAME):
    if distro_name == "arch":
        return ArchDeprovisionHandler()
    if distro_name == "ubuntu":
        if DistroVersion(distro_version) >= DistroVersion('18.04'):
            return Ubuntu1804DeprovisionHandler()
        else:
            return UbuntuDeprovisionHandler()
    if distro_name in ("flatcar", "coreos"):
        return CoreOSDeprovisionHandler()
    if "Clear Linux" in distro_full_name:
        return ClearLinuxDeprovisionHandler()  # pylint: disable=E1120

    return DeprovisionHandler()


````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/version.py.DISTRO_NAME`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_FULL_NAME`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler`
- `%REPO%/azurelinuxagent/pa/provision/cloudinit.py.CloudInitProvisionHandler`
- `%REPO%/azurelinuxagent/pa/provision/cloudinitdetect.py.cloud_init_is_enabled`
- `%REPO%/azurelinuxagent/pa/provision/factory.py.get_provision_handler`
- `%REPO%/azurelinuxagent/pa/provision/factory.py.get_provision_handler.distro_name`
- `%REPO%/azurelinuxagent/pa/provision/factory.py.get_provision_handler.distro_version`
- `%REPO%/azurelinuxagent/pa/provision/factory.py.get_provision_handler.distro_full_name`
- `%REPO%/azurelinuxagent/common/conf.py.get_provisioning_agent`
- `%REPO%/azurelinuxagent/common/logger.py.info`

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

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, \
                                     DISTRO_FULL_NAME

from .default import ProvisionHandler
from .cloudinit import CloudInitProvisionHandler, cloud_init_is_enabled

def get_provision_handler(distro_name=DISTRO_NAME,  # pylint: disable=W0613
                            distro_version=DISTRO_VERSION,  # pylint: disable=W0613
                            distro_full_name=DISTRO_FULL_NAME):  # pylint: disable=W0613

    provisioning_agent = conf.get_provisioning_agent()

    if provisioning_agent == 'cloud-init' or (
            provisioning_agent == 'auto' and
            cloud_init_is_enabled()):
        logger.info('Using cloud-init for provisioning')
        return CloudInitProvisionHandler()

    logger.info('Using waagent for provisioning')
    return ProvisionHandler()

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_LONG_VERSION`
- `%REPO%/azurelinuxagent/ga/guestagent.py.AGENT_MANIFEST_FILE`
- `%REPO%/makepkg.py.MANIFEST`
- `%REPO%/makepkg.py.PUBLISH_MANIFEST`
- `%REPO%/makepkg.py.PUBLISH_MANIFEST_FILE`
- `%REPO%/makepkg.py.do`
- `%REPO%/makepkg.py.do.args`
- `%REPO%/makepkg.py.run`
- `%REPO%/makepkg.py.run.agent_family`
- `%REPO%/makepkg.py.run.output_directory`
- `%REPO%/makepkg.py.run.log`
- `parser`
- `arguments`
- `exception`

### Source excerpt

````
#!/usr/bin/env python3

import argparse
import glob
import logging
import os.path
import shutil
import subprocess
import sys

from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, \
    AGENT_LONG_VERSION, AGENT_SIGNING_INFO_NAME
from azurelinuxagent.ga.guestagent import AGENT_MANIFEST_FILE

MANIFEST = '''[{{
    "name": "{0}",
    "version": 1.0,
    "handlerManifest": {{
        "installCommand": "",
        "uninstallCommand": "",
        "updateCommand": "",
        "enableCommand": "python -u {1} -run-exthandlers",
        "disableCommand": "",
        "rebootAfterInstall": false,
        "reportHeartbeat": false
    }},
    "signingInfo": {{
        "version": "{2}",
        "name": "{3}"
    }}
}}]'''

PUBLISH_MANIFEST = '''<?xml version="1.0" encoding="utf-8" ?>
<ExtensionImage xmlns="http://schemas.microsoft.com/windowsazure"  xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
  <!-- WARNING: Ordering of fields matter in this file. -->
  <ProviderNameSpace>Microsoft.OSTCLinuxAgent</ProviderNameSpace>
  <Type>{1}</Type>
  <Version>{0}</Version>
  <Label>Microsoft Azure Guest Agent for Linux IaaS</Label>
  <HostingResources>VmRole</HostingResources>
  <MediaLink></MediaLink>
  <Description>Microsoft Azure Guest Agent for Linux IaaS</Description>
  <IsInternalExtension>true</IsInternalExtension>
  <Eula>https://github.com/Azure/WALinuxAgent/blob/2.1/LICENSE.txt</Eula>
  <PrivacyUri>https://github.com/Azure/WALinuxAgent/blob/2.1/LICENSE.txt</PrivacyUri>
  <HomepageUri>https://github.com/Azure/WALinuxAgent</HomepageUri>
  <IsJsonExtension>true</IsJsonExtension>
  <CompanyName>Microsoft</CompanyName>
  <SupportedOS>Linux</SupportedOS>
  <!--%REGIONS%-->
</ExtensionImage>
'''

PUBLISH_MANIFEST_FILE = 'manifest.xml'


def do(*args):
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:  # pylint: disable=C0103
        raise Exception("[{0}] failed:\n{1}\n{2}".format(" ".join(args), str(e), e.output))


def run(agent_family, output_directory, log):
    output_path = os.path.join(output_directory, "eggs")
    target_path = os.path.join(output_path, AGENT_LONG_VERSION)
    b
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_DESCRIPTION`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_NAME`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_FULL_NAME`
- `%REPO%/setup.py.root_dir`
- `%REPO%/setup.py.set_files`
- `%REPO%/setup.py.set_files.data_files`
- `%REPO%/setup.py.set_files.dest`
- `%REPO%/setup.py.set_files.src`
- `%REPO%/setup.py.set_bin_files`
- `%REPO%/setup.py.set_bin_files.data_files`
- `%REPO%/setup.py.set_bin_files.dest`
- `%REPO%/setup.py.set_bin_files.src`
- `%REPO%/setup.py.set_conf_files`
- `%REPO%/setup.py.set_conf_files.data_files`
- `%REPO%/setup.py.set_conf_files.dest`
- `%REPO%/setup.py.set_conf_files.src`
- `%REPO%/setup.py.set_logrotate_files`
- `%REPO%/setup.py.set_logrotate_files.data_files`
- `%REPO%/setup.py.set_logrotate_files.dest`
- `%REPO%/setup.py.set_logrotate_files.src`
- `%REPO%/setup.py.set_sysv_files`
- `%REPO%/setup.py.set_sysv_files.data_files`
- `%REPO%/setup.py.set_sysv_files.dest`
- `%REPO%/setup.py.set_sysv_files.src`
- `%REPO%/setup.py.set_openrc_files`
- `%REPO%/setup.py.set_openrc_files.data_files`
- `%REPO%/setup.py.set_openrc_files.dest`
- `%REPO%/setup.py.set_openrc_files.src`
- `%REPO%/setup.py.set_systemd_files`
- `%REPO%/setup.py.set_systemd_files.data_files`


### Source excerpt

````
#!/usr/bin/env python
#
# Microsoft Azure Linux Agent setup.py
#
# Copyright 2013 Microsoft Corporation
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

import gzip
import os
import shutil
import subprocess
import sys

import setuptools
from setuptools import find_packages
from setuptools.command.install import install as _install

from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, \
    AGENT_DESCRIPTION, \
    DISTRO_NAME, DISTRO_VERSION, DISTRO_FULL_NAME

root_dir = os.path.dirname(os.path.abspath(__file__))  # pylint: disable=invalid-name
os.chdir(root_dir)


def set_files(data_files, dest=None, src=None):
    data_files.append((dest, src))


def set_bin_files(data_files, dest, src=None):
    if src is None:
        src = ["bin/waagent", "bin/waagent2.0"]
    data_files.append((dest, src))


def set_conf_files(data_files, dest="/etc", src=None):
    if src is None:
        src = ["config/waagent.conf"]
    data_files.append((dest, src))


def set_logrotate_files(data_files, dest="/etc/logrotate.d", src=None):
    if src is None:
        src = ["config/waagent.logrotate"]
    data_files.append((dest, src))


def set_sysv_files(data_files, dest="/etc/rc.d/init.d", src=None):
    if src is None:
        src = ["init/waagent"]
    data_files.append((dest, src))

def set_openrc_files(data_files, dest="/etc/init.d", src=None):
    if src is None:
        src = ["init/openrc/waagent"]
    data_files.append((dest, src))

def set_systemd_files(data_files, dest, src=None):
    if src is None:
        src = ["init/waagent.service"]
    data_files.append((dest, src))


def set_freebsd_rc_files(data_files, des
````

---
