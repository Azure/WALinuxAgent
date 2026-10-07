# Compose Content for: L2-platform/platform-error-handling.md

Total files: 28

---

## setup.py

### Structural symbols

N/A

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

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.CGroupsException`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.AGENT_LOG_COLLECTOR`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.create_cgroup_api`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.InvalidCgroupMountpointException`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/ga/logcollector.py.LogCollector`
- `%REPO%/azurelinuxagent/ga/logcollector.py.OUTPUT_RESULTS_FILE_PATH`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_LONG_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_NAME`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.PY_VERSION_MAJOR`
- `%REPO%/azurelinuxagent/common/version.py.PY_VERSION_MINOR`
- `%REPO%/azurelinuxagent/common/version.py.PY_VERSION_MICRO`
- `%REPO%/azurelinuxagent/common/version.py.GOAL_STATE_AGENT_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.get_daemon_version`
- `%REPO%/azurelinuxagent/common/version.py.set_daemon_version`
- `%REPO%/azurelinuxagent/ga/collect_logs.py.CollectLogsHandler`
- `%REPO%/azurelinuxagent

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

"""
Module agent
"""

from __future__ import print_function

import json
import os
import re
import subprocess
import sys
import threading
import time

from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.ga import logcollector, cgroupconfigurator
from azurelinuxagent.ga.cgroupcontroller import AGENT_LOG_COLLECTOR
from azurelinuxagent.ga.cpucontroller import _CpuController
from azurelinuxagent.ga.cgroupapi import create_cgroup_api, InvalidCgroupMountpointException
from azurelinuxagent.ga.firewall_manager import FirewallManager, IpTables

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.event as event
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.ga.logcollector import LogCollector, OUTPUT_RESULTS_FILE_PATH
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil, textutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.shellutil import run_command, CommandError
from azurelinuxagent.common.version import AGENT_NAME, AGENT_LONG_VERSION, AGENT_VERSION, \
    DISTRO_NAME, DISTRO_VERSION, \
    PY_VERSION_MAJOR, PY_VERSION_MINOR, \
    PY_VERSION_MICRO, GOAL_STATE_AGENT_VERSION, \
    get_daemon_version, set_daemon_version
from azurelinuxagent.ga.collect_logs import CollectLogsHandler, get_log_collector_monitor_handler
from azurelinux
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/utils/fileutil.py.read_file`
- `%REPO%/azurelinuxagent/common/exception.py.AgentConfigError`
- `%REPO%/azurelinuxagent/common/conf.py.DISABLE_AGENT_FILE`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.__init__`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.__init__.self`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.load`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.load.self`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.load.content`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider._get_default`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider._get_default.default`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.get`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.get.self`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.get.key`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.get.default_value`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.get_switch`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.get_switch.self`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.get_switch.key`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.get_switch.default_value`
- `%REPO%/azurelinuxagent/common/conf.py.ConfigurationProvider.get_int`
- `%REPO%/azurelinuxagent/

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

"""
Module conf loads and parses configuration file
"""  # pylint: disable=W0105
import os
import os.path

from azurelinuxagent.common.utils.fileutil import read_file #pylint: disable=R0401
from azurelinuxagent.common.exception import AgentConfigError

DISABLE_AGENT_FILE = 'disable_agent'


class ConfigurationProvider(object):
    """
    Parse and store key:values in /etc/waagent.conf.
    """

    def __init__(self):
        self.values = {}

    def load(self, content):
        if not content:
            raise AgentConfigError("Can't not parse empty configuration")
        for line in content.split('\n'):
            if not line.startswith("#") and "=" in line:
                parts = line.split('=', 1)
                if len(parts) < 2:
                    continue
                key = parts[0].strip()
                value = parts[1].split('#')[0].strip("\" ").strip()
                self.values[key] = value if value != "None" else None

    @staticmethod
    def _get_default(default):
        if hasattr(default, '__call__'):
            return default()
        return default

    def get(self, key, default_value):
        """
        Retrieves a string parameter by key and returns its value. If not found returns the default value,
        or if the default value is a callable returns the result of invoking the callable.
        """
        val = self.values.get(key)
        return val if val is not None else self._get_default(default_value)

    def get_switch(self, key, default_value):
        """

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.ProtocolError`
- `%REPO%/azurelinuxagent/common/datacontract.py.DataContract`
- `%REPO%/azurelinuxagent/common/datacontract.py.DataContractList`
- `%REPO%/azurelinuxagent/common/datacontract.py.DataContractList.__init__`
- `%REPO%/azurelinuxagent/common/datacontract.py.DataContractList.__init__.self`
- `%REPO%/azurelinuxagent/common/datacontract.py.DataContractList.__init__.item_cls`
- `%REPO%/azurelinuxagent/common/datacontract.py.validate_param`
- `%REPO%/azurelinuxagent/common/datacontract.py.validate_param.name`
- `%REPO%/azurelinuxagent/common/datacontract.py.validate_param.val`
- `%REPO%/azurelinuxagent/common/datacontract.py.validate_param.expected_type`
- `%REPO%/azurelinuxagent/common/datacontract.py.set_properties`
- `%REPO%/azurelinuxagent/common/datacontract.py.set_properties.name`
- `%REPO%/azurelinuxagent/common/datacontract.py.set_properties.obj`
- `%REPO%/azurelinuxagent/common/datacontract.py.set_properties.data`
- `%REPO%/azurelinuxagent/common/logger.py.warn`
- `%REPO%/azurelinuxagent/common/datacontract.py.get_properties`
- `%REPO%/azurelinuxagent/common/datacontract.py.get_properties.obj`

### Source excerpt

````
# Microsoft Azure Linux Agent
#
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

from azurelinuxagent.common.exception import ProtocolError
import azurelinuxagent.common.logger as logger

# pylint: disable=W0105
"""
Base class for data contracts between guest and host and utilities to manipulate the properties in those contracts
"""
# pylint: enable=W0105


class DataContract(object):
    pass


class DataContractList(list):
    def __init__(self, item_cls):  # pylint: disable=W0231
        self.item_cls = item_cls


def validate_param(name, val, expected_type):
    if val is None:
        raise ProtocolError("{0} is None".format(name))
    if not isinstance(val, expected_type):
        raise ProtocolError(("{0} type should be {1} not {2}"
                             "").format(name, expected_type, type(val)))


def set_properties(name, obj, data):
    if isinstance(obj, DataContract):
        validate_param("Property '{0}'".format(name), data, dict)
        for prob_name, prob_val in data.items():
            prob_full_name = "{0}.{1}".format(name, prob_name)
            try:
                prob = getattr(obj, prob_name)
            except AttributeError:
                logger.warn("Unknown property: {0}", prob_full_name)
                continue
            prob = set_properties(prob_full_name, prob, prob_val)
            setattr(obj, prob_name, prob)
        return obj
    elif isinstance(obj, DataContractList):
        validate_param("List '{0}'".format(name), data, list)
        for item_data in data:
            item = obj.item_cls()
            item = set_properties(name, item, ite
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.DhcpError`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.KNOWN_WIRESERVER_IP`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.hex_dump`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.hex_dump2`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.hex_dump3`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.compare_bytes`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.str_to_ord`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.unpack_big_endian`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.int_to_ip4_addr`
- `%REPO%/azurelinuxagent/common/dhcp.py.KNOWN_WIRESERVER_IP_ENTRY`
- `%REPO%/azurelinuxagent/common/dhcp.py.get_dhcp_handler`
- `%REPO%/azurelinuxagent/common/dhcp.py.DhcpHandler`
- `%REPO%/azurelinuxagent/common/dhcp.py.DhcpHandler.__init__`
- `%REPO%/azurelinuxagent/common/dhcp.py.DhcpHandler.__init__.self`
- `%REPO%/azurelinuxagent/common/dhcp.py.DhcpHandler.run`
- `%REPO%/azurelinuxagent/common/dhcp.py.DhcpHandler.run.self`
- `%REPO%/azurelinuxagent/common/dhcp.py.DhcpHandler.send_dhcp_req`
- `%REPO%/azurelinuxagent/common/dhcp.py.DhcpHandler.conf_routes`
- `%REPO%/azurelinuxagent/common/dhcp.py.DhcpHandler.wait_for_network`
- `%REPO%/azurelinuxagent/common/dhcp.py.DhcpHandler.wait_for_network.self`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/dhcp.py.DhcpHandler.wireserver_route_exists`
- `%REPO%/azure

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

import array
import os
import socket
import time

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import DhcpError
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP
from azurelinuxagent.common.utils.textutil import hex_dump, hex_dump2, \
    hex_dump3, \
    compare_bytes, str_to_ord, \
    unpack_big_endian, \
    int_to_ip4_addr

# the kernel routing table representation of 168.63.129.16
KNOWN_WIRESERVER_IP_ENTRY = '10813FA8'


def get_dhcp_handler():
    return DhcpHandler()


class DhcpHandler(object):
    """
    Azure use DHCP option 245 to pass endpoint ip to VMs.
    """

    def __init__(self):
        self.osutil = get_osutil()
        self.endpoint = None
        self.gateway = None
        self.routes = None
        self._request_broadcast = False
        self.skip_cache = False

    def run(self):
        """
        Send dhcp request
        Configure default gateway and routes
        Save wire server endpoint if found
        """
        if self.wireserver_route_exists or self.dhcp_cache_exists:
            return

        self.send_dhcp_req()
        self.conf_routes()

    def wait_for_network(self):
        """
        Wait for network stack to be initialized.
        """
        ipv4 = self.osutil.get_ip4_addr()
        while ipv4 == '' or ipv4 == '0.0.0.0':
            logger.info("Waiting for network.")
            time.sleep(10)
            logger.info("Try to start network in
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.ExitException`
- `%REPO%/azurelinuxagent/common/exception.py.ExitException.__init__`
- `%REPO%/azurelinuxagent/common/exception.py.ExitException.__init__.self`
- `%REPO%/azurelinuxagent/common/exception.py.ExitException.__init__.reason`
- `%REPO%/azurelinuxagent/common/exception.py.AgentUpgradeExitException`
- `%REPO%/azurelinuxagent/common/exception.py.AgentError`
- `%REPO%/azurelinuxagent/common/exception.py.AgentError.__init__`
- `%REPO%/azurelinuxagent/common/exception.py.AgentError.__init__.self`
- `%REPO%/azurelinuxagent/common/exception.py.AgentError.__init__.msg`
- `%REPO%/azurelinuxagent/common/exception.py.AgentError.__init__.inner`
- `%REPO%/azurelinuxagent/common/exception.py.AgentConfigError`
- `%REPO%/azurelinuxagent/common/exception.py.AgentConfigError.__init__`
- `%REPO%/azurelinuxagent/common/exception.py.AgentConfigError.__init__.self`
- `%REPO%/azurelinuxagent/common/exception.py.AgentConfigError.__init__.msg`
- `%REPO%/azurelinuxagent/common/exception.py.AgentConfigError.__init__.inner`
- `%REPO%/azurelinuxagent/common/exception.py.AgentMemoryExceededException`
- `%REPO%/azurelinuxagent/common/exception.py.AgentMemoryExceededException.__init__`
- `%REPO%/azurelinuxagent/common/exception.py.AgentMemoryExceededException.__init__.self`
- `%REPO%/azurelinuxagent/common/exception.py.AgentMemoryExceededException.__init__.msg`
- `%REPO%/azurelinuxagent/common/exception.py.AgentMemoryExceededException.__init__.inner`
-

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

"""
Defines all exceptions
"""


class ExitException(BaseException):
    """
    Used to exit the agent's process
    """
    def __init__(self, reason):
        super(ExitException, self).__init__()
        self.reason = reason


class AgentUpgradeExitException(ExitException):
    """
    Used to exit the agent's process due to Agent Upgrade
    """


class AgentError(Exception):
    """
    Base class of agent error.
    """

    def __init__(self, msg, inner=None):
        msg = u"[{0}] {1}".format(type(self).__name__, msg)
        if inner is not None:
            msg = u"{0}\nInner error: {1}".format(msg, inner)
        super(AgentError, self).__init__(msg)


class AgentConfigError(AgentError):
    """
    When configure file is not found or malformed.
    """

    def __init__(self, msg=None, inner=None):
        super(AgentConfigError, self).__init__(msg, inner)


class AgentMemoryExceededException(AgentError):
    """
    When Agent memory limit reached.
    """
    def __init__(self, msg=None, inner=None):
        super(AgentMemoryExceededException, self).__init__(msg, inner)


class AgentNetworkError(AgentError):
    """
    When network is not available.
    """

    def __init__(self, msg=None, inner=None):
        super(AgentNetworkError, self).__init__(msg, inner)


class AgentUpdateError(AgentError):
    """
    When agent failed to update.
    """

    def __init__(self, msg=None, inner=None):
        super(AgentUpdateError, self).__init__(msg, inner)


class AgentFamilyMissingError(AgentError):

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/future.py.array_to_bytes`
- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil._wait_until_mcpd_is_initialized`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil._wait_until_mcpd_is_initialized.self`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil._save_sys_config`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil._save_sys_config.self`
- `%REPO%/azurelinuxagent/common/logger.py.error`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil.restart_ssh_service.self`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil.stop_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil.stop_agent_service.self`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil.start_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil.start_agent_service.self`
- `%REPO%/azurelinuxagent/common/osutil/bigip.py.BigIpOSUtil.register_agent_service`
- `%R

### Source excerpt

````
# Copyright 2016 F5 Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and Openssl 1.0+
#

import array
import fcntl
import os
import platform
import re
import socket
import struct
import time

from azurelinuxagent.common.future import array_to_bytes

try:
    # WAAgent > 2.1.3
    import azurelinuxagent.common.logger as logger
    import azurelinuxagent.common.utils.shellutil as shellutil

    from azurelinuxagent.common.exception import OSUtilError
    from azurelinuxagent.common.osutil.default import DefaultOSUtil
except ImportError:
    # WAAgent <= 2.1.3
    import azurelinuxagent.logger as logger
    import azurelinuxagent.utils.shellutil as shellutil

    from azurelinuxagent.exception import OSUtilError
    from azurelinuxagent.distro.default.osutil import DefaultOSUtil


class BigIpOSUtil(DefaultOSUtil):

    def __init__(self):  # pylint: disable=W0235
        super(BigIpOSUtil, self).__init__()

    def _wait_until_mcpd_is_initialized(self):
        """Wait for mcpd to become available

        All configuration happens in mcpd so we need to wait that this is
        available before we go provisioning the system. I call this method
        at the first opportunity I have (during the DVD mounting call).
        This ensures that the rest of the provisioning does not need to wait
        for mcpd to be available unless it absolutely wants to.

        :return bool: Returns True upon success
        :raises OSUtilError: Raises exception if mcpd does not come up within
                             roughly 50 minutes (100 * 30 seconds)
        """
        for retries in range(1, 100):  # pylint: disable=W0612
            # Retry unt
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `__CRYPT_IMPORTED__`
- `crypt`
- `crypt.password`
- `crypt.salt`
- `%REPO%/azurelinuxagent/common/future.py.array_to_bytes`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil`
- `%REPO%/azurelinuxagent/common/utils/networkutil.py.RouteEntry`
- `%REPO%/azurelinuxagent/common/utils/networkutil.py.NetworkInterfaceCard`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.CommandError`
- `%REPO%/azurelinuxagent/common/osutil/default.py.__RULES_FILES__`
- `%REPO%/azurelinuxagent/common/osutil/default.py.ALL_CPUS_REGEX`
- `%REPO%/azurelinuxagent/common/osutil/default.py.ALL_MEMS_REGEX`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DMIDECODE_CMD`
- `%REPO%/azurelinuxagent/common/osutil/default.py.PRODUCT_ID_FILE`
- `%REPO%/azurelinuxagent/common/osutil/default.py.UUID_PATTERN`
- `%REPO%/azurelinuxagent/common/osutil/default.py.IOCTL_SIOCGIFCONF`
- `%REPO%/azurelinuxagent/common/osutil/default.py.IOCTL_SIOCGIFFLAGS`
- `%REPO%/azurelinuxagent/common/osutil/default.py.IOCTL_SIOCGIFHWADDR`
- `%REPO%/azurelinuxagent/common/osutil/default.py.IFNAMSIZ`
- `%REPO%/azurelinuxagent/common/osutil/default.py.IP_COMMAND_OUTPUT`
- `%REPO%/azurelinuxagent/common/osutil/default.py.STORAGE_DEVICE_PATH`
- `%REPO%/azurelinuxagent/common/osutil/default.py.GEN2_DEVICE_ID`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil.__init__`
- `%REPO%/azurelinu

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

import array
import base64
import datetime
import errno
import fcntl
import glob
import json
import multiprocessing
import os
import platform
import pwd
import random
import re
import shutil
import socket
import string
import struct
import sys
import time
import warnings
from pwd import getpwall

from azurelinuxagent.common.exception import OSUtilError

#
# The 'crypt' package was removed in Python 3.13.
#
# To work around this, on WALinuxAgent 2.12 and 2.13 we added a dependency on legacycrypt and imported crypt from there. From
# WALinuxAgent 2.14, we instead get crypt from the crypt-r package. Lastly, from WALinuxAgent 2.16, we dropped the dependency
# on crypt altogether and instead use the hashing functions on passlib.hash.
#
# The WALinuxAgent that is pre-installed on the VM images works fine on any of those cases, but self-update WALinuxAgent needs
# to do a discovery process to determine what module and function to use. For example, it may be the case that after self
# update, WALinuxAgent is running on a machine where 2.12 was pre-installed and crypt is coming from legacycrypt.
#
# We first try importing from crypt, which may have been installed from the crypt or crypt-r packages, then try
# importing from legacy crypt, and lastly try importing passlib.hash. If none of those work, we raise an exception when
# trying to hash a password. The Provisioning Agent and JIT requests need to hash passwords, so those features would fail
# if none of the required dependencies are installed.
#
__HASH_METHOD_NONE__    = 0  # None of the required
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.get_agent_bin_path`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.set_hostname`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.set_hostname.self`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.set_hostname.hostname`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.read_file`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.set_ini_config`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.write_file`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil._run_command_without_raising`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.restart_ssh_service.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.useradd`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.useradd.self`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil.useradd.username`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSU

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

import socket
import struct
import binascii
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.future import ustr


class FreeBSDOSUtil(DefaultOSUtil):

    def __init__(self):
        super(FreeBSDOSUtil, self).__init__()
        self.agent_conf_file_path = '/usr/local/etc/waagent.conf'
        self._scsi_disks_timeout_set = False
        self.jit_enabled = True

    @staticmethod
    def get_agent_bin_path():
        return "/usr/local/sbin"

    def set_hostname(self, hostname):
        rc_file_path = '/etc/rc.conf'
        conf_file = fileutil.read_file(rc_file_path).split("\n")
        textutil.set_ini_config(conf_file, "hostname", hostname)
        fileutil.write_file(rc_file_path, "\n".join(conf_file))
        self._run_command_without_raising(["hostname", hostname], log_error=False)

    def restart_ssh_service(self):
        return shellutil.run('service sshd restart', chk_err=False)

    def useradd(self, username, expiration=None, comment=None):
        """
        Create user account with 'username'
        """
        userentry = self.get_userentry(username)
        if userentry is not None:
            logger.warn("User {0} already exists, skip useradd", username)
            return

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil._run_clish`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil._run_clish.self`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil._run_clish.cmd`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_command`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.useradd`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.useradd.self`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.useradd.username`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.useradd.expiration`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.useradd.comment`
- `%REPO%/azurelinuxagent/common/logger.py.warn`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.chpasswd`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.chpasswd.self`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.chpasswd.username`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.chpasswd.password`
- `%REPO%/azurelinuxagent/common/osutil/gaia.py.GaiaOSUtil.chpasswd.crypt_id`
- `%REPO%/azurelinuxage

### Source excerpt

````
#
# Copyright 2017 Check Point Software Technologies
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

import base64
import socket
import struct
import time

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.future import ustr, bytebuffer, range, int  # pylint: disable=redefined-builtin
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil


class GaiaOSUtil(DefaultOSUtil):

    def __init__(self):  # pylint: disable=W0235
        super(GaiaOSUtil, self).__init__()

    def _run_clish(self, cmd):
        ret = 0
        out = ""
        for i in range(10):  # pylint: disable=W0612
            try:
                final_command = ["/bin/clish", "-s", "-c", "'{0}'".format(cmd)]
                out = shellutil.run_command(final_command, log_error=True)
                ret = 0
                break
            except shellutil.CommandError as e:
                ret = e.returncode
                out = e.stdout
            except Exception as e:
                ret = -1
                out = ustr(e)

            if 'NMSHST0025' in out:  # Entry for [hostname] already present
                ret = 0
                break
            time.sleep(2)
        return ret, out

    def useradd(self, username, expiration=None, comment=None):
        logger.warn('useradd is not supported on GAiA')

    def chpasswd(self, username, password,
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/osutil/freebsd.py.FreeBSDOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.resolver`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.set_hostname`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.set_hostname.self`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.set_hostname.hostname`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil._run_command_without_raising`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.restart_ssh_service.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.conf_sshd`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.conf_sshd.self`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.conf_sshd.disable_password`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.get_root_username`
- `%REPO%/azurelinuxagent/common/osutil/nsbsd.py.NSBSDOSUtil.get_root_username.self`
- `%REPO%/azure

### Source excerpt

````
#
# Copyright 2018 Stormshield
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

import os

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.osutil.freebsd import FreeBSDOSUtil


class NSBSDOSUtil(FreeBSDOSUtil):
    resolver = None

    def __init__(self):
        super(NSBSDOSUtil, self).__init__()
        self.agent_conf_file_path = '/etc/waagent.conf'

        if self.resolver is None:
            # NSBSD doesn't have a system resolver, configure a python one

            try:
                import dns.resolver
            except ImportError:
                raise OSUtilError("Python DNS resolver not available. Cannot proceed!")

            self.resolver = dns.resolver.Resolver(configure=False)
            servers = []
            cmd = "getconf /usr/Firewall/ConfigFiles/dns Servers | tail -n +2"
            ret, output = shellutil.run_get_output(cmd)  # pylint: disable=W0612
            for server in output.split("\n"):
                if server == '':
                    break
                server = server[:-1]  # remove last '='
                cmd = "grep '{}' /etc/hosts".format(server) + " | awk '{print $1}'"
                ret, ip = shellutil.run_get_output(cmd)
                ip = ip.strip() # Remove new line char
                servers.append(ip)
            self.resolver.nameservers = servers
            dns.resolver.override_system_resolver(self.resolver)

    def set_hostname(self, hostname):
        self._run_command_without_raising(
            ['/usr/Fi
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.UUID_PATTERN`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.get_agent_bin_path`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.get_instance_id`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.get_instance_id.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.set_hostname`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.set_hostname.self`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.set_hostname.hostname`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.write_file`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil._run_command_without_raising`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.restart_ssh_service.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/openbsd.py.OpenBSDOSUtil.start_agent_service`
- `%REPO%/azurelinuxagent/common/osuti

### Source excerpt

````
# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
# Copyright 2017 Reyk Floeter <reyk@openbsd.org>
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
# Requires Python 2.6+ and OpenSSL 1.0+

import os
import re
import time
import glob
import datetime

from azurelinuxagent.common.future import UTC
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.conf as conf

from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.osutil.default import DefaultOSUtil

UUID_PATTERN = re.compile(
    r'^\s*[A-F0-9]{8}(?:\-[A-F0-9]{4}){3}\-[A-F0-9]{12}\s*$',
    re.IGNORECASE)


class OpenBSDOSUtil(DefaultOSUtil):

    def __init__(self):
        super(OpenBSDOSUtil, self).__init__()
        self.jit_enabled = True
        self._scsi_disks_timeout_set = False

    @staticmethod
    def get_agent_bin_path():
        return "/usr/local/sbin"

    def get_instance_id(self):
        ret, output = shellutil.run_get_output("sysctl -n hw.uuid")
        if ret != 0 or UUID_PATTERN.match(output) is None:
            return ""
        return output.strip()

    def set_hostname(self, hostname):
        fileutil.write_file("/etc/myname", "{}\n".format(hostname))
        self._run_command_without_raising(["hostname", hostname], log_error=False)

    def restart_ssh_service(self):
        return shellutil.run('rcctl restart sshd', chk_err=False)

    def start_agent_service(self):
        return shellutil.run('rcctl start {0}'.format(self.service_name), chk_err=False)

    def stop_agent_service(self):
        return s
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/exception.py.CryptError`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.start_network`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.start_network.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.restart_ssh_service`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.restart_ssh_service.self`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.stop_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.stop_agent_service.self`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.start_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.start_agent_service.self`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.register_agent_service`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.register_agent_service.self`
- `%REPO%/azurelinuxagent/common/osutil/redhat.py.Redhat6xOSUtil.unregister_agent_service`
- `%REPO

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

import os  # pylint: disable=W0611
import re  # pylint: disable=W0611
import pwd  # pylint: disable=W0611
import shutil  # pylint: disable=W0611
import socket  # pylint: disable=W0611
import array  # pylint: disable=W0611
import struct  # pylint: disable=W0611
import fcntl  # pylint: disable=W0611
import time  # pylint: disable=W0611
import base64  # pylint: disable=W0611
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr, bytebuffer  # pylint: disable=W0611
from azurelinuxagent.common.exception import OSUtilError, CryptError
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil  # pylint: disable=W0611
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class Redhat6xOSUtil(DefaultOSUtil):

    def __init__(self):
        super(Redhat6xOSUtil, self).__init__()
        self.jit_enabled = True

    def start_network(self):
        return shellutil.run("/sbin/service networking start", chk_err=False)

    def restart_ssh_service(self):
        return shellutil.run("/sbin/service sshd condrestart", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("/sbin/service {0} stop".format(self.service_name), chk_err=False)

    def start_agent_service(self):
        return shellutil.run("/sbin/service {0} start".format(self.service_name), chk_err=False
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.__init__`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.set_hostname`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.set_hostname.self`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.set_hostname.hostname`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.write_file`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil._run_command_without_raising`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.get_dhcp_pid`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.get_dhcp_pid.self`
- `%REPO%/azurelinuxagent/common/osutil/default.py.DefaultOSUtil._get_dhcp_pid`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.is_dhcp_enabled`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.is_dhcp_enabled.self`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.stop_dhcp_service`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.stop_dhcp_service.self`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.start_dhcp_service`
- `%REPO%/azurelinuxagent/common/osutil/suse.py.SUSE11OSUtil.start_dhcp_service.self`
- `%REPO%/azurelinuxagent/common/osutil/s

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

import time

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil  # pylint: disable=W0611
from azurelinuxagent.common.exception import OSUtilError  # pylint: disable=W0611
from azurelinuxagent.common.future import ustr  # pylint: disable=W0611
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class SUSE11OSUtil(DefaultOSUtil):
    def __init__(self):
        super(SUSE11OSUtil, self).__init__()
        self.jit_enabled = True
        self.dhclient_name = 'dhcpcd'

    def set_hostname(self, hostname):
        fileutil.write_file('/etc/HOSTNAME', hostname)
        self._run_command_without_raising(["hostname", hostname], log_error=False)

    def get_dhcp_pid(self):
        return self._get_dhcp_pid(["pidof", self.dhclient_name])

    def is_dhcp_enabled(self):
        return True

    def stop_dhcp_service(self):
        self._run_command_without_raising(["/sbin/service", self.dhclient_name, "stop"], log_error=False)

    def start_dhcp_service(self):
        self._run_command_without_raising(["/sbin/service", self.dhclient_name, "start"], log_error=False)

    def start_network(self):
        self._run_command_without_raising(["/sbin/service", "network", "start"], log_error=False)

    def restart_ssh_service(self):
        self._run_command_without_raising(["/sbin/service", "sshd", "restart"], log_error=False)

    def stop_agent_service(self):
        self._run_command_without_raising(["/sbin/service", self.service
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.HttpError`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_VERSION`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.Observation`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.Observation.__init__`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.Observation.__init__.self`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.Observation.__init__.name`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.Observation.__init__.is_healthy`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.Observation.__init__.description`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.Observation.__init__.value`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.Observation.as_obj`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.Observation.as_obj.self`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.HealthService`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.HealthService.ENDPOINT`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.HealthService.API`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.HealthService.VERSION`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.HealthService.OBSERVER_NAME`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.HealthService.HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME`
- `%REPO%/azurelinuxagent/common/protocol/health

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

import json

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import restutil
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION


class Observation(object):
    def __init__(self, name, is_healthy, description='', value=''):
        if name is None:
            raise ValueError("Observation name must be provided")

        if is_healthy is None:
            raise ValueError("Observation health must be provided")

        if value is None:
            value = ''

        if description is None:
            description = ''

        self.name = name
        self.is_healthy = is_healthy
        self.description = description
        self.value = value

    @property
    def as_obj(self):
        return {
            "ObservationName": self.name[:64],
            "IsHealthy": self.is_healthy,
            "Description": self.description[:128],
            "Value": self.value[:128]
        }


class HealthService(object):

    ENDPOINT = 'http://{0}:80/HealthService'
    API = 'reporttargethealth'
    VERSION = "1.0"
    OBSERVER_NAME = 'WALinuxAgent'
    HOST_PLUGIN_HEARTBEAT_OBSERVATION_NAME = 'GuestAgentPluginHeartbeat'
    HOST_PLUGIN_STATUS_OBSERVATION_NAME = 'GuestAgentPluginStatus'
    HOST_PLUGIN_VERSIONS_OBSERVATION_NAME = 'GuestAgentPluginVersions'
    HOST_PLUGIN_ARTIFACT_OBSERVATION_NAME = 'GuestAgentPluginArtifact'
    IMDS_OBSERVATION_NAME = 'InstanceMetadat
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.HttpError`
- `%REPO%/azurelinuxagent/common/exception.py.ResourceGoneError`
- `%REPO%/azurelinuxagent/common/datacontract.py.DataContract`
- `%REPO%/azurelinuxagent/common/datacontract.py.set_properties`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.IMDS_ENDPOINT`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.APIVERSION`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.BASE_METADATA_URI`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.IMDS_IMAGE_ORIGIN_UNKNOWN`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.IMDS_IMAGE_ORIGIN_CUSTOM`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.IMDS_IMAGE_ORIGIN_ENDORSED`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.IMDS_IMAGE_ORIGIN_PLATFORM`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.MetadataResult`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.IMDS_RESPONSE_SUCCESS`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.IMDS_RESPONSE_ERROR`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.IMDS_CONNECTION_ERROR`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.IMDS_INTERNAL_SERVER_ERROR`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.get_imds_client`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.ImdsClient`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.ENDORSED_IMAGE_INFO_MATCHER_JSON`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.ImageInfoMatcher`
- `%REPO%/azurelinuxagent/c

### Source excerpt

````
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
import json
import re
from collections import namedtuple

import azurelinuxagent.common.utils.restutil as restutil
from azurelinuxagent.common.exception import HttpError, ResourceGoneError
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.datacontract import DataContract, set_properties
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion

IMDS_ENDPOINT = '169.254.169.254'
APIVERSION = '2018-02-01'
BASE_METADATA_URI = "http://{0}/metadata/{1}?api-version={2}"

IMDS_IMAGE_ORIGIN_UNKNOWN = 0
IMDS_IMAGE_ORIGIN_CUSTOM = 1
IMDS_IMAGE_ORIGIN_ENDORSED = 2
IMDS_IMAGE_ORIGIN_PLATFORM = 3

MetadataResult = namedtuple('MetadataResult', ['success', 'service_error', 'response'])
IMDS_RESPONSE_SUCCESS = 0
IMDS_RESPONSE_ERROR = 1
IMDS_CONNECTION_ERROR = 2
IMDS_INTERNAL_SERVER_ERROR = 3


def get_imds_client():
    return ImdsClient()


# A *slightly* future proof list of endorsed distros.
#  -> e.g. I have predicted the future and said that 20.04-LTS will exist
#     and is endored.
#
# See https://docs.microsoft.com/en-us/azure/virtual-machines/linux/endorsed-distros for
# more details.
#
# This is not an exhaustive list. This is a best attempt to mark images as
# endorsed or not.  Image publishers do not encode all of the requisite information
# in their publisher, offer, sku, and version to definitively mark something as
# endorsed or not.  This is not perfect, but it is approximately 98% perfect.
ENDORSED_IMAGE_INFO_MATCHER_JSON = """{
    "CANONICAL": {
        "UBUNTUSERVER": {
            "List": [
                "14.04.0-LTS",
                "14.04.1-LTS",
                "14.04.2-LTS",
                "14.04.3-LTS",
                "14.04.4-LTS",
                "14.04.5-LTS",
                "14.04.6-LTS",
                "14.04.7-LTS",
                "14.04.8-LTS",

                "16.04-LTS",
                "16.04.0-LTS",
                "18.04-LTS",
                "20.04-LTS",
                "22.04-LTS"
            ]
        }
    },
    "COR
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.ProtocolError`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.parse_doc`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findall`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.find`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findtext`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OVF_VERSION`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OVF_NAME_SPACE`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.WA_NAME_SPACE`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py._validate_ovf`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py._validate_ovf.val`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py._validate_ovf.msg`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OvfEnv`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OvfEnv.__init__`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OvfEnv.__init__.self`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OvfEnv.__init__.xml_text`
- `%REPO%/azurelinuxagent/common/logger.py.verbose`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OvfEnv.parse`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OvfEnv.parse.self`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OvfEnv.parse.xml_text`
- `%REPO%/azurelinuxagent/common/logger.py.warn`

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
"""
Copy and parse ovf-env.xml from provisioning ISO and local cache
"""
import os  # pylint: disable=W0611
import re  # pylint: disable=W0611
import shutil  # pylint: disable=W0611
import xml.dom.minidom as minidom  # pylint: disable=W0611
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.exception import ProtocolError
from azurelinuxagent.common.future import ustr  # pylint: disable=W0611
import azurelinuxagent.common.utils.fileutil as fileutil  # pylint: disable=W0611
from azurelinuxagent.common.utils.textutil import parse_doc, findall, find, findtext

OVF_VERSION = "1.0"
OVF_NAME_SPACE = "http://schemas.dmtf.org/ovf/environment/1"
WA_NAME_SPACE = "http://schemas.microsoft.com/windowsazure"

def _validate_ovf(val, msg):
    if val is None:
        raise ProtocolError("Failed to validate OVF: {0}".format(msg))


class OvfEnv(object):
    """
    Read, and process provisioning info from provisioning file OvfEnv.xml
    """
    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("ovf-env is None")
        logger.verbose("Load ovf-env.xml")
        self.hostname = None
        self.username = None
        self.user_password = None
        self.customdata = None
        self.disable_ssh_password_auth = True
        self.ssh_pubkeys = []
        self.ssh_keypairs = []
        self.provision_guest_agent = None
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        Parse xml tree, retreiving user and ssh key information.
        Retu
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.CryptError`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.DECRYPT_SECRET_CMD`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.__init__`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.__init__.self`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.__init__.openssl_cmd`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.gen_transport_cert`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.gen_transport_cert.self`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.gen_transport_cert.prv_file`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.gen_transport_cert.crt_file`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_command`
- `%REPO%/azurelinuxagent/common/logger.py.error`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.get_pubkey_from_prv`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.get_pubkey_from_prv.self`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.get_pubkey_from_prv.file_name`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.get_pubkey_from_crt`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.get_pubkey_from_crt.self`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.get_pubkey_from_crt.file_name`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil.get_thumbprint_fro

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

import base64
import errno
import struct
import os.path
import subprocess

from azurelinuxagent.common.future import ustr, bytebuffer
from azurelinuxagent.common.exception import CryptError

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil


DECRYPT_SECRET_CMD = "{0} cms -decrypt -inform DER -inkey {1} -in /dev/stdin"


class CryptUtil(object):
    def __init__(self, openssl_cmd):
        self.openssl_cmd = openssl_cmd

    def gen_transport_cert(self, prv_file, crt_file):
        """
        Create ssl certificate for https communication with endpoint server.
        """
        cmd = [self.openssl_cmd, "req", "-x509", "-nodes", "-subj", "/CN=LinuxTransport",
            "-days", "730", "-newkey", "rsa:2048", "-keyout", prv_file, "-out", crt_file]
        try:
            shellutil.run_command(cmd)
        except shellutil.CommandError as cmd_err:
            msg = "Failed to create {0} and {1} certificates.\n[stdout]\n{2}\n\n[stderr]\n{3}\n"\
                .format(prv_file, crt_file, cmd_err.stdout, cmd_err.stderr)
            logger.error(msg)

    def get_pubkey_from_prv(self, file_name):
        if not os.path.exists(file_name):
            raise IOError(errno.ENOENT, "File not found", file_name)

        # OpenSSL's pkey command may not be available on older versions so try 'rsa' first.
        try:
            command = [self.openssl_cmd, "rsa", "-in", file_name, "-pubout"]
            return shellutil.run_command(command, log_error=False)

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.HttpError`
- `%REPO%/azurelinuxagent/common/exception.py.ResourceGoneError`
- `%REPO%/azurelinuxagent/common/exception.py.InvalidContainerError`
- `%REPO%/azurelinuxagent/common/version.py.PY_VERSION_MAJOR`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.GOAL_STATE_AGENT_VERSION`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.SECURE_WARNING_EMITTED`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.DEFAULT_RETRIES`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.DELAY_IN_SECONDS`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.THROTTLE_RETRIES`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.THROTTLE_DELAY_IN_SECONDS`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.TELEMETRY_THROTTLE_DELAY_IN_SECONDS`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.TELEMETRY_FLUSH_THROTTLE_DELAY_IN_SECONDS`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.RETRY_CODES`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.HGAP_GET_EXTENSION_ARTIFACT_RETRY_CODES`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.RESOURCE_GONE_CODES`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.OK_CODES`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.NOT_MODIFIED_CODES`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.HOSTPLUGIN_UPSTREAM_FAILURE_CODES`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.THROTTLE_CODES`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.RETRY_EXCEPTIONS

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

import json
import os
import threading
import time
import socket
import struct

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.textutil as textutil

from azurelinuxagent.common.exception import HttpError, ResourceGoneError
from azurelinuxagent.common.future import httpclient, urlparse, ustr
from azurelinuxagent.common.version import PY_VERSION_MAJOR, AGENT_NAME, GOAL_STATE_AGENT_VERSION

SECURE_WARNING_EMITTED = False

DEFAULT_RETRIES = 6
DELAY_IN_SECONDS = 1

FAIL_FAST_REQUEST_TIMEOUT = 5

THROTTLE_RETRIES = 25
THROTTLE_DELAY_IN_SECONDS = 1
# Reducing next attempt calls when throttled since telemetrydata endpoint has a limit 15 calls per 15 secs,
TELEMETRY_THROTTLE_DELAY_IN_SECONDS = 8
# Considering short delay for telemetry flush imp events
TELEMETRY_FLUSH_THROTTLE_DELAY_IN_SECONDS = 2

RETRY_CODES = [
    httpclient.RESET_CONTENT,
    httpclient.PARTIAL_CONTENT,
    httpclient.FORBIDDEN,
    httpclient.INTERNAL_SERVER_ERROR,
    httpclient.NOT_IMPLEMENTED,
    httpclient.BAD_GATEWAY,
    httpclient.SERVICE_UNAVAILABLE,
    httpclient.GATEWAY_TIMEOUT,
    httpclient.INSUFFICIENT_STORAGE,
    429,  # Request Rate Limit Exceeded
]

#
# Currently the HostGAPlugin has an issue its cache that may produce a BAD_REQUEST failure for valid URIs when using the extensionArtifact API.
# Add this status to the retryable codes, but use it only when requesting downloads via the HostGAPlugin. The retry logic in the download code
# would give enough
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.ResourceDiskError`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler.__init__`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler.__init__.self`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler.parse_gpart_list`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler.parse_gpart_list.data`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler.mount_resource_disk`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler.mount_resource_disk.self`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler.mount_resource_disk.mount_point`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.mkdir`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler.create_swap_space`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler.create_swap_space.self`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/freebsd.py.FreeBSDResourceDiskHandler.create_swap

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
import os
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import ResourceDiskError
from azurelinuxagent.daemon.resourcedisk.default import ResourceDiskHandler


class FreeBSDResourceDiskHandler(ResourceDiskHandler):
    """
    This class handles resource disk mounting for FreeBSD.

    The resource disk locates at following slot:
    scbus2 on blkvsc1 bus 0:
    <Msft Virtual Disk 1.0>            at scbus2 target 1 lun 0 (da1,pass2)

    There are 2 variations based on partition table type:
    1. MBR: The resource disk partition is /dev/da1s1
    2. GPT: The resource disk partition is /dev/da1p2, /dev/da1p1 is for reserved usage.
    """

    def __init__(self):  # pylint: disable=W0235
        super(FreeBSDResourceDiskHandler, self).__init__()

    @staticmethod
    def parse_gpart_list(data):
        dic = {}
        for line in data.split('\n'):
            if line.find("Geom name: ") != -1:
                geom_name = line[11:]
            elif line.find("scheme: ") != -1:
                dic[geom_name] = line[8:]
        return dic

    def mount_resource_disk(self, mount_point):
        fs = self.fs
        if fs != 'ufs':
            raise ResourceDiskError(
                "Unsupported filesystem type:{0}, only ufs is supported.".format(fs))

        # 1. Detect device
        err, output = shellutil.run_get_out
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.ResourceDiskError`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler.__init__`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler.__init__.self`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler.create_swap_space`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler.create_swap_space.self`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler.create_swap_space.mount_point`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler.create_swap_space.size_mb`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler.enable_swap`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler.enable_swap.self`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler.enable_swap.mount_point`
- `%REPO%/azurelinuxagent/common/conf.py.get_resourcedisk_swap_size_mb`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output`
- `%REPO%/azurelinuxagent/common/logger.py.error`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openbsd.py.OpenBSDResourceDiskHandler.mount_resou

### Source excerpt

````
# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
# Copyright 2017 Reyk Floeter <reyk@openbsd.org>
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
# Requires Python 2.6+ and OpenSSL 1.0+
#
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import ResourceDiskError
from azurelinuxagent.daemon.resourcedisk.default import ResourceDiskHandler

class OpenBSDResourceDiskHandler(ResourceDiskHandler):
    def __init__(self):
        super(OpenBSDResourceDiskHandler, self).__init__()
        # Fase File System (FFS) is UFS
        if self.fs == 'ufs' or self.fs == 'ufs2':
            self.fs = 'ffs'

    def create_swap_space(self, mount_point, size_mb):
        pass

    def enable_swap(self, mount_point):
        size_mb = conf.get_resourcedisk_swap_size_mb()
        if size_mb:
            logger.info("Enable swap")
            device = self.osutil.device_for_ide_port(1)
            err, output = shellutil.run_get_output("swapctl -a /dev/"
                                                   "{0}b".format(device),
                                                   chk_err=False)
            if err:
                logger.error("Failed to enable swap, error {0}", output)

    def mount_resource_disk(self, mount_point):
        fs = self.fs
        if fs != 'ffs':
            raise ResourceDiskError("Unsupported filesystem type: {0}, only "
                                    "ufs/ffs is supported.".format(fs))

        # 1. Get device
        device = self.osutil.device_
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.ResourceDiskError`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openwrt.py.OpenWRTResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openwrt.py.OpenWRTResourceDiskHandler.__init__`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openwrt.py.OpenWRTResourceDiskHandler.__init__.self`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openwrt.py.OpenWRTResourceDiskHandler.reread_partition_table`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openwrt.py.OpenWRTResourceDiskHandler.reread_partition_table.self`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openwrt.py.OpenWRTResourceDiskHandler.reread_partition_table.device`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output`
- `%REPO%/azurelinuxagent/common/logger.py.warn`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openwrt.py.OpenWRTResourceDiskHandler.mount_resource_disk`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openwrt.py.OpenWRTResourceDiskHandler.mount_resource_disk.self`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/openwrt.py.OpenWRTResourceDiskHandler.mount_resource_disk.mount_point`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.mkdir`
- `%REPO%/azurelinuxagent/common/logger.py.error`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler.change_partition_type`
- `%REPO%/azurelinuxagent/common/util

### Source excerpt

````
# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
# Copyright 2018 Sonus Networks, Inc. (d.b.a. Ribbon Communications Operating Company)
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
from time import sleep

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.exception import ResourceDiskError
from azurelinuxagent.daemon.resourcedisk.default import ResourceDiskHandler

class OpenWRTResourceDiskHandler(ResourceDiskHandler):
    def __init__(self):
        super(OpenWRTResourceDiskHandler, self).__init__()
        # Fase File System (FFS) is UFS
        if self.fs == 'ufs' or self.fs == 'ufs2':
            self.fs = 'ffs'

    def reread_partition_table(self, device):
        ret, output = shellutil.run_get_output("hdparm -z {0}".format(device), chk_err=False)  # pylint: disable=W0612
        if ret != 0:
            logger.warn("Failed refresh the partition table.")

    def mount_resource_disk(self, mount_point):
        device = self.osutil.device_for_ide_port(1)
        if device is None:
            raise ResourceDiskError("unable to detect disk topology")
        logger.info('Resource disk device {0} found.', device)

        # 2. Get partition
        device = "/dev/{0}".format(device)
        partition = device + "1"
        logger.info('Resource disk partition {0} found.', partition)

        # 3. Mount partition
        mount_list = shellutil.run_get_output("mount")[1]
        existing = self.osutil.get_mount_poi
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.CGroupsException`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py._REPORT_EVERY_HOUR`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py._DEFAULT_REPORT_PERIOD`
- `%REPO%/azurelinuxagent/common/conf.py.get_cgroup_check_period`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.AGENT_NAME_TELEMETRY`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.AGENT_LOG_COLLECTOR`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.CounterNotFound`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.__init__`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.__init__.self`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.__init__.category`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.__init__.counter`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.__init__.instance`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.__init__.value`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.__init__.report_period`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.category`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.category.self`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.counter`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.counter.self`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue.instance`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py

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

import errno
import glob
import os
from datetime import timedelta

from azurelinuxagent.common import logger, conf
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import fileutil

_REPORT_EVERY_HOUR = timedelta(hours=1)

AGENT_NAME_TELEMETRY = "walinuxagent.service"  # Name used for telemetry; it needs to be consistent even if the name of the service changes
AGENT_LOG_COLLECTOR = "azure-walinuxagent-logcollector"


class CounterNotFound(Exception):
    pass


class MetricValue(object):
    """
    Class for defining all the required metric fields to send telemetry.
    """

    def __init__(self, category, counter, instance, value, report_period=None):
        self._category = category
        self._counter = counter
        self._instance = instance
        self._value = value
        self._report_period = timedelta(seconds=conf.get_cgroup_check_period()) if report_period is None else report_period

    @property
    def category(self):
        return self._category

    @property
    def counter(self):
        return self._counter

    @property
    def instance(self):
        return self._instance

    @property
    def value(self):
        return self._value

    @property
    def report_period(self):
        return self._report_period


class MetricsCategory(object):
    MEMORY_CATEGORY = "Memory"
    CPU_CATEGORY = "CPU"


class MetricsCounter(object):
    PROCESSOR_PERCENT_TIME = "% Processor Time"
    THROTTLED_TIME = "Throttled Time (s)"
    TO
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.CGroupsException`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py._CgroupController`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricsCategory`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricsCounter`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py.re_v1_user_system_times`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py.re_v2_usage_time`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController.__init__`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController.__init__.self`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController.__init__.name`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController.__init__.cgroup_path`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController._get_cpu_stat_counter`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController._get_cpu_stat_counter.self`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController._get_cpu_stat_counter.counter_name`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController._cpu_usage_initialized`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController._cpu_usage_initialized.self`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController.initialize_cpu_usage`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController.initialize_cpu_usage

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

import errno
import os
import re

from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.ga.cgroupcontroller import _CgroupController, MetricValue, MetricsCategory, MetricsCounter

re_v1_user_system_times = re.compile(r'user (\d+)\nsystem (\d+)\n')
re_v2_usage_time = re.compile(r'[\s\S]*usage_usec (\d+)[\s\S]*')


class _CpuController(_CgroupController):
    def __init__(self, name, cgroup_path):
        super(_CpuController, self).__init__(name, cgroup_path)

        self._osutil = get_osutil()
        self._previous_cgroup_cpu = None
        self._previous_system_cpu = None
        self._current_cgroup_cpu = None
        self._current_system_cpu = None
        self._previous_throttled_time = None
        self._current_throttled_time = None
        self._track_throttle_time = False

    def _get_cpu_stat_counter(self, counter_name):
        """
        Gets the value for the provided counter in cpu.stat
        """
        try:
            with open(os.path.join(self.path, 'cpu.stat')) as cpu_stat:
                #
                # Sample file v1:
                #   # cat cpu.stat
                #   nr_periods  51660
                #   nr_throttled 19461
                #   throttled_time 1529590856339
                #
                # Sample file v2
                #   # cat cpu.stat
                #   usage_usec 200161503
                #   user_usec 199388368
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.AgentUpdateError`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateSource`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_DIR_PATTERN`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_VERSION`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgent`
- `%REPO%/azurelinuxagent/ga/guestagent.py.AGENT_MANIFEST_FILE`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater.__init__`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater.__init__.self`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater.__init__.gs_id`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater.is_update_allowed_this_time`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater.is_update_allowed_this_time.self`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater.is_update_allowed_this_time.ext_gs_updated`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater.is_rsm_update_enabled`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater.is_rsm_update_enabled.self`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater.is_rsm_update_enabled.agent_family`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionU

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

import glob
import json
import os
import shutil

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpdateError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.extensions_goal_state import GoalStateSource
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_NAME, AGENT_DIR_PATTERN, CURRENT_VERSION
from azurelinuxagent.ga.exthandlers import HandlerManifest
from azurelinuxagent.ga.guestagent import GuestAgent, AGENT_MANIFEST_FILE
from azurelinuxagent.ga.signature_validation_util import agent_signature_validation_enabled, report_validation_event, \
    SignatureValidationError, SignatureValidationTimeoutError, SignatureValidationTimeout, \
    validate_agent_manifest_signing_info, ManifestValidationError


class GAVersionUpdater(object):

    def __init__(self, gs_id):
        self._gs_id = gs_id
        self._version = FlexibleVersion("0.0.0.0")  # Initialize to zero and retrieve from goal state later stage
        self._agent_manifest = None  # Initialize to None and fetch from goal state at different stage for different updater

    def is_update_allowed_this_time(self, ext_gs_updated):
        """
        This function checks if we allowed to update the agent.
        @param ext_gs_updated: True if extension goal state updated else False

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/exception.py.CGroupsException`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py._CgroupController`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.CounterNotFound`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricsCategory`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricsCounter`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py._REPORT_EVERY_HOUR`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController.__init__`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController.__init__.self`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController.__init__.name`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController.__init__.cgroup_path`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController._get_memory_stat_counter`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController._get_memory_stat_counter.self`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController._get_memory_stat_counter.counter_name`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController.get_memory_usage`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController.get_memory_usage.self`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController.try_swap_memory_usage`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController.try_swap_memo

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

import errno
import os
import re

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.ga.cgroupcontroller import _CgroupController, CounterNotFound, MetricValue, MetricsCategory, \
    MetricsCounter, _REPORT_EVERY_HOUR


class _MemoryController(_CgroupController):
    def __init__(self, name, cgroup_path):
        super(_MemoryController, self).__init__(name, cgroup_path)
        self._counter_not_found_error_count = 0

    def _get_memory_stat_counter(self, counter_name):
        """
        Gets the value for the provided counter in memory.stat
        """
        try:
            with open(os.path.join(self.path, 'memory.stat')) as memory_stat:
                #
                # Sample file v1:
                #   # cat memory.stat
                #   cache 0
                #   rss 0
                #   rss_huge 0
                #   shmem 0
                #   mapped_file 0
                #   dirty 0
                #   writeback 0
                #   swap 0
                #   ...
                #
                # Sample file v2
                #   # cat memory.stat
                #   anon 0
                #   file 147140608
                #   kernel 1421312
                #   kernel_stack 0
                #   pagetables 0
                #   sec_pagetables 0
                #   percpu 130752
                #   sock 0
                #   ...
                #
                for line in memory_stat:

````

---

## setup.py

### Structural symbols

N/A

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


````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.elapsed_milliseconds`
- `%REPO%/azurelinuxagent/common/exception.py.ProvisionError`
- `%REPO%/azurelinuxagent/common/exception.py.ProtocolError`
- `%REPO%/azurelinuxagent/common/protocol/util.py.OVF_FILE_NAME`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OvfEnv`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler`
- `%REPO%/azurelinuxagent/pa/provision/cloudinitdetect.py.cloud_init_is_enabled`
- `%REPO%/azurelinuxagent/pa/provision/cloudinit.py.CloudInitProvisionHandler`
- `%REPO%/azurelinuxagent/pa/provision/cloudinit.py.CloudInitProvisionHandler.__init__`
- `%REPO%/azurelinuxagent/pa/provision/cloudinit.py.CloudInitProvisionHandler.__init__.self`
- `%REPO%/azurelinuxagent/pa/provision/cloudinit.py.CloudInitProvisionHandler.run`
- `%REPO%/azurelinuxagent/pa/provision/cloudinit.py.CloudInitProvisionHandler.run.self`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/pa/provision/cloudinit.py.CloudInitProvisionHandler.wait_for_ovfenv`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler.report_not_ready`
- `%REPO%/azurelinuxagent/pa/provision/cloudinit.py.CloudInitProvisionHandler.wait_for_ssh_host_key`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler.write_provisioned`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler.report_ready`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler.report_event`
- `%REPO%/azurelinuxagent/pa/p

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

import os
import os.path
import time

from datetime import datetime

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.event import elapsed_milliseconds
from azurelinuxagent.common.exception import ProvisionError, ProtocolError
from azurelinuxagent.common.future import ustr, UTC
from azurelinuxagent.common.protocol.util import OVF_FILE_NAME
from azurelinuxagent.common.protocol.ovfenv import OvfEnv
from azurelinuxagent.pa.provision.default import ProvisionHandler
from azurelinuxagent.pa.provision.cloudinitdetect import cloud_init_is_enabled


class CloudInitProvisionHandler(ProvisionHandler):
    def __init__(self):  # pylint: disable=W0235
        super(CloudInitProvisionHandler, self).__init__()

    def run(self):
        try:
            if super(CloudInitProvisionHandler, self).check_provisioned_file():
                logger.info("Provisioning already completed, skipping.")
                return

            utc_start = datetime.now(UTC)
            logger.info("Running CloudInit provisioning handler")
            self.wait_for_ovfenv()
            self.wait_for_ssh_host_key()
            self.write_provisioned()
            logger.info("Finished provisioning")

            self.report_event("Provisioning with cloud-init succeeded ({0}s)".format(self._get_uptime_seconds()),
                is_success=True,
                duration=elapsed_milliseconds(utc_start))

        except Prov
````

---
