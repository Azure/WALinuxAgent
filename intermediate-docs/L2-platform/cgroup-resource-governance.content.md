# Compose Content for: L2-platform/cgroup-resource-governance.md

Total files: 3

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.AGENT_NAME_TELEMETRY`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricsCounter`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.SystemdRunError`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.EXTENSION_SLICE_PREFIX`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.CGroupUtil`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.SystemdCgroupApiv2`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.log_cgroup_info`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.log_cgroup_warning`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.create_cgroup_api`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.InvalidCgroupMountpointException`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py._MemoryController`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionErrorCodes`
- `%REPO%/azurelinuxagent/common/exception.py.CGroupsException`
- `%REPO%/azurelinuxagent/common/exception.py.AgentMemoryExceededException`
- `%REPO%/azurelinuxagent/common/version.py.get_distro`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.handle_process_completion`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py.AZURE_SLICE`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py._AZURE_SLICE_CONTENTS`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py._VMEXTENSIONS_SLICE`


### Source excerpt

````
# -*- encoding: utf-8 -*-
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
import glob
import json
import os
import re
import subprocess
import threading

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.ga.cgroupcontroller import AGENT_NAME_TELEMETRY, MetricsCounter
from azurelinuxagent.ga.cgroupapi import SystemdRunError, EXTENSION_SLICE_PREFIX, CGroupUtil, SystemdCgroupApiv2, \
    log_cgroup_info, log_cgroup_warning, create_cgroup_api, InvalidCgroupMountpointException
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.ga.cpucontroller import _CpuController
from azurelinuxagent.ga.memorycontroller import _MemoryController
from azurelinuxagent.common.exception import ExtensionErrorCodes, CGroupsException, AgentMemoryExceededException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.version import get_distro
from azurelinuxagent.common.utils import shellutil, fileutil
from azurelinuxagent.ga.extensionprocessutil import handle_process_completion
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.ga.resourcequota import CpuQuota, MemoryQuota, ResourceName

AZURE_SLICE = "azure.slice"
_AZURE_SLICE_CONTENTS = """
[Unit]
Description=Slice for Azure VM Agent and Extensions
DefaultDependencies=no
Before=slices.target
"""
_VMEXTENSIONS_SLICE = EXTENSION_SLICE_PREFIX + ".slice"
_AZURE_VMEXTENSIONS_SLICE = AZURE_SLICE + "/" + _VMEXTENSIONS_SLICE
_VMEXTENSIONS_SLICE_CONTENTS = """
[Unit]
Description=Sli
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricsCounter`
- `%REPO%/azurelinuxagent/common/event.py.elapsed_milliseconds`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/ga/interfaces.py.ThreadHandlerInterface`
- `%REPO%/azurelinuxagent/ga/logcollector.py.COMPRESSED_ARCHIVE_PATH`
- `%REPO%/azurelinuxagent/ga/logcollector.py.GRACEFUL_KILL_ERRCODE`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py.CGroupConfigurator`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py.LOGCOLLECTOR_ANON_MEMORY_LIMIT_FOR_V1_AND_V2`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py.LOGCOLLECTOR_CACHE_MEMORY_LIMIT_FOR_V1_AND_V2`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py.LOGCOLLECTOR_MAX_THROTTLED_EVENTS_FOR_V2`
- `%REPO%/azurelinuxagent/common/protocol/util.py.get_protocol_util`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.CommandError`
- `%REPO%/azurelinuxagent/common/version.py.PY_VERSION_MAJOR`
- `%REPO%/azurelinuxagent/common/version.py.PY_VERSION_MINOR`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_VERSION`
- `%REPO%/azurelinuxagent/ga/collect_logs.py.get_collect_logs_handler`
- `%REPO%/azurelinuxagent/ga/collect_logs.py.CollectLogsHandler`
- `%REPO%/azurelinuxagent/ga/collect_logs.py.is_log_collection_allowed`
- `%REPO%/azurelinuxagent/common/conf.py.get_collect_logs`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.p

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
import datetime
import os
import sys
import threading
import time
from azurelinuxagent.ga import logcollector, cgroupconfigurator

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common import logger
from azurelinuxagent.ga.cgroupcontroller import MetricsCounter
from azurelinuxagent.common.event import elapsed_milliseconds, add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr, UTC
from azurelinuxagent.ga.interfaces import ThreadHandlerInterface
from azurelinuxagent.ga.logcollector import COMPRESSED_ARCHIVE_PATH, GRACEFUL_KILL_ERRCODE
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator, LOGCOLLECTOR_ANON_MEMORY_LIMIT_FOR_V1_AND_V2, LOGCOLLECTOR_CACHE_MEMORY_LIMIT_FOR_V1_AND_V2, LOGCOLLECTOR_MAX_THROTTLED_EVENTS_FOR_V2
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.shellutil import CommandError
from azurelinuxagent.common.version import PY_VERSION_MAJOR, PY_VERSION_MINOR, AGENT_NAME, CURRENT_VERSION


def get_collect_logs_handler():
    return CollectLogsHandler()


def is_log_collection_allowed():
    # There are three conditions that need to be met in order to allow periodic log collection:
    # 1) It should be enabled in the configuration.
    # 2) The system must be using cgroups to manage services - needed for resource limiting of the log collection. The
    # agent currently fully supports resource limiting for v1, but only supports log collector res
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricValue`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricsCategory`
- `%REPO%/azurelinuxagent/ga/cgroupcontroller.py.MetricsCounter`
- `%REPO%/azurelinuxagent/ga/cgroupconfigurator.py.CGroupConfigurator`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry`
- `%REPO%/azurelinuxagent/common/errorstate.py.ErrorState`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.report_metric`
- `%REPO%/azurelinuxagent/ga/interfaces.py.ThreadHandlerInterface`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/protocol/healthservice.py.HealthService`
- `%REPO%/azurelinuxagent/common/protocol/imds.py.get_imds_client`
- `%REPO%/azurelinuxagent/common/protocol/util.py.get_protocol_util`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.IOErrorCounter`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_VERSION`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation`
- `%REPO%/azurelinuxagent/ga/monitor.py.get_monitor_handler`
- `%REPO%/azurelinuxagent/ga/monitor.py.MonitorHandler`
- `%REPO%/azurelinuxagent/ga/monitor.py.PollResourceUsage`
- `%REPO%/azurelinuxagent/ga/monitor.py.PollResourceUsage.__init__`
- `%REPO%/azurelinuxagent/ga/monitor.py.PollResourceUsage.__init__.self`
- `%REPO%/azurelinuxagent/c

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

import datetime
import os
import platform
import threading

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.networkutil as networkutil
from azurelinuxagent.ga.cgroupcontroller import MetricValue, MetricsCategory, MetricsCounter
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.errorstate import ErrorState
from azurelinuxagent.common.event import add_event, WALAEventOperation, report_metric
from azurelinuxagent.common.future import ustr, UTC
from azurelinuxagent.ga.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.healthservice import HealthService
from azurelinuxagent.common.protocol.imds import get_imds_client
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils.restutil import IOErrorCounter
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.ga.kernel_event_monitor import MonitorKernelSoftLockup
from azurelinuxagent.ga.periodic_operation import PeriodicOperation


def get_monitor_handler():
    return MonitorHandler()


class PollResourceUsage(PeriodicOperation):
    """
    Periodic operation to poll the tracked cgroups for resource usage data.

    It also checks whether there are processes in the agent's cgroup that should not be there.

    """
    def __init__(self):
        super(Pol
````

---
