# Compose Content for: L2-platform/agent-event-reporting.md

Total files: 20

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionsConfigError`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.ExtensionsGoalState`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateChannel`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state.py.GoalStateSource`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.ExtensionSettings`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.Extension`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMAgentFamily`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.ExtensionState`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.InVMGoalStateMetaData`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.parse_doc`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.parse_json`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findall`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.find`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findtext`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.getattrib`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.gettext`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.format_exception`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.is_str_none_or_whitespace`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.is_str_empty`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.gettextxml`
- `%REPO%/

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
import json

from collections import defaultdict

from azurelinuxagent.common import logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ExtensionsConfigError
from azurelinuxagent.common.future import ustr, urlparse
from azurelinuxagent.common.protocol.extensions_goal_state import ExtensionsGoalState, GoalStateChannel, GoalStateSource
from azurelinuxagent.common.protocol.restapi import ExtensionSettings, Extension, VMAgentFamily, ExtensionState, InVMGoalStateMetaData
from azurelinuxagent.common.utils.textutil import parse_doc, parse_json, findall, find, findtext, getattrib, gettext, \
    format_exception, is_str_none_or_whitespace, is_str_empty, gettextxml
from azurelinuxagent.ga.confidential_vm_info import ConfidentialVMInfo


class ExtensionsGoalStateFromExtensionsConfig(ExtensionsGoalState):
    def __init__(self, incarnation, xml_text, wire_client):
        super(ExtensionsGoalStateFromExtensionsConfig, self).__init__()
        self._id = "incarnation_{0}".format(incarnation)
        self._is_outdated = False
        self._incarnation = incarnation
        self._text = xml_text
        self._status_upload_blob = None
        self._status_upload_blob_type = None
        self._status_upload_blob_xml_node = None
        self._artifacts_profile_blob_xml_node = None
        self._required_features = []
        self._on_hold = False
        self._activity_id = None
        self._correlation_id = None
        self._created_on_timestamp = None

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py._METADATA_PROTOCOL_NAME`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py._LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py._LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py._LEGACY_METADATA_SERVER_P7B_FILE_NAME`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py._KNOWN_METADATASERVER_IP`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py.is_metadata_server_artifact_present`
- `%REPO%/azurelinuxagent/common/conf.py.get_lib_dir`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py.cleanup_metadata_server_artifacts`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py._cleanup_metadata_protocol_certificates`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py._reset_firewall_rules`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py._ensure_file_removed`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py._remove_firewall`
- `%R

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
import re
import os

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion

# Name for Metadata Server Protocol
_METADATA_PROTOCOL_NAME = "MetadataProtocol"

# MetadataServer Certificates for Cleanup
_LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME = "V2TransportPrivate.pem"
_LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME = "V2TransportCert.pem"
_LEGACY_METADATA_SERVER_P7B_FILE_NAME = "Certificates.p7b"

# MetadataServer Endpoint
_KNOWN_METADATASERVER_IP = "169.254.169.254"


def is_metadata_server_artifact_present():
    metadata_artifact_path = os.path.join(conf.get_lib_dir(), _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME)
    return os.path.isfile(metadata_artifact_path)


def cleanup_metadata_server_artifacts():
    logger.info("Clean up for MetadataServer to WireServer protocol migration: removing MetadataServer certificates and resetting firewall rules.")
    _cleanup_metadata_protocol_certificates()
    _reset_firewall_rules()


def _cleanup_metadata_protocol_certificates():
    """
    Removes MetadataServer Certificates.
    """
    lib_directory = conf.get_lib_dir()
    _ensure_file_removed(lib_directory, _LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME)
    _ensure_file_removed(lib_directory, _LEGACY_METADATA_SERVER_TRANSPORT_
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.initialize_event_logger_vminfo_common_parameters_and_protocol`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/protocol/goal_state.py.GoalState`
- `%REPO%/azurelinuxagent/common/protocol/goal_state.py.GoalStateProperties`
- `%REPO%/azurelinuxagent/common/protocol/util.py.get_protocol_util`
- `%REPO%/azurelinuxagent/pa/rdma/rdma.py.setup_rdma_device`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_LONG_NAME`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_NAME`
- `%REPO%/azurelinuxagent/common/version.py.DISTRO_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.PY_VERSION_MAJOR`
- `%REPO%/azurelinuxagent/common/version.py.PY_VERSION_MINOR`
- `%REPO%/azurelinuxagent/common/version.py.PY_VERSION_MICRO`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/factory.py.get_resourcedisk_handler`
- `%REPO%/azurelinuxagent/daemon/scvmm.py.get_scvmm_handler`
- `%REPO%/azurelinuxagent/ga/update.py.get_update_handler`
- `%REPO%/azurelinuxagent/pa/provision/factory.py.get_provision_handler`
- `%REPO%/azurelinuxagent/pa/rdma/factory.py.get_rdma_handler`
- `%REPO%/azurelinuxagent/daemon/main.py.OPENSSL_FIPS_ENVIRONMENT`
- `%REPO%/azurelinuxagent/daemon/main.py.get_daemon_handle

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
import sys
import time

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.event import add_event, WALAEventOperation, initialize_event_logger_vminfo_common_parameters_and_protocol
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.goal_state import GoalState, GoalStateProperties
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.pa.rdma.rdma import setup_rdma_device
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.version import AGENT_NAME, AGENT_LONG_NAME, \
    AGENT_VERSION, \
    DISTRO_NAME, DISTRO_VERSION, PY_VERSION_MAJOR, PY_VERSION_MINOR, \
    PY_VERSION_MICRO
from azurelinuxagent.daemon.resourcedisk import get_resourcedisk_handler
from azurelinuxagent.daemon.scvmm import get_scvmm_handler
from azurelinuxagent.ga import state_dir
from azurelinuxagent.ga.update import get_update_handler
from azurelinuxagent.pa.provision import get_provision_handler
from azurelinuxagent.pa.rdma import get_rdma_handler

OPENSSL_FIPS_ENVIRONMENT = "OPENSSL_FIPS"


def get_daemon_handler():
    return DaemonHandler()


class DaemonHandler(object):
    """
    Main thread of daemon. It will invoke other threads to do actual work
    """

    def __init__(self):
        self.running = True
        self.osutil = get_osutil()

    def run(self, c
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/exception.py.ResourceDiskError`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.DATALOSS_WARNING_FILE_NAME`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.DATA_LOSS_WARNING`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler.__init__`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler.__init__.self`
- `%REPO%/azurelinuxagent/common/conf.py.get_resourcedisk_filesystem`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler.start_activate_resource_disk`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler.start_activate_resource_disk.self`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler.run`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler.run.self`
- `%REPO%/azurelinuxagent/common/conf.py.get_resourcedisk_format`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler.activate_resource_disk`
- `%REPO%/azurelinuxagent/common/conf.py.get_resourcedisk_enable_swap`
- `%REPO%/azurelinuxagent/daemon/resourcedisk/default.py.ResourceDiskHandler.enable_swa

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

import os
import re
import stat
import sys
import threading
from time import sleep

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.event import add_event, WALAEventOperation
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
from azurelinuxagent.common.exception import ResourceDiskError
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.version import AGENT_NAME

DATALOSS_WARNING_FILE_NAME = "DATALOSS_WARNING_README.txt"
DATA_LOSS_WARNING = """\
WARNING: THIS IS A TEMPORARY DISK.

Any data stored on this drive is SUBJECT TO LOSS and THERE IS NO WAY TO RECOVER IT.

Please do not use this disk for storing any personal or application data.

For additional details to please refer to the MSDN documentation at :
http://msdn.microsoft.com/en-us/library/windowsazure/jj672979.aspx
"""


class ResourceDiskHandler(object):
    def __init__(self):
        self.osutil = get_osutil()
        self.fs = conf.get_resourcedisk_filesystem()

    def start_activate_resource_disk(self):
        disk_thread = threading.Thread(target=self.run)
        disk_thread.start()

    def run(self):
        mount_point = None
        if conf.get_resourcedisk_format():
            mount_point = self.activate_resource_disk()
        if mount_point is not None and \
                conf.get_resourcedisk_enable_swap():
            self.enable_swap(mount_point)

    def a
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/exception.py.AgentUpgradeExitException`
- `%REPO%/azurelinuxagent/common/exception.py.AgentUpdateError`
- `%REPO%/azurelinuxagent/common/exception.py.AgentFamilyMissingError`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMAgentUpdateStatuses`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VMAgentUpdateStatus`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.VERSION_0`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/version.py.get_daemon_version`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_VERSION`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgentUpdateUtil`
- `%REPO%/azurelinuxagent/ga/rsm_version_updater.py.RSMVersionUpdater`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.SelfUpdateVersionUpdater`
- `%REPO%/azurelinuxagent/ga/agent_update_handler.py.UpdateMode`
- `%REPO%/azurelinuxagent/ga/agent_update_handler.py.UpdateMode.RSM`
- `%REPO%/azurelinuxagent/ga/agent_update_handler.py.UpdateMode.SelfUpdate`
- `%REPO%/azurelinuxagent/ga/agent_update_handler.py.get_agent_update_handler`
- `%REPO%/azurelinuxagent/ga/agent_update_handler.py.get_agent_update_handler.protocol`
- `%REPO%/azurelinuxagent/ga/agent_update_handler.py.AgentUpdateHandler`
- `%REPO%/azurelinuxagent/ga/agent_update_handler.py.AgentUpdateHandler.__init__`
- `%REPO

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

import json

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, AgentUpdateError, AgentFamilyMissingError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import VMAgentUpdateStatuses, VMAgentUpdateStatus, VERSION_0
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import get_daemon_version, CURRENT_VERSION
from azurelinuxagent.ga.guestagent import GuestAgentUpdateUtil
from azurelinuxagent.ga.rsm_version_updater import RSMVersionUpdater
from azurelinuxagent.ga.self_update_version_updater import SelfUpdateVersionUpdater
from azurelinuxagent.ga.signature_validation_util import agent_signature_goal_state_telemetry_enabled


class UpdateMode(object):
    """
    Enum for Update modes
    """
    RSM = "RSM"
    SelfUpdate = "SelfUpdate"


def get_agent_update_handler(protocol):
    return AgentUpdateHandler(protocol)


class AgentUpdateHandler(object):
    """
    This class handles two type of agent updates. Handler initializes the updater to SelfUpdateVersionUpdater and switch to appropriate updater based on below conditions:
        RSM update: This update requested by RSM and contract between CRP and agent is we get following properties in the goal state:
                    version: it will have what version to update

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/ga/cgroupstelemetry.py.CGroupsTelemetry`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py._CpuController`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py.CpuControllerV1`
- `%REPO%/azurelinuxagent/ga/cpucontroller.py.CpuControllerV2`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py.MemoryControllerV1`
- `%REPO%/azurelinuxagent/ga/memorycontroller.py.MemoryControllerV2`
- `%REPO%/azurelinuxagent/common/conf.py.get_agent_pid_file_path`
- `%REPO%/azurelinuxagent/common/exception.py.CGroupsException`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionErrorCodes`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionError`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionOperationError`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.handle_process_completion`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.read_output`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.TELEMETRY_MESSAGE_MAX_LEN`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/version.py.get_distro`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.CGROUP_FILE_SYSTEM_ROOT`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.EXTENSION_SLICE_PREFIX`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.log_cgroup_info`
- `%REPO%/azurelinuxagent/ga/cgroupapi.py.log_cgroup_info.formatted_string`
- `%REPO%/azurelinuxagent/ga/cgroupa

### Source excerpt

````
# -*- coding: utf-8 -*-
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
import json
import os
import re
import shutil
import subprocess
import threading
import uuid

from azurelinuxagent.common import logger
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.ga.cpucontroller import _CpuController, CpuControllerV1, CpuControllerV2
from azurelinuxagent.ga.memorycontroller import MemoryControllerV1, MemoryControllerV2
from azurelinuxagent.common.conf import get_agent_pid_file_path
from azurelinuxagent.common.exception import CGroupsException, ExtensionErrorCodes, ExtensionError, \
    ExtensionOperationError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.osutil.systemd import is_systemd_run_failure
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.ga.extensionprocessutil import handle_process_completion, read_output
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import get_distro

CGROUP_FILE_SYSTEM_ROOT = '/sys/fs/cgroup'
EXTENSION_SLICE_PREFIX = "azure-vmextensions"


def log_cgroup_info(formatted_string, op=WALAEventOperation.CGroupsInfo, send_event=True):
    logger.info("[CGI] " + formatted_string)
    if send_event:
        add_event(op=op, message=formatted_string)


def log_cgroup_warning(formatted_string, op=WALAEventOperation.CGroupsInfo, send_event=True):
    logger.info("[CGW] " + formatted_string)  # log as INF
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/dhcp.py.get_dhcp_handler`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallStateError`
- `%REPO%/azurelinuxagent/ga/interfaces.py.ThreadHandlerInterface`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/protocol/util.py.get_protocol_util`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation`
- `%REPO%/azurelinuxagent/ga/env.py.CACHE_PATTERNS`
- `%REPO%/azurelinuxagent/ga/env.py.MAXIMUM_CACHED_FILES`
- `%REPO%/azurelinuxagent/ga/env.py.get_env_handler`
- `%REPO%/azurelinuxagent/ga/env.py.EnvHandler`
- `%REPO%/azurelinuxagent/ga/env.py.RemovePersistentNetworkRules`
- `%REPO%/azurelinuxagent/ga/env.py.RemovePersistentNetworkRules.__init__`
- `%REPO%/azurelinuxagent/ga/env.py.RemovePersistentNetworkRules.__init__.self`
- `%REPO%/azurelinuxagent/ga/env.py.RemovePersistentNetworkRules.__init__.osutil`
- `%REPO%/azurelinuxagent/common/conf.py.get_remove_persistent_net_rules_period`
- `%REPO%/azurelinuxagent/ga/env.py.RemovePersistentNetworkRules._operation`
- `%REPO%/azurelinuxagent/ga/env.py.RemovePersistentNetworkRules._operation.self`
- `%REPO%/azurelinuxagent/ga/env.py.MonitorDhcpClientRestart`
- `%REPO%/azurelinuxagent/ga/env.py.MonitorDhcpCli

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
import datetime
import re
import socket
import threading

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.dhcp import get_dhcp_handler
from azurelinuxagent.common import event
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common.future import UTC
from azurelinuxagent.ga.firewall_manager import FirewallManager, FirewallStateError, IptablesInconsistencyError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.ga.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.version import AGENT_NAME
from azurelinuxagent.ga.periodic_operation import PeriodicOperation

CACHE_PATTERNS = [
    re.compile(r"^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(xml)$", re.IGNORECASE)
]

MAXIMUM_CACHED_FILES = 50


def get_env_handler():
    return EnvHandler()


class RemovePersistentNetworkRules(PeriodicOperation):
    def __init__(self, osutil):
        super(RemovePersistentNetworkRules, self).__init__(conf.get_remove_persistent_net_rules_period())
        self.osutil = osutil

    def _operation(self):
        self.osutil.remove_rules_files()


class MonitorDhcpClientRestart(PeriodicOperation):
    def __init__(self, osuti
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionErrorCodes`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionOperationError`
- `%REPO%/azurelinuxagent/common/exception.py.ExtensionError`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.TELEMETRY_MESSAGE_MAX_LEN`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.wait_for_process_completion_or_timeout`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.wait_for_process_completion_or_timeout.process`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.wait_for_process_completion_or_timeout.timeout`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.wait_for_process_completion_or_timeout.cpu_controller`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.get_cpu_throttled_time`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.handle_process_completion`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.handle_process_completion.process`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.handle_process_completion.command`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.handle_process_completion.timeout`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.handle_process_completion.stdout`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.handle_process_completion.stderr`
- `%REPO%/azurelinuxagent/ga/extensionprocessutil.py.handle_process_completion.error_code`
- `%REPO%/azurel

### Source excerpt

````
# Microsoft Azure Linux Agent
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#
# You may not use this file except in compliance with the License.
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
import signal
import time

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common.exception import ExtensionErrorCodes, ExtensionOperationError, ExtensionError
from azurelinuxagent.common.future import ustr

TELEMETRY_MESSAGE_MAX_LEN = 3200


def wait_for_process_completion_or_timeout(process, timeout, cpu_controller):
    """
    Utility function that waits for the process to complete within the given time frame. This function will terminate
    the process if when the given time frame elapses.
    :param process: Reference to a running process
    :param timeout: Number of seconds to wait for the process to complete before killing it
    :return: Two parameters: boolean for if the process timed out and the return code of the process (None if timed out)
    """
    while timeout > 0 and process.poll() is None:
        time.sleep(1)
        timeout -= 1

    return_code = None
    throttled_time = 0

    if timeout == 0:
        throttled_time = get_cpu_throttled_time(cpu_controller)
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    else:
        # process completed or forked; sleep 1 sec to give the child process (if any) a chance to start
        time.sleep(1)
        return_code = process.wait()

    return timeout == 0, return_code, throttled_time


def handle_process_completion(process, command, timeout, stdout, stderr, error_code, cpu_contr
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.CommandError`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManagerNotAvailableError`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallStateError`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.__init__`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.__init__.self`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.__init__.wire_server_address`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.ACCEPT_DNS`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.ACCEPT`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.DROP`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.create`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.create.wire_server_address`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.IpTables`
- `%REPO%/azurelinuxagent/common/event.py.info`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.NfTables`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.version`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.version.self`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallManager.setup`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.F

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
import errno
import json
import os
import re

from azurelinuxagent.common import logger
from azurelinuxagent.common import event
from azurelinuxagent.common.event import WALAEventOperation
from azurelinuxagent.common.utils import shellutil

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.shellutil import CommandError


class FirewallManagerNotAvailableError(Exception):
    """
    Exception raised the command-line tool needed to manage the firewall (e.g. iptables, firewalld, nft) is not available
    """


class FirewallStateError(Exception):
    """
    Exception raised when the firewall rules are not set up correctly.
    """


class FirewallRulesMissingError(FirewallStateError):
    """
    Exception raised when some firewall rules are missing.
    """
    def __init__(self, missing_rules):
        super(FirewallRulesMissingError, self).__init__("The following rules are missing: {0}".format(missing_rules))
        self.missing_rules = missing_rules


class IptablesInconsistencyError(FirewallStateError):
    """
    Exception raised when "iptables -C OUTPUT" does not detect a rule, but "iptables -L OUTPUT" reports that it does exist.
    """
    def __init__(self, missing_rules, output_chain):
        super(IptablesInconsistencyError, self).__init__("Inconsistent results from iptables: -C reports that some rules are missing ({0}), but -L shows some of them exist:\n{1}".format(missing_rules, output_chain))
        self.missing_rules = mi
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/exception.py.UpdateError`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_DIR_PATTERN`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/ga/exthandlers.py.HandlerManifest`
- `%REPO%/azurelinuxagent/ga/guestagent.py.AGENT_ERROR_FILE`
- `%REPO%/azurelinuxagent/ga/guestagent.py.AGENT_MANIFEST_FILE`
- `%REPO%/azurelinuxagent/ga/guestagent.py.MAX_FAILURE`
- `%REPO%/azurelinuxagent/ga/guestagent.py.AGENT_UPDATE_COUNT_FILE`
- `%REPO%/azurelinuxagent/ga/guestagent.py.RSM_UPDATE_STATE_FILE`
- `%REPO%/azurelinuxagent/ga/guestagent.py.INITIAL_UPDATE_STATE_FILE`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgent`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgent.__init__`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgent.__init__.self`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgent.__init__.path`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgent.__init__.pkg`
- `%REPO%/azurelinuxagent/common/logger.py.verbose`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgentError`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgent.get_agent_error_file`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgentError.load`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgentUpdateAttempt`
- `%REPO%/azurelinuxagent/ga/guestagent

### Source excerpt

````
import json
import os
import shutil
import time

from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import textutil

from azurelinuxagent.common import logger, conf, event
from azurelinuxagent.common.exception import UpdateError
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_DIR_PATTERN, AGENT_NAME
from azurelinuxagent.ga.exthandlers import HandlerManifest

AGENT_ERROR_FILE = "error.json"  # File name for agent error record
AGENT_MANIFEST_FILE = "HandlerManifest.json"
MAX_FAILURE = 3  # Max failure allowed for agent before declare bad agent
AGENT_UPDATE_COUNT_FILE = "update_attempt.json"  # File for tracking agent update attempt count

RSM_UPDATE_STATE_FILE = "waagent_rsm_update"
INITIAL_UPDATE_STATE_FILE = "waagent_initial_update"


class GuestAgent(object):
    def __init__(self, path, pkg):
        """
        If 'path' is given, the object is initialized to the version installed under that path.

        If 'pkg' is given, the version specified in the package information is downloaded and the object is
        initialized to that version.

        NOTE: Prefer using the from_installed_agent and from_agent_package methods instead of calling __init__ directly
        """
        self.pkg = pkg
        version = None
        if path is not None:
            m = AGENT_DIR_PATTERN.match(path)
            if m is None:
                raise UpdateError(u"Illegal agent directory: {0}".format(path))
            version = m.group(1)
        elif self.pkg is not None:
            version = pkg.version

        if version is None:
            raise UpdateError(u"Illegal agent version: {0}".format(version))
        self.version = FlexibleVersion(version)

        location = u"disk" if path is not None else u"package"
        logger.verbose(u"Loading Agent {0} from {1}", self.name, location)

        self.error = GuestAgentError(self.get_agent_error_file())
        self.error.load()

        self.update_attempt_data = GuestAgentUpdateAttempt(self.get_agent_update_count_file())
        self.update_
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/conf.py.get_lib_dir`
- `%REPO%/azurelinuxagent/common/conf.py.get_ext_log_dir`
- `%REPO%/azurelinuxagent/common/conf.py.get_agent_log_file`
- `%REPO%/azurelinuxagent/common/event.py.initialize_event_logger_vminfo_common_parameters_and_protocol`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/ga/logcollector_manifests.py.MANIFEST_NORMAL`
- `%REPO%/azurelinuxagent/ga/logcollector_manifests.py.MANIFEST_FULL`
- `%REPO%/azurelinuxagent/common/protocol/goal_state.py.GoalStateProperties`
- `%REPO%/azurelinuxagent/common/protocol/util.py.get_protocol_util`
- `%REPO%/azurelinuxagent/ga/logcollector.py._EXTENSION_LOG_DIR`
- `%REPO%/azurelinuxagent/ga/logcollector.py._AGENT_LIB_DIR`
- `%REPO%/azurelinuxagent/ga/logcollector.py._AGENT_LOG`
- `%REPO%/azurelinuxagent/ga/logcollector.py._LOG_COLLECTOR_DIR`
- `%REPO%/azurelinuxagent/ga/logcollector.py._TRUNCATED_FILES_DIR`
- `%REPO%/azurelinuxagent/ga/logcollector.py.OUTPUT_RESULTS_FILE_PATH`
- `%REPO%/azurelinuxagent/ga/logcollector.py.COMPRESSED_ARCHIVE_PATH`
- `%REPO%/azurelinuxagent/ga/logcollector.py.CGROUPS_UNIT`
- `%REPO%/azurelinuxagent/ga/logcollector.py.GRACEFUL_KILL_ERRCODE`
- `%REPO%/azurelinuxagent/ga/logcollector.py.INVALID_CGROUPS_ERRCODE`
- `%REPO%/azurelinuxagent/ga/logcollector.py.UNEXPECTED_CGROUP_PATH_ERRCODE`
- `%REPO%/azurelinuxagent/ga/logcollector.py.LOG_COLLECTOR_CGROUP_PATH_VALIDATION_MAX_RET

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

import glob
import logging
import os
import subprocess
import time
import zipfile
from datetime import datetime
from heapq import heappush, heappop

from azurelinuxagent.common.conf import get_lib_dir, get_ext_log_dir, get_agent_log_file
from azurelinuxagent.common.event import initialize_event_logger_vminfo_common_parameters_and_protocol, add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr, UTC, BACKSLASH_REPLACE
from azurelinuxagent.ga.logcollector_manifests import MANIFEST_NORMAL, MANIFEST_FULL

# Please note: be careful when adding agent dependencies in this module.
# This module uses its own logger and logs to its own file, not to the agent log.
from azurelinuxagent.common.protocol.goal_state import GoalStateProperties
from azurelinuxagent.common.protocol.util import get_protocol_util

_EXTENSION_LOG_DIR = get_ext_log_dir()
_AGENT_LIB_DIR = get_lib_dir()
_AGENT_LOG = get_agent_log_file()

_LOG_COLLECTOR_DIR = os.path.join(_AGENT_LIB_DIR, "logcollector")
_TRUNCATED_FILES_DIR = os.path.join(_LOG_COLLECTOR_DIR, "truncated")

OUTPUT_RESULTS_FILE_PATH = os.path.join(_LOG_COLLECTOR_DIR, "results.txt")
COMPRESSED_ARCHIVE_PATH = os.path.join(_LOG_COLLECTOR_DIR, "logs.zip")

CGROUPS_UNIT = "collect-logs.scope"

GRACEFUL_KILL_ERRCODE = 3
INVALID_CGROUPS_ERRCODE = 2
UNEXPECTED_CGROUP_PATH_ERRCODE = 4

LOG_COLLECTOR_CGROUP_PATH_VALIDATION_MAX_RETRIES = 3
LOG_COLLECTOR_CGROUP_PATH_VALIDATION_RETRY_DELAY = 5
LOG_COLLECTOR_CGROUP_PATH_VALIDATION_MAX_FAILURES = 3


_MUST_COLLECT_FILES = [
    _AGENT
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallCmd`
- `%REPO%/azurelinuxagent/ga/firewall_manager.py.FirewallStateError`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.CommandError`
- `%REPO%/azurelinuxagent/common/version.py.get_distro`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler.__SERVICE_FILE_CONTENT`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler.__BINARY_CONTENTS`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler._AGENT_NETWORK_SETUP_NAME_FORMAT`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler.BINARY_FILE_NAME`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler._UNIT_VERSION`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler._DISTRO`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler.get_service_file_path`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler.__init__`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallRulesHandler.__init__.self`
- `%REPO%/azurelinuxagent/ga/persist_firewall_rules.py.PersistFirewallR

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
import sys

import azurelinuxagent.common.conf as conf
from azurelinuxagent.common import logger
from azurelinuxagent.common import event
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.ga.firewall_manager import FirewallCmd, FirewallStateError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil, systemd
from azurelinuxagent.common.utils import shellutil, fileutil, textutil
from azurelinuxagent.common.utils.shellutil import CommandError
from azurelinuxagent.common.version import get_distro


class PersistFirewallRulesHandler(object):

    __SERVICE_FILE_CONTENT = """
# This unit file (Version={version}) was created by the Azure VM Agent.
# Do not edit.
[Unit]
Description=Setup network rules for WALinuxAgent
After={after_dependencies}
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no
ConditionPathExists={binary_path}

[Service]
Type=oneshot
ExecStart={py_path} {binary_path}
RemainAfterExit=yes

[Install]
WantedBy=network.target
"""

    __BINARY_CONTENTS = """
# This python file was created by the Azure VM Agent. Please do not edit.

import os


if __name__ == '__main__':
    if os.path.exists("{egg_path}"):
        os.system("{py_path} {egg_path} --setup-firewall={wire_ip}")
    else:
        print("{egg_path} file not found, skipping execution of firewall execution setup for this boot")
"""

    _AGENT_NETWORK_SETUP_NAME_FORMAT = "{0}-network-setup.service"
    BINARY_FILE_NAME = "waagent-network-setup.py"

    # The
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
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/exception.py.AgentError`
- `%REPO%/azurelinuxagent/common/protocol/extensions_goal_state_from_vm_settings.py._CaseFoldedDict`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py._DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py._DEFAULT_SIGNATURE_REQUIRED`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py._DEFAULT_EXTENSIONS`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py._MAX_SUPPORTED_POLICY_VERSION`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py.InvalidPolicyError`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py.InvalidPolicyError.__init__`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py.InvalidPolicyError.__init__.self`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py.InvalidPolicyError.__init__.msg`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py.InvalidPolicyError.__init__.inner`
- `%REPO%/azurelinuxagent/common/conf.py.get_policy_file_path`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py._PolicyEngine`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py._PolicyEngine.__init__`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py._PolicyEngine.__init__.self`
- `%REPO%/azurelinuxagent/ga/policy/policy_engine.py._PolicyEngine.__get_policy_enforcement_enabled`
- `%REPO%/a

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
# Requires Python 2.4+ and Openssl 1.0+
#

import json
import re
import os
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common import logger
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import _CaseFoldedDict
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.ga.confidential_vm_info import ConfidentialVMInfo
from azurelinuxagent.ga.signature_validation_util import openssl_version_supported_for_signature_validation


# Default policy values to be used when customer does not specify these attributes in the policy file.
_DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY = False
_DEFAULT_SIGNATURE_REQUIRED = False
_DEFAULT_EXTENSIONS = {}

# Agent supports up to this version of the policy file ("policyVersion" in schema).
# Increment this number when any new attributes are added to the policy schema.
_MAX_SUPPORTED_POLICY_VERSION = "0.1.0"

# Extension signature validation is currently only supported on CVMs. If a non-CVM user creates a policy with signature
# required, we should raise an error indicating that the policy is invalid.
# TODO: Remove once signature validation is supported on all VMs


class PolicyError(AgentError):
    """
    Base class for policy-related errors.
    """
    def __init__(self, msg=None, inner=None):
        super(PolicyError, self).__init__(msg, inner)


class InvalidPolicyError(PolicyError):
    """
    Error r
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/utils/cryptutil.py.CryptUtil`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_VERSION`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.REMOTE_USR_EXPIRATION_FORMAT`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.DATE_FORMAT`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.TRANSPORT_PRIVATE_CERT`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.REMOTE_ACCESS_ACCOUNT_COMMENT`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.MAX_TRY_ATTEMPT`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.FAILED_ATTEMPT_THROTTLE`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.get_remote_access_handler`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.get_remote_access_handler.protocol`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.RemoteAccessHandler`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.RemoteAccessHandler.__init__`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.RemoteAccessHandler.__init__.self`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.RemoteAccessHandler.__init__.protocol`
- `%REPO%/azurelinuxagent/common/conf.py.get_openssl_cmd`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.RemoteAccessHandler.run`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.RemoteAccessHandler.run.self`
- `%REPO%/azurelinuxagent/ga/remoteaccess.py.RemoteAccessHandler._handl

### Source excerpt

````
# Microsoft Azure Linux Agent
#
# Copyright Microsoft Corporation
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
from datetime import datetime, timedelta

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr, UTC
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION

REMOTE_USR_EXPIRATION_FORMAT = "%a, %d %b %Y %H:%M:%S %Z"
DATE_FORMAT = "%Y-%m-%d"
TRANSPORT_PRIVATE_CERT = "TransportPrivate.pem"
REMOTE_ACCESS_ACCOUNT_COMMENT = "JIT_Account"
MAX_TRY_ATTEMPT = 5
FAILED_ATTEMPT_THROTTLE = 1


def get_remote_access_handler(protocol):
    return RemoteAccessHandler(protocol)


class RemoteAccessHandler(object):
    def __init__(self, protocol):
        self._os_util = get_osutil()
        self._protocol = protocol
        self._cryptUtil = CryptUtil(conf.get_openssl_cmd())
        self._remote_access = None
        self._check_existing_jit_users = True

    def run(self, remote_access):
        try:
            if self._os_util.jit_enabled:
                # Handle remote access if any.
                self._remote_access = remote_access
                self._handle_remote_access()
        except Exception as e:
            msg = u"Exception processing goal state for remote access users: {0}".format(textutil.format_exception(e))
            add_event(AGENT_NAME,

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/exception.py.AgentUpgradeExitException`
- `%REPO%/azurelinuxagent/common/exception.py.AgentUpdateError`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgent`
- `%REPO%/azurelinuxagent/ga/rsm_version_updater.py.RSMVersionUpdater`
- `%REPO%/azurelinuxagent/ga/rsm_version_updater.py.RSMVersionUpdater.__init__`
- `%REPO%/azurelinuxagent/ga/rsm_version_updater.py.RSMVersionUpdater.__init__.self`
- `%REPO%/azurelinuxagent/ga/rsm_version_updater.py.RSMVersionUpdater.__init__.gs_id`
- `%REPO%/azurelinuxagent/ga/rsm_version_updater.py.RSMVersionUpdater.__init__.daemon_version`
- `%REPO%/azurelinuxagent/ga/rsm_version_updater.py.RSMVersionUpdater._get_all_agents_on_disk`
- `%REPO%/azurelinuxagent/common/conf.py.get_lib_dir`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgent.from_installed_agent`
- `%REPO%/azurelinuxagent/ga/rsm_version_updater.py.RSMVersionUpdater._get_available_agents_on_disk`
- `%REPO%/azurelinuxagent/ga/rsm_version_updater.py.RSMVersionUpdater._get_available_agents_on_disk.self`
- `%REPO%/azurelinuxagent/ga/rsm_version_updater.py.RSMVersionUpdater.is_update_al

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
import os

from azurelinuxagent.common import conf, logger, event
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, AgentUpdateError
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import CURRENT_VERSION, AGENT_NAME
from azurelinuxagent.ga.ga_version_updater import GAVersionUpdater
from azurelinuxagent.ga.guestagent import GuestAgent


class RSMVersionUpdater(GAVersionUpdater):
    def __init__(self, gs_id, daemon_version):
        super(RSMVersionUpdater, self).__init__(gs_id)
        self._daemon_version = daemon_version

    @staticmethod
    def _get_all_agents_on_disk():
        path = os.path.join(conf.get_lib_dir(), "{0}-*".format(AGENT_NAME))
        return [GuestAgent.from_installed_agent(path=agent_dir) for agent_dir in glob.iglob(path) if
                os.path.isdir(agent_dir)]

    def _get_available_agents_on_disk(self):
        available_agents = [agent for agent in self._get_all_agents_on_disk() if agent.is_available]
        return sorted(available_agents, key=lambda agent: agent.version, reverse=True)

    def is_update_allowed_this_time(self, ext_gs_updated):
        """
        RSM update allowed if we have a new goal state
        """
        return ext_gs_updated

    def is_rsm_update_enabled(self, agent_family, ext_gs_updated):
        """
        Checks if there is a new goal state and decide if we need to continue with rsm u
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/exception.py.AgentUpgradeExitException`
- `%REPO%/azurelinuxagent/common/exception.py.AgentUpdateError`
- `%REPO%/azurelinuxagent/common/future.py.datetime_min_utc`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/version.py.CURRENT_VERSION`
- `%REPO%/azurelinuxagent/ga/ga_version_updater.py.GAVersionUpdater`
- `%REPO%/azurelinuxagent/ga/guestagent.py.GuestAgentUpdateUtil`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.SelfUpdateType`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.SelfUpdateType.Hotfix`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.SelfUpdateType.Regular`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.SelfUpdateVersionUpdater`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.SelfUpdateVersionUpdater.__init__`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.SelfUpdateVersionUpdater.__init__.self`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.SelfUpdateVersionUpdater.__init__.gs_id`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.SelfUpdateVersionUpdater._get_largest_version`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.SelfUpdateVersionUpdater._get_largest_version.agent_manifest`
- `%REPO%/azurelinuxagent/ga/self_update_version_updater.py.Se

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

import datetime
import random

from azurelinuxagent.common import conf, logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import AgentUpgradeExitException, AgentUpdateError
from azurelinuxagent.common.future import UTC, datetime_min_utc, ustr
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils import timeutil
from azurelinuxagent.common.version import CURRENT_VERSION
from azurelinuxagent.ga.ga_version_updater import GAVersionUpdater
from azurelinuxagent.ga.guestagent import GuestAgentUpdateUtil


class SelfUpdateType(object):
    """
    Enum for different modes of Self updates
    """
    Hotfix = "Hotfix"
    Regular = "Regular"


class SelfUpdateVersionUpdater(GAVersionUpdater):
    def __init__(self, gs_id):
        super(SelfUpdateVersionUpdater, self).__init__(gs_id)
        self._last_attempted_manifest_download_time = datetime_min_utc
        self._next_update_time = datetime_min_utc

    @staticmethod
    def _get_agent_upgrade_type(version):
        # We follow semantic versioning for the agent, if <Major>.<Minor>.<Patch> is same, then <Build> has changed.
        # In this case, we consider it as a Hotfix upgrade. Else we consider it a Regular upgrade.
        if version.major == CURRENT_VERSION.major and version.minor == CURRENT_VERSION.minor and version.patch == CURRENT_VERSION.patch:
            return SelfUpdateType.Hotfix
        return SelfUpdateType.Regular

    @staticmethod

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/exception.py.ServiceStoppedError`
- `%REPO%/azurelinuxagent/ga/interfaces.py.ThreadHandlerInterface`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.get_send_telemetry_events_handler`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.get_send_telemetry_events_handler.protocol_util`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler._THREAD_NAME`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler._MAX_TIMEOUT`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler._MIN_EVENTS_TO_BATCH`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler._MIN_BATCH_WAIT_TIME`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler.__init__`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler.__init__.self`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler.__init__.protocol_util`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler.get_thread_name`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler.run`
- `%REPO%/azurelinuxagent/ga/send_telemetry_events.py.SendTelemetryEventsHandler.run.self`
- `%REPO%/azur

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
import threading
import time

from azurelinuxagent.common import logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ServiceStoppedError
from azurelinuxagent.common.future import ustr, UTC, Queue, Empty
from azurelinuxagent.ga.interfaces import ThreadHandlerInterface
from azurelinuxagent.common.utils import textutil


def get_send_telemetry_events_handler(protocol_util):
    return SendTelemetryEventsHandler(protocol_util)


class SendTelemetryEventsHandler(ThreadHandlerInterface):
    """
    This Handler takes care of sending all telemetry out of the agent to Wireserver. It sends out data as soon as
    there's any data available in the queue to send.
    """

    _THREAD_NAME = "SendTelemetryHandler"
    _MAX_TIMEOUT = datetime.timedelta(seconds=5).seconds
    _MIN_EVENTS_TO_BATCH = 30
    _MIN_BATCH_WAIT_TIME = datetime.timedelta(seconds=5)

    def __init__(self, protocol_util):
        self._protocol = protocol_util.get_protocol()
        self.should_run = True
        self._thread = None

        # We're using a Queue for handling the communication between threads. We plan to remove any dependency on the
        # filesystem in the future and use add_event to directly queue events into the queue rather than writing to
        # a file and then parsing it later.

        # Once we move add_event to directly queue events, we need to add a maxsize here to ensure some limitations are
        # being set (currently our limits
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/ga/signing_certificate_util.py._MICROSOFT_ROOT_CERT_2011_03_22`
- `%REPO%/azurelinuxagent/ga/signing_certificate_util.py.get_microsoft_signing_certificate_path`
- `%REPO%/azurelinuxagent/common/conf.py.get_lib_dir`
- `%REPO%/azurelinuxagent/ga/signing_certificate_util.py._write_certificate`
- `%REPO%/azurelinuxagent/ga/signing_certificate_util.py._write_certificate.cert_string`
- `%REPO%/azurelinuxagent/ga/signing_certificate_util.py._write_certificate.output_path`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/event.py.error`
- `%REPO%/azurelinuxagent/ga/signing_certificate_util.py.write_signing_certificates`

### Source excerpt

````
# Windows Azure Linux Agent
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
from azurelinuxagent.common import logger
from azurelinuxagent.common import conf
from azurelinuxagent.common import event
from azurelinuxagent.common.event import WALAEventOperation


_MICROSOFT_ROOT_CERT_2011_03_22 = """-----BEGIN CERTIFICATE-----
MIIF7TCCA9WgAwIBAgIQP4vItfyfspZDtWnWbELhRDANBgkqhkiG9w0BAQsFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEw
MzIyMjIwNTI4WhcNMzYwMzIyMjIxMzA0WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
aWNhdGUgQXV0aG9yaXR5IDIwMTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCygEGqNThNE3IyaCJNuLLx/9VSvGzH9dJKjDbu0cJcfoyKrq8TKG/Ac+M6
ztAlqFo6be+ouFmrEyNozQwph9FvgFyPRH9dkAFSWKxRxV8qh9zc2AodwQO5e7BW
6KPeZGHCnvjzfLnsDbVU/ky2ZU+I8JxImQxCCwl8MVkXeQZ4KI2JOkwDJb5xalwL
54RgpJki49KvhKSn+9GY7Qyp3pSJ4Q6g3MDOmT3qCFK7VnnkH4S6Hri0xElcTzFL
h93dBWcmmYDgcRGjuKVB4qRTufcyKYMME782XgSzS0NHL2vikR7TmE/dQgfI6B0S
/Jmpaz6SfsjWaTr8ZL22CZ3K/QwLopt3YEsDlKQwaRLWQi3BQUzK3Kr9j1uDRprZ
/LHR47PJf0h6zSTwQY9cdNCssBAgBkm3xy0hyFfj0IbzA2j70M5xwYmZSmQBbP3s
MJHPQTySx+W6hh1hhMdfgzlirrSSL0fzC/hV66AfWdC7dJse0Hbm8ukG1xDo+mTe
acY1logC8Ea4PyeZb8txiSk190gWAjWP1Xl8TQLPX+uKg09FcYj5qQ1OcunCnAfP
SRtOBA5jUYxe2ADBVSy2xuDCZU7JNDn1nLPEfuhhbhNfFcRf2X7tHc7uROzLLoax
7Dj2cO2rXBPB2Q8Nx4CyVe0096yb5MPa50c8prWPMd/FS6/r8QIDAQABo1EwTzAL
BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.elapsed_milliseconds`
- `%REPO%/azurelinuxagent/common/exception.py.ProvisionError`
- `%REPO%/azurelinuxagent/common/exception.py.ProtocolError`
- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/protocol/restapi.py.ProvisionStatus`
- `%REPO%/azurelinuxagent/common/protocol/util.py.get_protocol_util`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/pa/provision/cloudinitdetect.py.cloud_init_is_enabled`
- `%REPO%/azurelinuxagent/pa/provision/default.py.CUSTOM_DATA_FILE`
- `%REPO%/azurelinuxagent/pa/provision/default.py.CLOUD_INIT_PATTERN`
- `%REPO%/azurelinuxagent/pa/provision/default.py.CLOUD_INIT_REGEX`
- `%REPO%/azurelinuxagent/pa/provision/default.py.PROVISIONED_FILE`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler.__init__`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler.__init__.self`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler.run`
- `%REPO%/azurelinuxagent/pa/provision/default.py.ProvisionHandler.run.self`
- `%REPO%/azurelinuxagent/common/conf.py.get_provision_enabled`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/pa/provisio

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

"""
Provision handler
"""

import os
import os.path
import re
import time

from datetime import datetime

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.future import ustr, UTC
from azurelinuxagent.common.event import add_event, WALAEventOperation, \
    elapsed_milliseconds
from azurelinuxagent.common.exception import ProvisionError, ProtocolError, \
    OSUtilError
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.goal_state import GoalState, GoalStateProperties
from azurelinuxagent.common.protocol.restapi import ProvisionStatus
from azurelinuxagent.common.protocol.util import get_protocol_util, MAX_RETRY, PROBE_INTERVAL
from azurelinuxagent.common.version import AGENT_NAME
from azurelinuxagent.pa.provision.cloudinitdetect import cloud_init_is_enabled

CUSTOM_DATA_FILE = "CustomData"
CLOUD_INIT_PATTERN = b".*/bin/cloud-init.*"
CLOUD_INIT_REGEX = re.compile(CLOUD_INIT_PATTERN)

PROVISIONED_FILE = 'provisioned'


class ProvisionHandler(object):
    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()

    def run(self):
        if not conf.get_provision_enabled():
            logger.info("Provisioning is disabled, skipping.")
            self.write_provisioned()
            self.report_ready()
            return

        try:
            utc_start = datetime.now(UTC)


````

---
