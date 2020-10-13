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

import os

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION

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

def cleanup_metadata_server_artifacts(osutil):
    logger.info("Clean up for MetadataServer to WireServer protocol migration: removing MetadataServer certificates and resetting firewall rules.")
    _cleanup_metadata_protocol_certificates()
    _reset_firewall_rules(osutil)

def _cleanup_metadata_protocol_certificates():
    """
    Removes MetadataServer Certificates.
    """
    lib_directory = conf.get_lib_dir()
    _ensure_file_removed(lib_directory, _LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME)
    _ensure_file_removed(lib_directory, _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME)
    _ensure_file_removed(lib_directory, _LEGACY_METADATA_SERVER_P7B_FILE_NAME)

def _reset_firewall_rules(osutil):
    """
    Removes MetadataServer firewall rule so IMDS can be used. Enables
    WireServer firewall rule based on if firewall is configured to be on.
    """
    osutil.remove_firewall(dst_ip=_KNOWN_METADATASERVER_IP, uid=os.getuid())
    if conf.enable_firewall():
        success = osutil.enable_firewall(dst_ip=KNOWN_WIRESERVER_IP, uid=os.getuid())
        add_event(
            AGENT_NAME,
            version=CURRENT_VERSION,
            op=WALAEventOperation.Firewall,
            is_success=success,
            log_event=False)

def _ensure_file_removed(directory, file_name):
    """
    Removes files if they are present.
    """
    path = os.path.join(directory, file_name)
    if os.path.isfile(path):
        os.remove(path)
