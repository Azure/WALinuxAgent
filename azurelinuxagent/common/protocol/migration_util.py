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

from azurelinuxagent.common.protocol.goal_state import TRANSPORT_CERT_FILE_NAME
from azurelinuxagent.common.protocol.util import WIRE_PROTOCOL_NAME
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP

# MetadataServer Legacy Certificates for Cleanup
LEGACY_TRANSPORT_PRV_FILE_NAME = "V2TransportPrivate.pem"
LEGACY_TRANSPORT_CERT_FILE_NAME = "V2TransportCert.pem"
LEGACY_P7B_FILE_NAME = "Certificates.p7b"

# MetadataServer Endpoint
METADATA_SERVER_ENDPOINT = "169.254.169.254"

def is_migrating_protocol():
    """
    Migrating away from Metadata Server protocol if Metadata Server transport
    certificate is present or Wire Server transport certificate is missing.
    """
    transport_cert_file = os.path.join(conf.get_lib_dir(), TRANSPORT_CERT_FILE_NAME)
    legacy_transport_cert_file = os.path.join(conf.get_lib_dir(), LEGACY_TRANSPORT_CERT_FILE_NAME)
    return os.path.isfile(legacy_transport_cert_file) or not os.path.isfile(transport_cert_file)

def update_goal_state_protocol_migration_safe(protocol, protocol_util):
    """
    Wrapper around update_goal_state that ensures WireServer certificates
    are generated before querying goal state. These certificates are missing
    in the case of agents transitioning from MetadataServer protocol.
    """
    def ensure_file_removed(directory, file_name):
        path = os.path.join(directory, file_name)
        if os.path.isfile(path):
            os.remove(path)
    if is_migrating_protocol():
        #
        # Generate transport certificates if it is missing. This handles the case
        # where MetadataServer VM's migrate over to WireServer.
        # Also cleanup old MetadataServer certificates and update protocol file.
        # Create WireServerEndpoint file.
        #
        protocol.detect()
        lib_directory = conf.get_lib_dir()
        ensure_file_removed(lib_directory, LEGACY_TRANSPORT_PRV_FILE_NAME)
        ensure_file_removed(lib_directory, LEGACY_TRANSPORT_CERT_FILE_NAME)
        ensure_file_removed(lib_directory, LEGACY_P7B_FILE_NAME)
        protocol_util.save_protocol(WIRE_PROTOCOL_NAME)
        protocol_util.set_wireserver_endpoint(KNOWN_WIRESERVER_IP)
    else:
        protocol.update_goal_state()