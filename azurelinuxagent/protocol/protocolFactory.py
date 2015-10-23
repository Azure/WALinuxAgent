# Microsoft Azure Linux Agent
#
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
import traceback
import threading
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text
import azurelinuxagent.utils.fileutil as fileutil
from azurelinuxagent.utils.osutil import OSUTIL
from azurelinuxagent.protocol.common import *
from azurelinuxagent.protocol.v1 import WireProtocol
from azurelinuxagent.protocol.v2 import MetadataProtocol

WIRE_SERVER_ADDR_FILE_NAME = "WireServer"

def get_wire_protocol_endpoint():
    path = os.path.join(OSUTIL.get_lib_dir(), WIRE_SERVER_ADDR_FILE_NAME)
    try:
        endpoint = fileutil.read_file(path)
    except IOError as e:
        raise ProtocolNotFound("Wire server endpoint not found: {0}".format(e))

    if endpoint is None:
        raise ProtocolNotFound("Wire server endpoint is None")

    return endpoint

def detect_wire_protocol():
    endpoint = get_wire_protocol_endpoint()

    OSUTIL.gen_transport_cert()
    protocol = WireProtocol(endpoint)
    protocol.initialize()
    logger.info("Protocol V1 found.")
    return protocol

def detect_metadata_protocol():
    protocol = MetadataProtocol()
    protocol.initialize()

    logger.info("Protocol V2 found.")
    return protocol

def detect_available_protocols(prob_funcs=[detect_wire_protocol, 
                                           detect_metadata_protocol]):
    available_protocols = []
    for probe_func in prob_funcs:
        try:
            protocol = probe_func()
            available_protocols.append(protocol)
        except ProtocolNotFound as e:
            logger.info(text(e))
    return available_protocols

def detect_default_protocol():
    logger.info("Detect default protocol.")
    available_protocols = detect_available_protocols()
    return choose_default_protocol(available_protocols)

def choose_default_protocol(protocols):
    if len(protocols) > 0:
        return protocols[0]
    else:
        raise ProtocolNotFound("No available protocol detected.")

def get_wire_protocol():
    endpoint = get_wire_protocol_endpoint()
    return WireProtocol(endpoint)

def get_metadata_protocol():
    return MetadataProtocol()

def get_available_protocols(getters=[get_wire_protocol, get_metadata_protocol]):
    available_protocols = []
    for getter in getters:
        try:
            protocol = getter()
            available_protocols.append(protocol)
        except ProtocolNotFound as e:
            logger.info(text(e))
    return available_protocols

class ProtocolFactory(object):
    def __init__(self):
        self._protocol = None
        self._lock = threading.Lock()

    def get_default_protocol(self):
        if self._protocol is None:
            self._lock.acquire()
            if self._protocol is None:
                available_protocols = get_available_protocols()
                self._protocol = choose_default_protocol(available_protocols)
            self._lock.release()

        return self._protocol

FACTORY = ProtocolFactory()
