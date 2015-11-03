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
import time
import threading
import azurelinuxagent.logger as logger
from azurelinuxagent.exception import *
from azurelinuxagent.future import text
import azurelinuxagent.utils.fileutil as fileutil
from azurelinuxagent.utils.osutil import OSUTIL
from azurelinuxagent.protocol.common import *
from azurelinuxagent.protocol.v1 import WireProtocol
from azurelinuxagent.protocol.v2 import MetadataProtocol
from azurelinuxagent.protocol.ovfenv import TAG_FILE_NAME

PROTOCOL_FILE_NAME = "Protocol"
MAX_RETRY = 60


def _detect_protocol(protocols=[WireProtocol, MetadataProtocol]):
    protocol_file_path = os.path.join(OSUTIL.get_lib_dir(), PROTOCOL_FILE_NAME)
    if os.path.isfile(protocol_file_path):
        os.remove(protocol_file_path)
    for retry in range(0, MAX_RETRY):
        for protocol_cls in protocols:
            try:
                logger.info("Detecting protocol: {0}", protocol_cls.__name__)
                protocol = protocol_cls()
                protocol.initialize()
                logger.info("Found protocol: {0}", protocol_cls.__name__)
                fileutil.write_file(protocol_file_path, protocol_cls.__name__)
                return protocol
            except ProtocolError as e:
                logger.info("Protocol endpoint not found: {0}, {1}", 
                            protocol_cls.__name__, e)
        if retry < MAX_RETRY -1:
            logger.info("Retry detect protocols: retry={0}", retry)
            time.sleep(10)
    raise ProtocolNotFound("No protocol found.")

def _get_protocol():
    protocol_file_path = os.path.join(OSUTIL.get_lib_dir(), 
                                      PROTOCOL_FILE_NAME)
    if not os.path.isfile(protocol_file_path):
        raise ProtocolError("No protocl found")

    protocol_name = fileutil.read_file(protocol_file_path)
    if protocol_name == WireProtocol.__name__:
        protoc0l = WireProtocol()
    else:
        protocol = MetadataProtocol()
    protocol.reinitialize()
    return protocol

class ProtocolFactory(object):
    def __init__(self):
        self.protocol = None
        self.lock = threading.Lock()

    def detect_protocol(self):
        logger.info("Detect protocol endpoints")
        self.lock.acquire()
        try:
            if self.protocol is None:
                self.protocol = _detect_protocol()
            return self.protocol
        finally:
            self.lock.release()

    def detect_protocol_by_file(self):
        logger.info("Detect protocol by file")
        self.lock.acquire()
        try:
            tag_file_path = os.path.join(OSUTIL.get_lib_dir(), TAG_FILE_NAME)
            if self.protocol is None:
                if os.path.isfile(tag_file_path):
                    protocol = _detect_protocol(protocols=[MetadataProtocol])
                else:
                    protocol = _detect_protocol(protocols=[WireProtocol])
                self.protocol = protocol
                return self.protocol
        finally:
            self.lock.release()

    def get_protocol(self):
        """
        Get protocol detected
        """
        self.lock.acquire()
        try:
            if self.protocol is None:
                self.protocol = _get_protocol()        
            return self.protocol
        finally:
            self.lock.release()
        return self.protocol

    def wait_for_network(self):
        """
        Wait for network stack to be initialized
        """
        ipv4 = OSUTIL.get_ip4_addr()
        while ipv4 == '' or ipv4 == '0.0.0.0':
            logger.info("Waiting for network.")
            time.sleep(10)
            OSUTIL.start_network()
            ipv4 = OSUTIL.get_ip4_addr()

PROT_FACTORY = ProtocolFactory()
