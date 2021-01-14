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

import errno
import os
import re
import time
import threading

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.singletonperthread import SingletonPerThread

from azurelinuxagent.common.exception import ProtocolError, OSUtilError, \
                                      ProtocolNotFoundError, DhcpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.dhcp import get_dhcp_handler
from azurelinuxagent.common.protocol.metadata_server_migration_util import cleanup_metadata_server_artifacts, \
                                                                           is_metadata_server_artifact_present
from azurelinuxagent.common.protocol.ovfenv import OvfEnv
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP, \
                                                  IOErrorCounter

OVF_FILE_NAME = "ovf-env.xml"
PROTOCOL_FILE_NAME = "Protocol"
MAX_RETRY = 360
PROBE_INTERVAL = 10
ENDPOINT_FILE_NAME = "WireServerEndpoint"
PASSWORD_PATTERN = "<UserPassword>.*?<"
PASSWORD_REPLACEMENT = "<UserPassword>*<"
WIRE_PROTOCOL_NAME = "WireProtocol"

def get_protocol_util():
    return ProtocolUtil()

class ProtocolUtil(SingletonPerThread):
    """
    ProtocolUtil handles initialization for protocol instance. 2 protocol types
    are invoked, wire protocol and metadata protocols.

    Note: ProtocolUtil is a sub class of SingletonPerThread, this basically means that there would only be 1 single
    instance of ProtocolUtil object per thread.
    """

    def __init__(self):
        self._lock = threading.RLock()  # protects the files on disk created during protocol detection
        self._protocol = None
        self.endpoint = None
        self.osutil = get_osutil()
        self.dhcp_handler = get_dhcp_handler()

    def copy_ovf_env(self):
        """
        Copy ovf env file from dvd to hard disk.
        Remove password before save it to the disk
        """
        dvd_mount_point = conf.get_dvd_mount_point()
        ovf_file_path_on_dvd = os.path.join(dvd_mount_point, OVF_FILE_NAME)
        ovf_file_path = os.path.join(conf.get_lib_dir(), OVF_FILE_NAME)

        try:
            self.osutil.mount_dvd()
        except OSUtilError as e:
            raise ProtocolError("[CopyOvfEnv] Error mounting dvd: "
                                "{0}".format(ustr(e)))

        try:
            ovfxml = fileutil.read_file(ovf_file_path_on_dvd, remove_bom=True)
            ovfenv = OvfEnv(ovfxml)
        except (IOError, OSError) as e:
            raise ProtocolError("[CopyOvfEnv] Error reading file "
                                "{0}: {1}".format(ovf_file_path_on_dvd,
                                                  ustr(e)))

        try:
            ovfxml = re.sub(PASSWORD_PATTERN,
                            PASSWORD_REPLACEMENT,
                            ovfxml)
            fileutil.write_file(ovf_file_path, ovfxml)
        except (IOError, OSError) as e:
            raise ProtocolError("[CopyOvfEnv] Error writing file "
                                "{0}: {1}".format(ovf_file_path,
                                                  ustr(e)))

        self._cleanup_ovf_dvd()

        return ovfenv

    def _cleanup_ovf_dvd(self):
        try:
            self.osutil.umount_dvd()
            self.osutil.eject_dvd()
        except OSUtilError as e:
            logger.warn(ustr(e))

    def get_ovf_env(self):
        """
        Load saved ovf-env.xml
        """
        ovf_file_path = os.path.join(conf.get_lib_dir(), OVF_FILE_NAME)
        if os.path.isfile(ovf_file_path):
            xml_text = fileutil.read_file(ovf_file_path)
            return OvfEnv(xml_text)
        else:
            raise ProtocolError(
                "ovf-env.xml is missing from {0}".format(ovf_file_path))

    def _get_protocol_file_path(self):
        return os.path.join(
            conf.get_lib_dir(),
            PROTOCOL_FILE_NAME)

    def _get_wireserver_endpoint_file_path(self):
        return os.path.join(
            conf.get_lib_dir(),
            ENDPOINT_FILE_NAME)

    def get_wireserver_endpoint(self):
        self._lock.acquire()
        try:
            if self.endpoint:
                return self.endpoint

            file_path = self._get_wireserver_endpoint_file_path()
            if os.path.isfile(file_path):
                try:
                    self.endpoint = fileutil.read_file(file_path)

                    if self.endpoint:
                        logger.info("WireServer endpoint {0} read from file", self.endpoint)
                        return self.endpoint

                    logger.error("[GetWireserverEndpoint] Unexpected empty file {0}", file_path)
                except (IOError, OSError) as e:
                    logger.error("[GetWireserverEndpoint] Error reading file {0}: {1}", file_path, str(e))
            else:
                logger.error("[GetWireserverEndpoint] Missing file {0}", file_path)

            self.endpoint = KNOWN_WIRESERVER_IP
            logger.info("Using hardcoded Wireserver endpoint {0}", self.endpoint)

            return self.endpoint
        finally:
            self._lock.release()

    def _set_wireserver_endpoint(self, endpoint):
        try:
            self.endpoint = endpoint
            file_path = self._get_wireserver_endpoint_file_path()
            fileutil.write_file(file_path, endpoint)
        except (IOError, OSError) as e:
            raise OSUtilError(ustr(e))

    def _clear_wireserver_endpoint(self):
        """
        Cleanup previous saved wireserver endpoint.
        """

        self.endpoint = None
        endpoint_file_path = self._get_wireserver_endpoint_file_path()
        if not os.path.isfile(endpoint_file_path):
            return

        try:
            os.remove(endpoint_file_path)
        except (IOError, OSError) as e:
            # Ignore file-not-found errors (since the file is being removed)
            if e.errno == errno.ENOENT:
                return
            logger.error("Failed to clear wiresever endpoint: {0}", e)

    def _detect_protocol(self):
        """
        Probe protocol endpoints in turn.
        """
        self.clear_protocol()

        for retry in range(0, MAX_RETRY):
            try:
                endpoint = self.dhcp_handler.endpoint
                if endpoint is None:
                    # pylint: disable=W0105
                    '''
                    Check if DHCP can be used to get the wire protocol endpoint
                    ''' 
                    # pylint: enable=W0105
                    dhcp_available = self.osutil.is_dhcp_available()
                    if dhcp_available:
                        logger.info("WireServer endpoint is not found. Rerun dhcp handler")
                        try:
                            self.dhcp_handler.run()
                        except DhcpError as e:
                            raise ProtocolError(ustr(e))
                        endpoint = self.dhcp_handler.endpoint
                    else:
                        logger.info("_detect_protocol: DHCP not available")
                        endpoint = self.get_wireserver_endpoint()

                try:
                    protocol = WireProtocol(endpoint)
                    protocol.detect()
                    self._set_wireserver_endpoint(endpoint)
                    return protocol

                except ProtocolError as e:
                    logger.info("WireServer is not responding. Reset dhcp endpoint")
                    self.dhcp_handler.endpoint = None
                    self.dhcp_handler.skip_cache = True
                    raise e
    
            except ProtocolError as e:
                logger.info("Protocol endpoint not found: {0}", e)

            if retry < MAX_RETRY - 1:
                logger.info("Retry detect protocol: retry={0}", retry)
                time.sleep(PROBE_INTERVAL)
        raise ProtocolNotFoundError("No protocol found.")
    
    def _save_protocol(self, protocol_name):
        """
        Save protocol endpoint
        """
        protocol_file_path = self._get_protocol_file_path()
        try:
            fileutil.write_file(protocol_file_path, protocol_name)
        except (IOError, OSError) as e:
            logger.error("Failed to save protocol endpoint: {0}", e)

    def clear_protocol(self):
        """
        Cleanup previous saved protocol endpoint.
        """
        self._lock.acquire()
        try:
            logger.info("Clean protocol and wireserver endpoint")
            self._clear_wireserver_endpoint()
            self._protocol = None
            protocol_file_path = self._get_protocol_file_path()
            if not os.path.isfile(protocol_file_path):
                return

            try:
                os.remove(protocol_file_path)
            except (IOError, OSError) as e:
                # Ignore file-not-found errors (since the file is being removed)
                if e.errno == errno.ENOENT:
                    return
                logger.error("Failed to clear protocol endpoint: {0}", e)
        finally:
            self._lock.release()

    def get_protocol(self):
        """
        Detect protocol by endpoint.
        :returns: protocol instance
        """
        self._lock.acquire()
        try:
            if self._protocol is not None:
                return self._protocol

            # If the protocol file contains MetadataProtocol we need to fall through to 
            # _detect_protocol so that we can generate the WireServer transport certificates.
            protocol_file_path = self._get_protocol_file_path()
            if os.path.isfile(protocol_file_path) and fileutil.read_file(protocol_file_path) == WIRE_PROTOCOL_NAME:
                endpoint = self.get_wireserver_endpoint()
                self._protocol = WireProtocol(endpoint)

                # If metadataserver certificates are present we clean certificates
                # and remove MetadataServer firewall rule. It is possible
                # there was a previous intermediate upgrade before 2.2.48 but metadata artifacts 
                # were not cleaned up (intermediate updated agent does not have cleanup 
                # logic but we transitioned from Metadata to Wire protocol)
                if is_metadata_server_artifact_present():
                    cleanup_metadata_server_artifacts(self.osutil)
                return self._protocol

            logger.info("Detect protocol endpoint")

            protocol = self._detect_protocol()

            IOErrorCounter.set_protocol_endpoint(endpoint=protocol.get_endpoint())
            self._save_protocol(WIRE_PROTOCOL_NAME)

            self._protocol = protocol

            # Need to clean up MDS artifacts only after _detect_protocol so that we don't
            # delete MDS certificates if we can't reach WireServer and have to roll back
            # the update
            if is_metadata_server_artifact_present():
                cleanup_metadata_server_artifacts(self.osutil)

            return self._protocol
        finally:
            self._lock.release()
