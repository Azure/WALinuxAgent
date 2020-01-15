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
import shutil
import threading
import time

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.singletonperthread import SingletonPerThread

from azurelinuxagent.common.exception import ProtocolError, OSUtilError, \
                                      ProtocolNotFoundError, DhcpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.dhcp import get_dhcp_handler
from azurelinuxagent.common.protocol.ovfenv import OvfEnv
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP, \
                                                  IOErrorCounter

OVF_FILE_NAME = "ovf-env.xml"
TAG_FILE_NAME = "useMetadataEndpoint.tag"
MAX_RETRY = 360
PROBE_INTERVAL = 10
ENDPOINT_FILE_NAME = "WireServerEndpoint"
PASSWORD_PATTERN = "<UserPassword>.*?<"
PASSWORD_REPLACEMENT = "<UserPassword>*<"


class _nameset(set):
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError("%s not a valid value" % name)


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
        tag_file_path_on_dvd = os.path.join(dvd_mount_point, TAG_FILE_NAME)
        ovf_file_path = os.path.join(conf.get_lib_dir(), OVF_FILE_NAME)
        tag_file_path = self._get_tag_file_path()

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

        try:
            if os.path.isfile(tag_file_path_on_dvd):
                logger.info("Found {0} in provisioning ISO", TAG_FILE_NAME)
                shutil.copyfile(tag_file_path_on_dvd, tag_file_path)
        except (IOError, OSError) as e:
            raise ProtocolError("[CopyOvfEnv] Error copying file "
                                "{0} to {1}: {2}".format(tag_file_path,
                                                         tag_file_path,
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

    def _get_wireserver_endpoint_file_path(self):
        return os.path.join(
            conf.get_lib_dir(),
            ENDPOINT_FILE_NAME)

    def _get_tag_file_path(self):
        return os.path.join(
            conf.get_lib_dir(),
            TAG_FILE_NAME)

    def get_wireserver_endpoint(self):

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

    def _detect_wire_protocol(self):
        endpoint = self.dhcp_handler.endpoint
        if endpoint is None:
            '''
            Check if DHCP can be used to get the wire protocol endpoint
            '''
            dhcp_available = self.osutil.is_dhcp_available()
            if dhcp_available:
                logger.info("WireServer endpoint is not found. Rerun dhcp handler")
                try:
                    self.dhcp_handler.run()
                except DhcpError as e:
                    raise ProtocolError(ustr(e))
                endpoint = self.dhcp_handler.endpoint
            else:
                logger.info("_detect_wire_protocol: DHCP not available")
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

    def _detect_protocol(self):
        """
        Probe protocol endpoints in turn.
        """
        self.clear_protocol()

        for retry in range(0, MAX_RETRY):
            try:
                protocol = self._detect_wire_protocol()

                return protocol

            except ProtocolError as e:
                logger.info("Wire protocol endpoint not found: {0}", e)

            if retry < MAX_RETRY - 1:
                logger.info("Retry detect protocols: retry={0}", retry)
                time.sleep(PROBE_INTERVAL)
        raise ProtocolNotFoundError("No protocol found.")

    def _get_protocol(self):
        """
        Get protocol instance based on previous detecting result.
        """
        endpoint = self.get_wireserver_endpoint()
        return WireProtocol(endpoint)

    def clear_protocol(self):
        """
        Cleanup previous saved protocol endpoint.
        """
        logger.info("Clean protocol and wireserver endpoint")
        self._clear_wireserver_endpoint()
        self._protocol = None

    def get_protocol(self): 
        """
        Detect protocol by endpoints
        :returns: protocol instance
        """

        if self._protocol is not None:
            return self._protocol

        try:
            self._protocol = self._get_protocol()
            return self._protocol
        except ProtocolNotFoundError:
            pass
        logger.info("Detect protocol endpoints")

        protocol = self._detect_protocol()

        IOErrorCounter.set_protocol_endpoint(endpoint=protocol.get_endpoint())

        self._protocol = protocol
        return self._protocol
