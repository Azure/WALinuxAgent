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

from azurelinuxagent.common.exception import ProtocolError, OSUtilError, \
                                      ProtocolNotFoundError, DhcpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.dhcp import get_dhcp_handler
from azurelinuxagent.common.protocol.ovfenv import OvfEnv
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.protocol.metadata import MetadataProtocol, \
                                                     METADATA_ENDPOINT
from azurelinuxagent.common.utils.restutil import IOErrorCounter

OVF_FILE_NAME = "ovf-env.xml"
TAG_FILE_NAME = "useMetadataEndpoint.tag"
PROTOCOL_FILE_NAME = "Protocol"
MAX_RETRY = 3600
PROBE_INTERVAL = 1
PRE_DETECT_MAX_RETRY = 2
ENDPOINT_FILE_NAME = "WireServerEndpoint"
PASSWORD_PATTERN = "<UserPassword>.*?<"
PASSWORD_REPLACEMENT = "<UserPassword>*<"


class _nameset(set):
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError("%s not a valid value" % name)

prots = _nameset(("WireProtocol", "MetadataProtocol"))


def get_protocol_util():
    return ProtocolUtil()


class ProtocolUtil(object):

    """
    ProtocolUtil handles initialization for protocol instance. 2 protocol types
    are invoked, wire protocol and metadata protocols.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.protocol = None
        self.osutil = get_osutil()
        self.dhcp_handler = get_dhcp_handler()

        self.wire_protocol = None
        self.wire_lock = threading.Lock()
        self.metadata_protocol = None
        self.metadata_lock = threading.Lock()

    def copy_ovf_env(self):
        """
        Copy ovf env file from dvd to hard disk.
        Remove password before save it to the disk
        """
        dvd_mount_point = conf.get_dvd_mount_point()
        ovf_file_path_on_dvd = os.path.join(dvd_mount_point, OVF_FILE_NAME)
        tag_file_path_on_dvd = os.path.join(dvd_mount_point, TAG_FILE_NAME)
        ovf_file_path = os.path.join(conf.get_lib_dir(), OVF_FILE_NAME)
        tag_file_path = os.path.join(conf.get_lib_dir(), TAG_FILE_NAME)

        try:
            self.osutil.mount_dvd()
        except OSUtilError as e:
            raise ProtocolError("[CopyOvfEnv] Error mounting dvd: "
                                "{0}".format(ustr(e)))

        try:
            ovfxml = fileutil.read_file(ovf_file_path_on_dvd, remove_bom=True)
            ovfenv = OvfEnv(ovfxml)
        except IOError as e:
            raise ProtocolError("[CopyOvfEnv] Error reading file "
                                "{0}: {1}".format(ovf_file_path_on_dvd,
                                                  ustr(e)))

        try:
            ovfxml = re.sub(PASSWORD_PATTERN,
                            PASSWORD_REPLACEMENT,
                            ovfxml)
            fileutil.write_file(ovf_file_path, ovfxml)
        except IOError as e:
            raise ProtocolError("[CopyOvfEnv] Error writing file "
                                "{0}: {1}".format(ovf_file_path,
                                                  ustr(e)))

        try:
            if os.path.isfile(tag_file_path_on_dvd):
                logger.info("Found {0} in provisioning ISO", TAG_FILE_NAME)
                shutil.copyfile(tag_file_path_on_dvd, tag_file_path)
        except IOError as e:
            raise ProtocolError("[CopyOvfEnv] Error copying file "
                                "{0} to {1}: {2}".format(tag_file_path,
                                                         tag_file_path,
                                                         ustr(e)))
        # defer the clean up to another thread to save time for provisioning.
        # can do this because do not handle the error for now.
        clean_t = threading.Thread(
            target=self._cleanup_ovf_dvd,
            name="cleanup_dvd")
        clean_t.start()

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

    def _get_wireserver_endpoint(self):
        try:
            file_path = os.path.join(conf.get_lib_dir(), ENDPOINT_FILE_NAME)
            return fileutil.read_file(file_path)
        except IOError as e:
            raise OSUtilError(ustr(e))

    def _set_wireserver_endpoint(self, endpoint):
        try:
            file_path = os.path.join(conf.get_lib_dir(), ENDPOINT_FILE_NAME)
            fileutil.write_file(file_path, endpoint)
        except IOError as e:
            raise OSUtilError(ustr(e))

    def _detect_wire_protocol(self):
        """
        detect the wire protocol.
        """
        self.wire_lock.acquire()
        try:
            if self.wire_protocol is not None:
                return self.wire_protocol
            endpoint = self.dhcp_handler.endpoint
            if endpoint is None:
                logger.info(
                    "WireServer endpoint is not found. Rerun dhcp handler")
                try:
                    self.dhcp_handler.run()
                except DhcpError as e:
                    raise ProtocolError(ustr(e))
                endpoint = self.dhcp_handler.endpoint

            try:
                protocol = WireProtocol(endpoint)
                protocol.detect()
                self._set_wireserver_endpoint(endpoint)
                # save it for other thread found it.
                self.wire_protocol = protocol
                return protocol
            except ProtocolError as e:
                logger.info("WireServer is not responding. Reset endpoint")
                self.dhcp_handler.endpoint = None
                self.dhcp_handler.skip_cache = True
                raise e
        finally:
            self.wire_lock.release()

    def _detect_metadata_protocol(self):
        """
        detect the metadata protocol
        """
        self.metadata_lock.acquire()
        try:
            if self.metadata_protocol is not None:
                return self.metadata_protocol
            protocol = MetadataProtocol()
            protocol.detect()
            self.metadata_protocol = protocol
            return protocol
        finally:
            self.metadata_lock.release()

    def _detect_protocol(self, protocols):
        """
        Probe protocol endpoints in turn.
        """

        self.clear_protocol()
        for retry in range(0, MAX_RETRY):
            for protocol_name in protocols:
                try:
                    if protocol_name == prots.WireProtocol:
                        if self.wire_protocol is not None:
                            # check whether we already detected the protocol
                            # in the pre_detect_async
                            protocol = self.wire_protocol
                        else:
                            protocol = self._detect_wire_protocol()
                    else:
                        if self.metadata_protocol is not None:
                            protocol = self.metadata_protocol
                        else:
                            protocol = self._detect_metadata_protocol()

                    return (protocol_name, protocol)

                except ProtocolError as e:
                    logger.info(
                        "Protocol endpoint not found: {0}, {1}",
                        protocol_name, e)

            if retry < MAX_RETRY - 1:
                logger.info("Retry detect protocols: retry={0}", retry)
                time.sleep(PROBE_INTERVAL)
        raise ProtocolNotFoundError("No protocol found.")

    def _get_protocol(self):
        """
        Get protocol instance based on previous detecting result.
        """
        protocol_file_path = os.path.join(conf.get_lib_dir(),
                                          PROTOCOL_FILE_NAME)
        if not os.path.isfile(protocol_file_path):
            raise ProtocolNotFoundError("No protocol found")

        protocol_name = fileutil.read_file(protocol_file_path)
        if protocol_name == prots.WireProtocol:
            endpoint = self._get_wireserver_endpoint()
            return WireProtocol(endpoint)
        elif protocol_name == prots.MetadataProtocol:
            return MetadataProtocol()
        else:
            raise ProtocolNotFoundError(("Unknown protocol: {0}"
                                         "").format(protocol_name))

    def _save_protocol(self, protocol_name):
        """
        Save protocol endpoint
        """
        protocol_file_path = os.path.join(
            conf.get_lib_dir(),
            PROTOCOL_FILE_NAME)
        try:
            fileutil.write_file(protocol_file_path, protocol_name)
        except IOError as e:
            logger.error("Failed to save protocol endpoint: {0}", e)

    def clear_protocol(self):
        """
        Cleanup previous saved endpoint.
        """
        logger.info("Clean protocol")
        self.protocol = None
        self.wire_protocol = None
        self.metadata_protocol = None
        protocol_file_path = os.path.join(
            conf.get_lib_dir(),
            PROTOCOL_FILE_NAME)
        if not os.path.isfile(protocol_file_path):
            return

        try:
            os.remove(protocol_file_path)
        except IOError as e:
            # Ignore file-not-found errors (since the file is being removed)
            if e.errno == errno.ENOENT:
                return
            logger.error("Failed to clear protocol endpoint: {0}", e)

    def _detect_protocol_daemon(self, stopped, protocol_name):
        for retry in range(0, PRE_DETECT_MAX_RETRY):
            try:
                if protocol_name == prots.WireProtocol:
                    if self.wire_protocol is not None:
                        break
                    protocol = self._detect_wire_protocol()
                else:
                    if self.metadata_protocol is not None:
                        break
                    protocol = self._detect_metadata_protocol()
                if protocol is not None:
                        break
            except ProtocolError as e:
                logger.info(
                    "Protocol endpoint not found when pre-detect: {0}, {1}",
                    protocol_name, e)

            if retry < PRE_DETECT_MAX_RETRY - 1:
                logger.info("Retry pre-detect protocols: retry={0}", retry)
                time.sleep(PROBE_INTERVAL)

    def pre_detect_async(self):
        """
        detect the protocol to save time for provisioning.
        """
        detect_wire_t = threading.Thread(
            target=self._detect_protocol_daemon,
            args=(prots.WireProtocol,))
        detect_wire_t.start()
        detect_meta_t = threading.Thread(
            target=self._detect_protocol_daemon,
            args=(prots.MetadataProtocol,))
        detect_meta_t.start()

    def get_protocol(self, by_file=False):
        """
        Detect protocol by endpoints, check the protocol file first,
        if not exist, then if by_file is True,
        detect MetadataProtocol in priority.

        :returns: protocol instance
        """
        self.lock.acquire()

        try:
            if self.protocol is not None:
                return self.protocol

            try:
                self.protocol = self._get_protocol()
                return self.protocol
            except ProtocolNotFoundError:
                pass
            logger.info("Detect protocol endpoints")
            protocols = [prots.WireProtocol]

            if by_file:
                protocols.insert(0, prots.MetadataProtocol)
            else:
                protocols.append(prots.MetadataProtocol)
            protocol_name, protocol = self._detect_protocol(protocols)

            self._save_protocol(protocol_name)
            IOErrorCounter.set_protocol_endpoint(endpoint=protocol.endpoint)

            self.protocol = protocol
            return self.protocol

        finally:
            self.lock.release()
