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
    _ensure_file_removed(lib_directory, _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME)
    _ensure_file_removed(lib_directory, _LEGACY_METADATA_SERVER_P7B_FILE_NAME)


def _reset_firewall_rules():
    """
    Removes MetadataServer firewall rule so IMDS can be used.
    """
    try:
        _remove_firewall(dst_ip=_KNOWN_METADATASERVER_IP, uid=os.getuid(), wait=_get_firewall_will_wait())
    except Exception as e:
        add_event(op=WALAEventOperation.Firewall, message="Failed to remove firewall rule for MetadataServer: {0}".format(e), is_success=False)


def _ensure_file_removed(directory, file_name):
    """
    Removes files if they are present.
    """
    path = os.path.join(directory, file_name)
    if os.path.isfile(path):
        os.remove(path)

#
# NOTE: The code below was taken almost verbatim from the old firewall code that use to reside in osutil (default.py), with only very minor edits
#

_IPTABLES_VERSION_PATTERN = re.compile(r"^[^\d\.]*([\d\.]+).*$")
_IPTABLES_LOCKING_VERSION = FlexibleVersion('1.4.21')


def _add_wait(wait, command):
    """
    If 'wait' is True, adds the wait option (-w) to the given iptables command line
    """
    if wait:
        command.insert(1, "-w")
    return command


def _get_iptables_version_command():
    return ["iptables", "--version"]


# Precisely delete the rules created by the agent. This rule was used <= 2.2.25.  This rule helped to validate our change, and determine impact.
def _get_firewall_delete_conntrack_accept_command(wait, destination):
    return _add_wait(
        wait,
        ["iptables", "-t", "security", "-D", "OUTPUT", "-d", destination, "-p", "tcp", "-m", "conntrack", "--ctstate", "INVALID,NEW", "-j", "ACCEPT"])


def _get_delete_accept_tcp_rule(wait, destination):
    return _add_wait(
        wait,
        ["iptables", "-t", "security", "-D", "OUTPUT", "-d", destination, "-p", "tcp", "--destination-port", "53", "-j", "ACCEPT"])


def _get_firewall_delete_owner_accept_command(wait, destination, owner_uid):
    return _add_wait(
        wait,
        ["iptables", "-t", "security", "-D", "OUTPUT", "-d", destination, "-p", "tcp", "-m", "owner", "--uid-owner", str(owner_uid), "-j", "ACCEPT"])


def _get_firewall_delete_conntrack_drop_command(wait, destination):
    return _add_wait(
        wait,
        ["iptables", "-t", "security", "-D", "OUTPUT", "-d", destination, "-p", "tcp", "-m", "conntrack", "--ctstate", "INVALID,NEW", "-j", "DROP"])


def _get_firewall_will_wait():
    # Determine if iptables will serialize access
    try:
        output = shellutil.run_command(_get_iptables_version_command())
    except Exception as e:
        msg = "Unable to determine version of iptables: {0}".format(ustr(e))
        logger.warn(msg)
        raise Exception(msg)

    m = _IPTABLES_VERSION_PATTERN.match(output)
    if m is None:
        msg = "iptables did not return version information: {0}".format(output)
        logger.warn(msg)
        raise Exception(msg)

    wait = "-w" \
        if FlexibleVersion(m.group(1)) >= _IPTABLES_LOCKING_VERSION \
        else ""
    return wait


def _delete_rule(rule):
    """
    Continually execute the delete operation until the return
    code is non-zero or the limit has been reached.
    """
    for i in range(1, 100):  # pylint: disable=W0612
        try:
            rc = shellutil.run_command(rule)  # pylint: disable=W0612
        except shellutil.CommandError as e:
            if e.returncode == 1:
                return
            if e.returncode == 2:
                raise Exception("invalid firewall deletion rule '{0}'".format(rule))


def _remove_firewall(dst_ip, uid, wait):
    try:
        # This rule was <= 2.2.25 only, and may still exist on some VMs.  Until 2.2.25
        # has aged out, keep this cleanup in place.
        _delete_rule(_get_firewall_delete_conntrack_accept_command(wait, dst_ip))

        _delete_rule(_get_delete_accept_tcp_rule(wait, dst_ip))
        _delete_rule(_get_firewall_delete_owner_accept_command(wait, dst_ip, uid))
        _delete_rule(_get_firewall_delete_conntrack_drop_command(wait, dst_ip))

        return True

    except Exception as e:
        logger.info("Unable to remove firewall -- no further attempts will be made: {0}".format(ustr(e)))
        return False

