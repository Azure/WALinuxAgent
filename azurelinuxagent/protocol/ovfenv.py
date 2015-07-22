# Windows Azure Linux Agent
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
"""
Copy and parse ovf-env.xml from provisiong ISO and local cache
"""
import os
import re
import xml.etree.ElementTree as ET
import azurelinuxagent.logger as logger
import azurelinuxagent.utils.fileutil as fileutil
from azurelinuxagent.utils.textutil import find_text
from azurelinuxagent.utils.osutil import OSUTIL, OSUtilError
from azurelinuxagent.protocol import ProtocolError

OVF_FILE_NAME = "ovf-env.xml"
OVF_VERSION = "1.0"
OVF_NAME_SPACE = {
        "oe" : "http://schemas.dmtf.org/ovf/environment/1",
        "wa" : "http://schemas.microsoft.com/windowsazure",
        "i" : "http://www.w3.org/2001/XMLSchema-instance"
}

def get_ovf_env():
    """
    Load saved ovf-env.xml
    """
    ovf_file_path = os.path.join(OSUTIL.get_lib_dir(), OVF_FILE_NAME)
    if os.path.isfile(ovf_file_path):
        xml_text = fileutil.read_file(ovf_file_path)
        return OvfEnv(xml_text)
    else:
        raise ProtocolError("ovf-env.xml is missing.")

def copy_ovf_env():
    """
    Copy ovf env file from dvd to hard disk.
    Remove password before save it to the disk
    """
    try:
        OSUTIL.mount_dvd()
        ovf_file_path_on_dvd = OSUTIL.get_ovf_env_file_path_on_dvd()
        ovfxml = fileutil.read_file(ovf_file_path_on_dvd, remove_bom=True)
        ovfenv = OvfEnv(ovfxml)
        ovfxml = re.sub("<UserPassword>.*?<", "<UserPassword>*<", ovfxml)
        ovf_file_path = os.path.join(OSUTIL.get_lib_dir(), OVF_FILE_NAME)
        fileutil.write_file(ovf_file_path, ovfxml)
        OSUTIL.umount_dvd()
    except IOError as e:
        raise ProtocolError(str(e))
    except OSUtilError as e:
        raise ProtocolError(str(e))
    return ovfenv

def _validate_ovf(val, msg):
    if val is None:
        raise ProtocolError("Failed to parse OVF XML: {0}".format(msg))

class OvfEnv(object):
    """
    Read, and process provisioning info from provisioning file OvfEnv.xml
    """
    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("ovf-env is None")
        logger.verb("Load ovf-env.xml")
        self.hostname = None
        self.username = None
        self.user_password = None
        self.customdata = None
        self.disable_ssh_password_auth = True
        self.ssh_pubkeys = []
        self.ssh_keypairs = []
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        Parse xml tree, retreiving user and ssh key information.
        Return self.
        """
        ns = OVF_NAME_SPACE
        xml_doc = ET.fromstring(xml_text)
        section = xml_doc.find(".//wa:ProvisioningSection", ns)
        _validate_ovf(section, "ProvisioningSection not found")

        version = section.find("wa:Version", ns).text
        _validate_ovf(version, "Version not found")

        if version > OVF_VERSION:
            logger.warn("Newer provisioning configuration detected. "
                        "Please consider updating waagent")

        conf_set = section.find("wa:LinuxProvisioningConfigurationSet", ns)
        _validate_ovf(conf_set, "LinuxProvisioningConfigurationSet not found")

        self.hostname = find_text(conf_set, "wa:HostName", ns=ns)
        _validate_ovf(self.hostname, "HostName not found")

        self.username = find_text(conf_set, "wa:UserName", ns=ns)
        _validate_ovf(self.username, "UserName not found")

        self.user_password = find_text(conf_set, "wa:UserPassword", ns=ns)

        self.customdata = find_text(conf_set, "wa:CustomData", ns=ns)

        auth = find_text(conf_set, "wa:DisableSshPasswordAuthentication", ns=ns)
        if auth is not None and auth.lower() == "true":
            self.disable_ssh_password_auth = True
        else:
            self.disable_ssh_password_auth = False

        public_keys = conf_set.findall("wa:SSH/wa:PublicKeys/wa:PublicKey", ns)
        for public_key in public_keys:
            path = find_text(public_key, "wa:Path", ns=ns)
            fingerprint = find_text(public_key, "wa:Fingerprint", ns=ns)
            value = find_text(public_key, "wa:Value", ns=ns)
            self.ssh_pubkeys.append((path, fingerprint, value))

        keypairs = conf_set.findall("wa:SSH/wa:KeyPairs/wa:KeyPair", ns)
        for keypair in keypairs:
            path = find_text(keypair, "wa:Path", ns=ns)
            fingerprint = find_text(keypair, "wa:Fingerprint", ns=ns)
            self.ssh_keypairs.append((path, fingerprint))

