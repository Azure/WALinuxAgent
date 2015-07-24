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

from azurelinuxagent.protocol.common import *

from azurelinuxagent.utils.osutil import OSUTIL, OSUtilError

def get_ovf_env():
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

OVF_FILE_NAME="ovf-env.xml"
class OvfEnv(object):
    """
    Read, and process provisioning info from provisioning file OvfEnv.xml
    """
    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("ovf-env is None")
        logger.verb("Load ovf-env.xml")
        self.parse(xml_text)

    def reinitialize(self):
        """
        Reset members.
        """
        self.wa_ns = "http://schemas.microsoft.com/windowsazure"
        self.ovf_ns = "http://schemas.dmtf.org/ovf/environment/1"
        self.major_version = 1
        self.minor_version = 0
        self.compute_name = None
        self.user_name = None
        self.user_password = None
        self.customdata = None
        self.disable_ssh_password_auth = True
        self.ssh_pubkeys = []
        self.ssh_keypairs = []

    def get_major_version(self):
        return self.major_version

    def get_minor_version(self):
        return self.minor_version

    def get_computer_name(self):
        return self.compute_name

    def get_username(self):
        return self.user_name

    def get_user_password(self):
        return self.user_password

    def clear_user_password(self):
        self.user_password = None

    def get_customdata(self):
        return self.customdata

    def get_disable_ssh_password_auth(self):
        return self.disable_ssh_password_auth

    def get_ssh_pubkeys(self):
        return self.ssh_pubkeys

    def get_ssh_keypairs(self):
        return self.ssh_keypairs

    def parse(self, xml_text):
        """
        Parse xml tree, retreiving user and ssh key information.
        Return self.
        """
        self.reinitialize()
        dom = xml.dom.minidom.parseString(xml_text)
        if len(dom.getElementsByTagNameNS(self.ovf_ns, "Environment")) != 1:
            logger.error("Unable to parse OVF XML.")
        section = None
        newer = False
        for p in dom.getElementsByTagNameNS(self.wa_ns, "ProvisioningSection"):
            for n in p.childNodes:
                if n.localName == "Version":
                    verparts = get_node_text(n).split('.')
                    major = int(verparts[0])
                    minor = int(verparts[1])
                    if major > self.major_version:
                        newer = True
                    if major != self.major_version:
                        break
                    if minor > self.minor_version:
                        newer = True
                    section = p
        if newer == True:
            logger.warn("Newer provisioning configuration detected. "
                    "Please consider updating waagent.")
            if section == None:
                logger.error("Could not find ProvisioningSection with "
                        "major version={0}", self.major_version)
                return None
        self.compute_name = get_node_text(section.getElementsByTagNameNS(self.wa_ns, "HostName")[0])
        self.user_name = get_node_text(section.getElementsByTagNameNS(self.wa_ns, "UserName")[0])
        try:
            self.user_password = get_node_text(section.getElementsByTagNameNS(self.wa_ns, "UserPassword")[0])
        except:
            pass
        cd_section=None
        cd_section=section.getElementsByTagNameNS(self.wa_ns, "CustomData")
        if len(cd_section) > 0 :
            self.customdata=get_node_text(cd_section[0])
        disable_ssh_password_auth = section.getElementsByTagNameNS(self.wa_ns, "DisableSshPasswordAuthentication")
        if len(disable_ssh_password_auth) != 0:
            self.disable_ssh_password_auth = (get_node_text(disable_ssh_password_auth[0]).lower() == "true")
        for pkey in section.getElementsByTagNameNS(self.wa_ns, "PublicKey"):
            logger.verb(repr(pkey))
            fp = None
            path = None
            for c in pkey.childNodes:
                if c.localName == "Fingerprint":
                    fp = get_node_text(c).upper()
                    logger.verb(fp)
                if c.localName == "Path":
                    path = get_node_text(c)
                    logger.verb(path)
            self.ssh_pubkeys += [[fp, path]]
        for keyp in section.getElementsByTagNameNS(self.wa_ns, "KeyPair"):
            fp = None
            path = None
            logger.verb(repr(keyp))
            for c in keyp.childNodes:
                if c.localName == "Fingerprint":
                    fp = get_node_text(c).upper()
                    logger.verb(fp)
                if c.localName == "Path":
                    path = get_node_text(c)
                    logger.verb(path)
            self.ssh_keypairs += [[fp, path]]
        return self

