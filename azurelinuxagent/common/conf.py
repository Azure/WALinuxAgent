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

"""
Module conf loads and parses configuration file
"""
import os
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.exception import AgentConfigError

class ConfigurationProvider(object):
    """
    Parse amd store key:values in /etc/waagent.conf.
    """
    def __init__(self):
        self.values = dict()

    def load(self, content):
        if not content:
            raise AgentConfigError("Can't not parse empty configuration")
        for line in content.split('\n'):
            if not line.startswith("#") and "=" in line:
                parts = line.split()[0].split('=')
                value = parts[1].strip("\" ")
                if value != "None":
                    self.values[parts[0]] = value
                else:
                    self.values[parts[0]] = None

    def get(self, key, default_val):
        val = self.values.get(key)
        return val if val is not None else default_val

    def get_switch(self, key, default_val):
        val = self.values.get(key)
        if val is not None and val.lower() == 'y':
            return True
        elif val is not None and val.lower() == 'n':
            return False
        return default_val

    def get_int(self, key, default_val):
        try:
            return int(self.values.get(key))
        except TypeError:
            return default_val
        except ValueError:
            return default_val


__conf__ = ConfigurationProvider()

def load_conf_from_file(conf_file_path, conf=__conf__):
    """
    Load conf file from: conf_file_path
    """
    if os.path.isfile(conf_file_path) == False:
        raise AgentConfigError(("Missing configuration in {0}"
                                "").format(conf_file_path))
    try:
        content = fileutil.read_file(conf_file_path)
        conf.load(content)
    except IOError as err:
        raise AgentConfigError(("Failed to load conf file:{0}, {1}"
                                "").format(conf_file_path, err))

def get_logs_verbose(conf=__conf__):
    return conf.get_switch("Logs.Verbose", False)

def get_lib_dir(conf=__conf__):
    return conf.get("Lib.Dir", "/var/lib/waagent")

def get_dvd_mount_point(conf=__conf__):
    return conf.get("DVD.MountPoint", "/mnt/cdrom/secure")

def get_agent_pid_file_path(conf=__conf__):
    return conf.get("Pid.File", "/var/run/waagent.pid")

def get_ext_log_dir(conf=__conf__):
    return conf.get("Extension.LogDir", "/var/log/azure")

def get_openssl_cmd(conf=__conf__):
    return conf.get("OS.OpensslPath", "/usr/bin/openssl")

def get_home_dir(conf=__conf__):
    return conf.get("OS.HomeDir", "/home")

def get_passwd_file_path(conf=__conf__):
    return conf.get("OS.PasswordPath", "/etc/shadow")

def get_sudoers_dir(conf=__conf__):
    return conf.get("OS.SudoersDir", "/etc/sudoers.d")

def get_sshd_conf_file_path(conf=__conf__):
    return conf.get("OS.SshdConfigPath", "/etc/ssh/sshd_config")

def get_root_device_scsi_timeout(conf=__conf__):
    return conf.get("OS.RootDeviceScsiTimeout", None)

def get_ssh_host_keypair_type(conf=__conf__):
    return conf.get("Provisioning.SshHostKeyPairType", "rsa")

def get_provision_enabled(conf=__conf__):
    return conf.get_switch("Provisioning.Enabled", True)

def get_allow_reset_sys_user(conf=__conf__):
    return conf.get_switch("Provisioning.AllowResetSysUser", False)

def get_regenerate_ssh_host_key(conf=__conf__):
    return conf.get_switch("Provisioning.RegenerateSshHostKeyPair", False)

def get_delete_root_password(conf=__conf__):
    return conf.get_switch("Provisioning.DeleteRootPassword", False)

def get_decode_customdata(conf=__conf__):
    return conf.get_switch("Provisioning.DecodeCustomData", False)

def get_execute_customdata(conf=__conf__):
    return conf.get_switch("Provisioning.ExecuteCustomData", False)

def get_password_cryptid(conf=__conf__):
    return conf.get("Provisioning.PasswordCryptId", "6")

def get_password_crypt_salt_len(conf=__conf__):
    return conf.get_int("Provisioning.PasswordCryptSaltLength", 10)

def get_monitor_hostname(conf=__conf__):
    return conf.get_switch("Provisioning.MonitorHostName", False)

def get_httpproxy_host(conf=__conf__):
    return conf.get("HttpProxy.Host", None)

def get_httpproxy_port(conf=__conf__):
    return conf.get("HttpProxy.Port", None)

def get_detect_scvmm_env(conf=__conf__):
    return conf.get_switch("DetectScvmmEnv", False)

def get_resourcedisk_format(conf=__conf__):
    return conf.get_switch("ResourceDisk.Format", False)

def get_resourcedisk_enable_swap(conf=__conf__):
    return conf.get_switch("ResourceDisk.EnableSwap", False)

def get_resourcedisk_mountpoint(conf=__conf__):
    return conf.get("ResourceDisk.MountPoint", "/mnt/resource")

def get_resourcedisk_filesystem(conf=__conf__):
    return conf.get("ResourceDisk.Filesystem", "ext3")

def get_resourcedisk_swap_size_mb(conf=__conf__):
    return conf.get_int("ResourceDisk.SwapSizeMB", 0)

def get_autoupdate_gafamily(conf=__conf__):
    return conf.get("AutoUpdate.GAFamily", "Prod")

def get_autoupdate_enabled(conf=__conf__):
    return conf.get_switch("AutoUpdate.Enabled", True)

