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

"""
Module conf loads and parses configuration file
""" # pylint: disable=W0105
import os
import os.path

from azurelinuxagent.common.utils.fileutil import read_file #pylint: disable=R0401
from azurelinuxagent.common.exception import AgentConfigError

DISABLE_AGENT_FILE = 'disable_agent'


class ConfigurationProvider(object):
    """
    Parse and store key:values in /etc/waagent.conf.
    """

    def __init__(self):
        self.values = dict()

    def load(self, content):
        if not content:
            raise AgentConfigError("Can't not parse empty configuration")
        for line in content.split('\n'):
            if not line.startswith("#") and "=" in line:
                parts = line.split('=', 1)
                if len(parts) < 2:
                    continue
                key = parts[0].strip()
                value = parts[1].split('#')[0].strip("\" ").strip()
                self.values[key] = value if value != "None" else None

    def get(self, key, default_val):
        val = self.values.get(key)
        return val if val is not None else default_val

    def get_switch(self, key, default_val):
        val = self.values.get(key)
        if val is not None and val.lower() == 'y': # pylint: disable=R1705
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
    if os.path.isfile(conf_file_path) == False: # pylint: disable=C0121
        raise AgentConfigError(("Missing configuration in {0}"
                                "").format(conf_file_path))
    try:
        content = read_file(conf_file_path)
        conf.load(content)
    except IOError as err:
        raise AgentConfigError(("Failed to load conf file:{0}, {1}"
                                "").format(conf_file_path, err))


__SWITCH_OPTIONS__ = {
    "OS.AllowHTTP": False,
    "OS.EnableFirewall": False,
    "OS.EnableFIPS": False,
    "OS.EnableRDMA": False,
    "OS.UpdateRdmaDriver": False,
    "OS.CheckRdmaDriver": False,
    "Logs.Verbose": False,
    "Logs.Console": True,
    "Logs.Collect": False,
    "Extensions.Enabled": True,
    "Provisioning.AllowResetSysUser": False,
    "Provisioning.RegenerateSshHostKeyPair": False,
    "Provisioning.DeleteRootPassword": False,
    "Provisioning.DecodeCustomData": False,
    "Provisioning.ExecuteCustomData": False,
    "Provisioning.MonitorHostName": False,
    "DetectScvmmEnv": False,
    "ResourceDisk.Format": False,
    "ResourceDisk.EnableSwap": False,
    "ResourceDisk.EnableSwapEncryption": False,
    "AutoUpdate.Enabled": True,
    "EnableOverProvisioning": True,
    "CGroups.EnforceLimits": False,
}


__STRING_OPTIONS__ = {
    "Lib.Dir": "/var/lib/waagent",
    "DVD.MountPoint": "/mnt/cdrom/secure",
    "Pid.File": "/var/run/waagent.pid",
    "Extension.LogDir": "/var/log/azure",
    "OS.OpensslPath": "/usr/bin/openssl",
    "OS.SshDir": "/etc/ssh",
    "OS.HomeDir": "/home",
    "OS.PasswordPath": "/etc/shadow",
    "OS.SudoersDir": "/etc/sudoers.d",
    "OS.RootDeviceScsiTimeout": None,
    "Provisioning.Agent": "auto",
    "Provisioning.SshHostKeyPairType": "rsa",
    "Provisioning.PasswordCryptId": "6",
    "HttpProxy.Host": None,
    "ResourceDisk.MountPoint": "/mnt/resource",
    "ResourceDisk.MountOptions": None,
    "ResourceDisk.Filesystem": "ext3",
    "AutoUpdate.GAFamily": "Prod",
    "CGroups.Excluded": "customscript,runcommand",
}


__INTEGER_OPTIONS__ = {
    "Extensions.GoalStatePeriod": 6,
    "Extensions.GoalStateHistoryCleanupPeriod": 86400,
    "OS.EnableFirewallPeriod": 30,
    "OS.RemovePersistentNetRulesPeriod": 30,
    "OS.RootDeviceScsiTimeoutPeriod": 30,
    "OS.MonitorDhcpClientRestartPeriod": 30,
    "OS.SshClientAliveInterval": 180,
    "Provisioning.MonitorHostNamePeriod": 30,
    "Provisioning.PasswordCryptSaltLength": 10,
    "HttpProxy.Port": None,
    "ResourceDisk.SwapSizeMB": 0,
    "Autoupdate.Frequency": 3600,
    "Logs.CollectPeriod": 3600
}


def get_configuration(conf=__conf__):
    options = {}
    for option in __SWITCH_OPTIONS__:
        options[option] = conf.get_switch(option, __SWITCH_OPTIONS__[option])

    for option in __STRING_OPTIONS__:
        options[option] = conf.get(option, __STRING_OPTIONS__[option])

    for option in __INTEGER_OPTIONS__:
        options[option] = conf.get_int(option, __INTEGER_OPTIONS__[option])

    return options


def get_default_value(option):
    if option in __STRING_OPTIONS__:
        return __STRING_OPTIONS__[option]
    raise ValueError("{0} is not a valid configuration parameter.".format(option))


def get_int_default_value(option):
    if option in __INTEGER_OPTIONS__:
        return int(__INTEGER_OPTIONS__[option])
    raise ValueError("{0} is not a valid configuration parameter.".format(option))


def get_switch_default_value(option):
    if option in __SWITCH_OPTIONS__:
        return __SWITCH_OPTIONS__[option]
    raise ValueError("{0} is not a valid configuration parameter.".format(option))


def enable_firewall(conf=__conf__):
    return conf.get_switch("OS.EnableFirewall", False)


def get_enable_firewall_period(conf=__conf__):
    return conf.get_int("OS.EnableFirewallPeriod", 30)


def get_remove_persistent_net_rules_period(conf=__conf__):
    return conf.get_int("OS.RemovePersistentNetRulesPeriod", 30)


def get_monitor_dhcp_client_restart_period(conf=__conf__):
    return conf.get_int("OS.MonitorDhcpClientRestartPeriod", 30)


def enable_rdma(conf=__conf__):
    return conf.get_switch("OS.EnableRDMA", False) or \
           conf.get_switch("OS.UpdateRdmaDriver", False) or \
           conf.get_switch("OS.CheckRdmaDriver", False)


def enable_rdma_update(conf=__conf__):
    return conf.get_switch("OS.UpdateRdmaDriver", False)


def enable_check_rdma_driver(conf=__conf__):
    return conf.get_switch("OS.CheckRdmaDriver", True)


def get_logs_verbose(conf=__conf__):
    return conf.get_switch("Logs.Verbose", False)


def get_logs_console(conf=__conf__):
    return conf.get_switch("Logs.Console", True)


def get_collect_logs(conf=__conf__):
    return conf.get_switch("Logs.Collect", False)


def get_collect_logs_period(conf=__conf__):
    return conf.get_int("Logs.CollectPeriod", 3600)


def get_lib_dir(conf=__conf__):
    return conf.get("Lib.Dir", "/var/lib/waagent")


def get_published_hostname(conf=__conf__):
    return os.path.join(get_lib_dir(conf), 'published_hostname')


def get_dvd_mount_point(conf=__conf__):
    return conf.get("DVD.MountPoint", "/mnt/cdrom/secure")


def get_agent_pid_file_path(conf=__conf__):
    return conf.get("Pid.File", "/var/run/waagent.pid")


def get_ext_log_dir(conf=__conf__):
    return conf.get("Extension.LogDir", "/var/log/azure")


def get_agent_log_file():
    return "/var/log/waagent.log"


def get_fips_enabled(conf=__conf__):
    return conf.get_switch("OS.EnableFIPS", False)


def get_openssl_cmd(conf=__conf__):
    return conf.get("OS.OpensslPath", "/usr/bin/openssl")


def get_ssh_client_alive_interval(conf=__conf__):
    return conf.get("OS.SshClientAliveInterval", 180)


def get_ssh_dir(conf=__conf__):
    return conf.get("OS.SshDir", "/etc/ssh")


def get_home_dir(conf=__conf__):
    return conf.get("OS.HomeDir", "/home")


def get_passwd_file_path(conf=__conf__):
    return conf.get("OS.PasswordPath", "/etc/shadow")


def get_sudoers_dir(conf=__conf__):
    return conf.get("OS.SudoersDir", "/etc/sudoers.d")


def get_sshd_conf_file_path(conf=__conf__):
    return os.path.join(get_ssh_dir(conf), "sshd_config")


def get_ssh_key_glob(conf=__conf__):
    return os.path.join(get_ssh_dir(conf), 'ssh_host_*key*')


def get_ssh_key_private_path(conf=__conf__):
    return os.path.join(get_ssh_dir(conf),
        'ssh_host_{0}_key'.format(get_ssh_host_keypair_type(conf))) 


def get_ssh_key_public_path(conf=__conf__):
    return os.path.join(get_ssh_dir(conf),
        'ssh_host_{0}_key.pub'.format(get_ssh_host_keypair_type(conf))) 


def get_root_device_scsi_timeout(conf=__conf__):
    return conf.get("OS.RootDeviceScsiTimeout", None)


def get_root_device_scsi_timeout_period(conf=__conf__):
    return conf.get_int("OS.RootDeviceScsiTimeoutPeriod", 30)


def get_ssh_host_keypair_type(conf=__conf__):
    keypair_type = conf.get("Provisioning.SshHostKeyPairType", "rsa")
    if keypair_type == "auto":
        '''
        auto generates all supported key types and returns the
        rsa thumbprint as the default.
        '''
        return "rsa"
    return keypair_type


def get_ssh_host_keypair_mode(conf=__conf__):
    return conf.get("Provisioning.SshHostKeyPairType", "rsa")


def get_extensions_enabled(conf=__conf__):
    return conf.get_switch("Extensions.Enabled", True)


def get_goal_state_period(conf=__conf__):
    return conf.get_int("Extensions.GoalStatePeriod", 6)


def get_goal_state_history_cleanup_period(conf=__conf__):
    return conf.get_int("Extensions.GoalStateHistoryCleanupPeriod", 86400)


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


def get_provisioning_agent(conf=__conf__):
    return conf.get("Provisioning.Agent", "auto")


def get_provision_enabled(conf=__conf__):
    """
    Provisioning (as far as waagent is concerned) is enabled if either the
    agent is set to 'auto' or 'waagent'. This wraps logic that was introduced
    for flexible provisioning agent configuration and detection. The replaces
    the older bool setting to turn provisioning on or off.
    """

    return get_provisioning_agent(conf) in ("auto", "waagent")


def get_password_crypt_salt_len(conf=__conf__):
    return conf.get_int("Provisioning.PasswordCryptSaltLength", 10)


def get_monitor_hostname(conf=__conf__):
    return conf.get_switch("Provisioning.MonitorHostName", False)


def get_monitor_hostname_period(conf=__conf__):
    return conf.get_int("Provisioning.MonitorHostNamePeriod", 30)


def get_httpproxy_host(conf=__conf__):
    return conf.get("HttpProxy.Host", None)


def get_httpproxy_port(conf=__conf__):
    return conf.get_int("HttpProxy.Port", None)


def get_detect_scvmm_env(conf=__conf__):
    return conf.get_switch("DetectScvmmEnv", False)


def get_resourcedisk_format(conf=__conf__):
    return conf.get_switch("ResourceDisk.Format", False)


def get_resourcedisk_enable_swap(conf=__conf__):
    return conf.get_switch("ResourceDisk.EnableSwap", False)


def get_resourcedisk_enable_swap_encryption(conf=__conf__):
    return conf.get_switch("ResourceDisk.EnableSwapEncryption", False)


def get_resourcedisk_mountpoint(conf=__conf__):
    return conf.get("ResourceDisk.MountPoint", "/mnt/resource")


def get_resourcedisk_mountoptions(conf=__conf__):
    return conf.get("ResourceDisk.MountOptions", None)


def get_resourcedisk_filesystem(conf=__conf__):
    return conf.get("ResourceDisk.Filesystem", "ext3")


def get_resourcedisk_swap_size_mb(conf=__conf__):
    return conf.get_int("ResourceDisk.SwapSizeMB", 0)


def get_autoupdate_gafamily(conf=__conf__):
    return conf.get("AutoUpdate.GAFamily", "Prod")


def get_autoupdate_enabled(conf=__conf__):
    return conf.get_switch("AutoUpdate.Enabled", True)


def get_autoupdate_frequency(conf=__conf__):
    return conf.get_int("Autoupdate.Frequency", 3600)


def get_enable_overprovisioning(conf=__conf__):
    return conf.get_switch("EnableOverProvisioning", True)


def get_allow_http(conf=__conf__):
    return conf.get_switch("OS.AllowHTTP", False)


def get_disable_agent_file_path(conf=__conf__):
    return os.path.join(get_lib_dir(conf), DISABLE_AGENT_FILE)


def get_cgroups_enforce_limits(conf=__conf__):
    return conf.get_switch("CGroups.EnforceLimits", False)


def get_cgroups_excluded(conf=__conf__):
    excluded_value = conf.get("CGroups.Excluded", "customscript, runcommand")
    return [s for s in [i.strip().lower() for i in excluded_value.split(',')] if len(s) > 0] if excluded_value else [] # pylint: disable=len-as-condition
