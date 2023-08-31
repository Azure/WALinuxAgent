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
"""  # pylint: disable=W0105
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

    @staticmethod
    def _get_default(default):
        if hasattr(default, '__call__'):
            return default()
        return default

    def get(self, key, default_value):
        """
        Retrieves a string parameter by key and returns its value. If not found returns the default value,
        or if the default value is a callable returns the result of invoking the callable.
        """
        val = self.values.get(key)
        return val if val is not None else self._get_default(default_value)

    def get_switch(self, key, default_value):
        """
        Retrieves a switch parameter by key and returns its value as a boolean. If not found returns the default value,
        or if the default value is a callable returns the result of invoking the callable.
        """
        val = self.values.get(key)
        if val is not None and val.lower() == 'y':
            return True
        elif val is not None and val.lower() == 'n':
            return False
        return self._get_default(default_value)

    def get_int(self, key, default_value):
        """
        Retrieves an int parameter by key and returns its value. If not found returns the default value,
        or if the default value is a callable returns the result of invoking the callable.
        """
        try:
            return int(self.values.get(key))
        except TypeError:
            return self._get_default(default_value)
        except ValueError:
            return self._get_default(default_value)


__conf__ = ConfigurationProvider()


def load_conf_from_file(conf_file_path, conf=__conf__):
    """
    Load conf file from: conf_file_path
    """
    if os.path.isfile(conf_file_path) == False:
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
    "Logs.Collect": True,
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
    #
    # "Debug" options are experimental and may be removed in later
    # versions of the Agent.
    #
    "Debug.CgroupLogMetrics": False,
    "Debug.CgroupDisableOnProcessCheckFailure": True,
    "Debug.CgroupDisableOnQuotaCheckFailure": True,
    "Debug.DownloadNewAgents": True,
    "Debug.EnableAgentMemoryUsageCheck": False,
    "Debug.EnableFastTrack": True,
    "Debug.EnableGAVersioning": True
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
    "Debug.CgroupMonitorExpiryTime": "2022-03-31",
    "Debug.CgroupMonitorExtensionName": "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent",
}


__INTEGER_OPTIONS__ = {
    "Extensions.GoalStatePeriod": 6,
    "Extensions.InitialGoalStatePeriod": 6,
    "OS.EnableFirewallPeriod": 300,
    "OS.RemovePersistentNetRulesPeriod": 30,
    "OS.RootDeviceScsiTimeoutPeriod": 30,
    "OS.MonitorDhcpClientRestartPeriod": 30,
    "OS.SshClientAliveInterval": 180,
    "Provisioning.MonitorHostNamePeriod": 30,
    "Provisioning.PasswordCryptSaltLength": 10,
    "HttpProxy.Port": None,
    "ResourceDisk.SwapSizeMB": 0,
    "Autoupdate.Frequency": 3600,
    "Logs.CollectPeriod": 3600,
    #
    # "Debug" options are experimental and may be removed in later
    # versions of the Agent.
    #
    "Debug.CgroupCheckPeriod": 300,
    "Debug.AgentCpuQuota": 50,
    "Debug.AgentCpuThrottledTimeThreshold": 120,
    "Debug.AgentMemoryQuota": 30 * 1024 ** 2,
    "Debug.EtpCollectionPeriod": 300,
    "Debug.AutoUpdateHotfixFrequency": 14400,
    "Debug.AutoUpdateNormalFrequency": 86400,
    "Debug.FirewallRulesLogPeriod": 86400
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
    return conf.get_int("OS.EnableFirewallPeriod", 300)


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
    return conf.get_switch("Logs.Collect", True)


def get_collect_logs_period(conf=__conf__):
    return conf.get_int("Logs.CollectPeriod", 3600)


def get_lib_dir(conf=__conf__):
    return conf.get("Lib.Dir", "/var/lib/waagent")


def get_published_hostname(conf=__conf__):
    # Some applications rely on this file; do not remove this setting
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


def get_initial_goal_state_period(conf=__conf__):
    return conf.get_int("Extensions.InitialGoalStatePeriod", default_value=lambda: get_goal_state_period(conf=conf))


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


def get_cgroups_enabled(conf=__conf__):
    return conf.get_switch("CGroups.Enabled", True)


def get_monitor_network_configuration_changes(conf=__conf__):
    return conf.get_switch("Monitor.NetworkConfigurationChanges", False)


def get_download_new_agents(conf=__conf__):
    """
    If True, the agent go through update logic to look for new agents to download otherwise it will stop agent updates.
    NOTE: AutoUpdate.Enabled controls whether the Agent downloads new update and also whether any downloaded updates are started or not, while DownloadNewAgents controls only the former.
    AutoUpdate.Enabled == false -> Agent preinstalled on the image will process extensions and will not update (regardless of DownloadNewAgents flag)
    AutoUpdate.Enabled == true and DownloadNewAgents == true, any update already downloaded will be started, and agent look for future updates
    AutoUpdate.Enabled == true and DownloadNewAgents == false, any update already downloaded will be started, but the agent will not look for future updates
    """
    return conf.get_switch("Debug.DownloadNewAgents", True)


def get_cgroup_check_period(conf=__conf__):
    """
    How often to perform checks on cgroups (are the processes in the cgroups as expected,
    has the agent exceeded its quota, etc)

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_int("Debug.CgroupCheckPeriod", 300)


def get_cgroup_log_metrics(conf=__conf__):
    """
    If True, resource usage metrics are written to the local log

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_switch("Debug.CgroupLogMetrics", False)


def get_cgroup_disable_on_process_check_failure(conf=__conf__):
    """
    If True, cgroups will be disabled if the process check fails

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_switch("Debug.CgroupDisableOnProcessCheckFailure", True)


def get_cgroup_disable_on_quota_check_failure(conf=__conf__):
    """
    If True, cgroups will be disabled if the CPU quota check fails

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_switch("Debug.CgroupDisableOnQuotaCheckFailure", True)


def get_agent_cpu_quota(conf=__conf__):
    """
    CPU quota for the agent as a percentage of 1 CPU (100% == 1 CPU)

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_int("Debug.AgentCpuQuota", 50)


def get_agent_cpu_throttled_time_threshold(conf=__conf__):
    """
    Throttled time threshold for agent cpu in seconds.

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_int("Debug.AgentCpuThrottledTimeThreshold", 120)


def get_agent_memory_quota(conf=__conf__):
    """
    Memory quota for the agent in bytes.

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_int("Debug.AgentMemoryQuota", 30 * 1024 ** 2)


def get_enable_agent_memory_usage_check(conf=__conf__):
    """
    If True, Agent checks it's Memory usage.

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_switch("Debug.EnableAgentMemoryUsageCheck", False)


def get_cgroup_monitor_expiry_time(conf=__conf__):
    """
    cgroups monitoring for pilot extensions disabled after expiry time

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get("Debug.CgroupMonitorExpiryTime", "2022-03-31")


def get_cgroup_monitor_extension_name (conf=__conf__):
    """
    cgroups monitoring extension name

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get("Debug.CgroupMonitorExtensionName", "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent")


def get_enable_fast_track(conf=__conf__):
    """
    If True, the agent use FastTrack when retrieving goal states

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_switch("Debug.EnableFastTrack", True)


def get_etp_collection_period(conf=__conf__):
    """
    Determines the frequency to perform ETP collection on extensions telemetry events.
    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_int("Debug.EtpCollectionPeriod", 300)


def get_hotfix_upgrade_frequency(conf=__conf__):
    """
    Determines the frequency to check for Hotfix upgrades (<Patch>.<Build> version changed in new upgrades).
    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_int("Debug.AutoUpdateHotfixFrequency", 4 * 60 * 60)


def get_normal_upgrade_frequency(conf=__conf__):
    """
    Determines the frequency to check for Normal upgrades (<Major>.<Minor> version changed in new upgrades).
    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_int("Debug.AutoUpdateNormalFrequency", 24 * 60 * 60)


def get_enable_ga_versioning(conf=__conf__):
    """
    If True, the agent looks for rsm updates(checking requested version in GS) otherwise it will fall back to self-update and finds the highest version from PIR.
    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_switch("Debug.EnableGAVersioning", False)


def get_firewall_rules_log_period(conf=__conf__):
    """
    Determine the frequency to perform the periodic operation of logging firewall rules.

    NOTE: This option is experimental and may be removed in later versions of the Agent.
    """
    return conf.get_int("Debug.FirewallRulesLogPeriod", 86400)
