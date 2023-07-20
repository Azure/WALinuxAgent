import os
import re

from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION
from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.logging import log

BASE_CGROUP = '/sys/fs/cgroup'
AGENT_CGROUP_NAME = 'WALinuxAgent'
AGENT_SERVICE_NAME = systemd.get_agent_unit_name()
AGENT_CONTROLLERS = ['cpu', 'memory']
EXT_CONTROLLERS = ['cpu', 'memory']

CGROUP_TRACKED_PATTERN = re.compile(r'Started tracking cgroup ([^\s]+)\s+\[(?P<path>[^\s]+)\]')

GATESTEXT_FULL_NAME = "Microsoft.Azure.Extensions.Edp.GATestExtGo"
GATESTEXT_SERVICE = "gatestext.service"
AZUREMONITOREXT_FULL_NAME = "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent"
AZUREMONITORAGENT_SERVICE = "azuremonitoragent.service"
MDSD_SERVICE = "mdsd.service"


def exit_if_cgroups_not_supported():
    """
    checks if agent is running in a distro that supports cgroups
    """
    log.info("===== Checking if distro supports cgroups =====")

    base_cgroup_fs_exists = os.path.exists(BASE_CGROUP)

    if not base_cgroup_fs_exists:
        raise Exception("\tDistro %s-%s does not support cgroups -- exiting".format(DISTRO_NAME, DISTRO_VERSION))
    else:
        log.info('\tDistro %s-%s supports cgroups\n', DISTRO_NAME, DISTRO_VERSION)


def print_cgroups():
    """
    log the mounted cgroups information
    """
    log.info("====== Currently mounted cgroups ======")
    for m in shellutil.run_command(['mount']).splitlines():
        # output is similar to
        #   mount
        #   sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime,seclabel)
        #   proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
        #   devtmpfs on /dev type devtmpfs (rw,nosuid,seclabel,size=1842988k,nr_inodes=460747,mode=755)
        #   cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd)
        #   cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,pids)
        #   cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,memory)
        #   cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,blkio)
        #   cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,hugetlb)
        if 'type cgroup' in m:
            log.info('\t%s', m)


def print_service_status():
    log.info("====== Agent Service status ======")
    output = shellutil.run_command(["systemctl", "status", systemd.get_agent_unit_name()])
    for line in output.splitlines():
        log.info("\t%s", line)


def get_agent_cgroup_mount_path():
    return os.path.join('/', 'azure.slice', AGENT_SERVICE_NAME)


def get_extension_cgroup_mount_path(extension_name):
    return os.path.join('/', 'azure.slice/azure-vmextensions.slice',
                        "azure-vmextensions-" + extension_name + ".slice")


def get_unit_cgroup_mount_path(unit_name):
    """
    Returns the cgroup mount path for the given unit
    """
    output = shellutil.run_command(["systemctl", "show", unit_name, "--property", "ControlGroup"])
    # Output is similar to
    #   systemctl show walinuxagent.service --property ControlGroup
    #   ControlGroup=/azure.slice/walinuxagent.service
    #  matches above output and extract right side value
    match = re.match("[^=]+=(?P<value>.+)", output)
    if match is not None:
        return match.group('value')
    return None


def verify_agent_cgroup_assigned_correctly():
    """
    This method checks agent is running and assigned to the correct cgroup using service status output
    """
    log.info("===== Verifying the daemon and the agent are assigned to the same correct cgroup using systemd =====")
    service_status = shellutil.run_command(["systemctl", "status", systemd.get_agent_unit_name()])
    log.info("\tAgent service status output:\n%s", service_status)
    is_active = False
    is_cgroup_assigned = False
    cgroup_mount_path = get_agent_cgroup_mount_path()
    is_active_pattern = re.compile(r".*Active:\s+active.*")

    for line in service_status.splitlines():
        if re.match(is_active_pattern, line):
            is_active = True
        elif cgroup_mount_path in line:
            is_cgroup_assigned = True

    if not is_active or not is_cgroup_assigned:
        raise Exception('walinuxagent service was not active/running or not assigned to the expected cgroup:{0}'.format(cgroup_mount_path))

    log.info("\tVerified the agent cgroup assigned correctly by systemd\n")


def get_cpu_quota():
    """
    Returns the cpu quota for the agent service
    """
    output = shellutil.run_command(["systemctl", "show", AGENT_SERVICE_NAME, "--property", "CPUQuotaPerSecUSec"])
    # Output is similar to
    #   systemctl show walinuxagent --property CPUQuotaPerSecUSec
    #   CPUQuotaPerSecUSec=infinity
    match = re.match("[^=]+=(?P<value>.+)", output)
    if match is not None:
        return match.group('value')
    return None


def check_quota_disabled():
    """
    Returns True if the cpu quota is infinity
    """
    cpu_quota = get_cpu_quota()
    return cpu_quota == 'infinity'


def check_cgroup_disabled_with_unknown_process():
    """
    Returns True if the cgroup is disabled with unknown process
    """
    for record in AgentLog().read():
        match = re.search("Disabling resource usage monitoring. Reason: Check on cgroups failed:.+UNKNOWN",
                          record.message, flags=re.DOTALL)
        if match is not None:
            log.info("Found message:\n\t%s", record.text.replace("\n", "\n\t"))
            return True
    return False
