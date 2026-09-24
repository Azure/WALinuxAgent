import os
import re

from assertpy import assert_that, fail

from azurelinuxagent.common.future import datetime_min_utc
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.utils import shellutil, fileutil
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION
from azurelinuxagent.ga.cgroupapi import create_cgroup_api, SystemdCgroupApiv1, SystemdCgroupApiv2
from azurelinuxagent.ga.cpucontroller import CpuControllerV1, CpuControllerV2
from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false

BASE_CGROUP = '/sys/fs/cgroup'
AGENT_CGROUP_NAME = 'WALinuxAgent'
AGENT_SERVICE_NAME = systemd.get_agent_unit_name()
CGROUP_TRACKED_PATTERN = r'Started tracking (cpu|memory) cgroup ([^\s]+)\s+\[(?P<path>[^\s]+)\]'

GATESTEXT_FULL_NAME = "Microsoft.Azure.Extensions.Edp.GATestExtGo"
GATESTEXT_SERVICE = "gatestext"
AZUREMONITOREXT_FULL_NAME = "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent"
AZUREMONITORAGENT_SERVICE = "azuremonitoragent"

def verify_if_distro_supports_cgroup():
    """
    checks if agent is running in a distro that supports cgroups
    """
    log.info("===== Checking if distro supports cgroups")

    base_cgroup_fs_exists = os.path.exists(BASE_CGROUP)

    assert_that(base_cgroup_fs_exists).is_true().described_as("Cgroup file system:{0} not found in Distro {1}-{2}".format(BASE_CGROUP, DISTRO_NAME, DISTRO_VERSION))

    log.info('Distro %s-%s supports cgroups\n', DISTRO_NAME, DISTRO_VERSION)


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
    return [os.path.join('/', 'azure.slice', AGENT_SERVICE_NAME), os.path.join("/", "system.slice", AGENT_SERVICE_NAME)]


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
    log.info("===== Verifying the daemon and the agent are assigned to the same correct cgroup using systemd")
    cgroup_mount_path = get_agent_cgroup_mount_path()
    service_status = ""

    def check_agent_service_cgroup():
        is_active = False
        is_cgroup_assigned = False
        service_status = shellutil.run_command(["systemctl", "status", systemd.get_agent_unit_name()])
        log.info("Agent service status output:\n%s", service_status)
        is_active_pattern = re.compile(r".*Active:\s+active.*")

        for line in service_status.splitlines():
            if re.match(is_active_pattern, line):
                is_active = True
            if any(cgroup in line for cgroup in cgroup_mount_path):
                is_cgroup_assigned = True

        return is_active and is_cgroup_assigned

    # Test check can happen before correct cgroup assigned and relfected in service status. So, retrying the check for few times
    if not retry_if_false(check_agent_service_cgroup):
        fail('walinuxagent service was not assigned to the expected cgroup:{0}. Current agent status:{1}'.format(cgroup_mount_path, service_status))

    log.info("Successfully verified the agent cgroup assigned correctly by systemd\n")


def get_agent_memory_quota():
    """
    Returns the memory quota for the agent service
    """
    output = shellutil.run_command(["systemctl", "show", AGENT_SERVICE_NAME, "--property", "MemoryHigh"])
    # Output is similar to
    #   systemctl show walinuxagent --property MemoryLimit
    #   MemoryLimit=1073741824
    match = re.match("[^=]+=(?P<value>.+)", output)
    if match is not None:
        return match.group('value')
    return None


def get_agent_cpu_quota():
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


def check_agent_quota_disabled():
    """
    Returns True if the cpu quota is infinity
    """
    cpu_quota = get_agent_cpu_quota()
    log.info(cpu_quota)
    # the quota can be expressed as seconds (s) or milliseconds (ms); no quota is expressed as "infinity"
    # Ubuntu 16 has an issue in expressing no quota as "infinity" https://github.com/systemd/systemd/issues/5965, so we are directly checking the quota value in cpu controller
    return cpu_quota == 'infinity' or get_unit_cgroup_cpu_quota_disabled(AGENT_SERVICE_NAME)

def check_cgroup_disabled_due_to_systemd_error():
    """
    Returns True if the cgroup is disabled due to systemd error (Connection reset by peer)

    Ex:
    2024-12-18T06:43:23.867711Z INFO ExtHandler ExtHandler [CGW] Disabling resource usage monitoring. Reason: Failed to start Microsoft.Azure.Extensions.Edp.GATestExtGo-1.2.0.0 using systemd-run, will try invoking the extension directly. Error: [SystemdRunError] Systemd process exited with code 1 and output [stdout]

    [stderr]
    Warning! D-Bus connection terminated.
    Failed to start transient scope unit: Connection reset by peer
    """
    return check_log_message("Failed to start.+using systemd-run, will try invoking the extension directly.+[SystemdRunError].+(Message recipient disconnected from message bus without replying|Connection reset by peer|Remote peer disconnected|Transport endpoint is not connected)")

def check_log_message(message, after_timestamp=datetime_min_utc):
    """
    Check if the log message is present after the given timestamp(if provided) in the agent log
    """
    log.info("Checking log message: {0}".format(message))
    for record in AgentLog().read():
        match = re.search(message, record.message, flags=re.DOTALL)
        if match is not None and record.timestamp > after_timestamp:
            log.info("Found message:\n\t%s", record.text.replace("\n", "\n\t"))
            return True
    return False


def get_unit_cgroup_proc_path(unit_name, controller):
    """
    Returns the cgroup.procs path for the given unit and controller.
    """
    cgroups_api = create_cgroup_api()
    unit_cgroup = cgroups_api.get_unit_cgroup(unit_name=unit_name, cgroup_name="test cgroup")
    if isinstance(cgroups_api, SystemdCgroupApiv1):
        return unit_cgroup.get_controller_procs_path(controller=controller)
    else:
        return unit_cgroup.get_procs_path()

def get_unit_cgroup_cpu_quota_disabled(unit_name):
    """
    Returns True if cpu quota not set for the given unit cgroup
    """
    cgroups_api = create_cgroup_api()
    unit_cgroup = cgroups_api.get_unit_cgroup(unit_name=unit_name, cgroup_name="test cgroup")
    controllers = unit_cgroup.get_controllers()
    for controller in controllers:
        if isinstance(controller, CpuControllerV1):
            path = os.path.join(controller.path, "cpu.cfs_quota_us")
            log.info("Checking cpu.cfs_quota_us file: {0}".format(path))
            val = fileutil.read_file(path).strip()
            return val == "-1" # -1 means no quota
        elif isinstance(controller, CpuControllerV2):
            # /sys/fs/cgroup/system.slice/cron.service$ cat cpu.max
            # max 100000
            path = os.path.join(controller.path, "cpu.max")
            log.info("Checking cpu.cfs_quota_us file: {0}".format(path))
            val = fileutil.read_file(path).split()[0]
            return val == "max" # max means no quota
    return False

def get_mounted_controller_list():
    """
    Returns list of controller names which are mounted in different cgroup paths
    """
    if using_cgroupv2():
        return [] # empty since v2 controllers are mounted at same root
    return ['cpu', 'memory']

def using_cgroupv2():
    """
    Returns True if systemd v2 is used
    """
    cgroups_api = create_cgroup_api()
    return isinstance(cgroups_api, SystemdCgroupApiv2)
