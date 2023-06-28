import logging
import os
import re
import subprocess
import sys

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION
from tests_e2e.tests.lib.agent_log import AgentLog

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
    logging.info("===== Checking if distro supports cgroups =====")

    base_fs_exists = os.path.exists(BASE_CGROUP)

    if not base_fs_exists:
        logging.warning("\tDistro %s-%s does not support cgroups -- exiting", DISTRO_NAME, DISTRO_VERSION)
        sys.exit(1)
    else:
        logging.info('\tDistro %s-%s supports cgroups\n', DISTRO_NAME, DISTRO_VERSION)


def run_get_output(cmd, print_std_out=False):
    # Returns a list of stdout lines without \n at the end of the line.
    output = subprocess.check_output(cmd,
                                     stderr=subprocess.STDOUT,
                                     shell=True)
    output = ustr(output,
                  encoding='utf-8',
                  errors="backslashreplace")

    if print_std_out:
        logging.info(output)

    return output.split("\n")


def print_cgroups():
    logging.info("====== Currently mounted cgroups ======")
    for m in run_get_output('mount'):
        if 'type cgroup' in m:
            logging.info('\t%s', m)
    logging.info("")


def print_processes():
    logging.info("====== Currently running processes ======")
    processes = run_get_output("ps aux --forest")
    for process in processes:
        logging.info("\t%s", process)
    logging.info("")


def print_service_status(service_status):
    # Make sure to replace non-ascii characters since DCR logs anything that goes to stdout and will fail if
    # there are non-ascii characters such as the ones showing up in `systemctl status {service_name}`.
    for line in service_status:
        logging.info("\t%s", line)
    logging.info("")


def get_agent_cgroup_mount_path():
    return os.path.join('/', 'azure.slice', AGENT_SERVICE_NAME)


def get_extension_cgroup_mount_path(extension_name):
    return os.path.join('/', 'azure.slice/azure-vmextensions.slice',
                        "azure-vmextensions-" + extension_name + ".slice")


def get_unit_cgroup_mount_path(unit_name):
    output = run_get_output("systemctl show " + unit_name + " --property ControlGroup")
    # Output is similar to
    #   systemctl show walinuxagent.service --property ControlGroup
    #   ControlGroup=/azure.slice/walinuxagent.service
    #  matches above output and extract right side value
    match = re.match("[^=]+=(?P<value>.+)", output[0].strip())
    if match is not None:
        return match.group('value')
    return None


def verify_agent_cgroup_assigned_correctly_systemd(service_status):
    print_service_status(service_status)

    is_active = False
    is_cgorup_assigned = False
    cgroup_month_path = get_agent_cgroup_mount_path()
    is_active_pattern = re.compile(r".*Active:\s+active.*")

    for line in service_status:
        if re.match(is_active_pattern, line):
            is_active = True
        elif cgroup_month_path in line:
            is_cgorup_assigned = True

    if not is_active or not is_cgorup_assigned:
        raise Exception('walinuxagent service was not active/running or not assigned to the expected cgroup!')

    logging.info("\tVerified the agent cgroup assigned correctly by systemd\n")


def verify_agent_cgroup_assigned_correctly():
    logging.info("===== Verifying the daemon and the agent are assigned to the same correct cgroup using systemd =====")
    output = run_get_output("systemctl status " + systemd.get_agent_unit_name())
    verify_agent_cgroup_assigned_correctly_systemd(output)


def get_cpu_quota():
    output = run_get_output("systemctl show " + AGENT_SERVICE_NAME + " --property CPUQuotaPerSecUSec")
    match = re.match("[^=]+=(?P<value>.+)", output[0].strip())
    if match is not None:
        return match.group('value')
    return None


def check_quota_disabled():
    cpu_quota = get_cpu_quota()
    return cpu_quota == 'infinity'


def check_cgroup_disabled_with_unknown_process():
    for record in AgentLog().read():
        match = re.search("Disabling resource usage monitoring. Reason: Check on cgroups failed:.+UNKNOWN",
                          record.message, flags=re.DOTALL)
        if match is not None:
            logging.info("Found message:\n\t%s", record.text.replace("\n", "\n\t"))
            return True
    return False
