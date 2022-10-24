import os
import re
import subprocess
import sys

from dcr.scenario_utils.distro import get_distro

BASE_CGROUP = '/sys/fs/cgroup'
AGENT_CGROUP_NAME = 'WALinuxAgent'
AGENT_SERVICE_NAME = "walinuxagent.service"
CONTROLLERS = ['cpu']  # Only verify the CPU controller since memory accounting is not enabled yet.

DAEMON_CMDLINE_PATTERN = re.compile(r".*python.*waagent.*-daemon")
AGENT_CMDLINE_PATTERN = re.compile(r".*python.*-run-exthandlers")

CREATED_CGROUP_PATTERN = r"..*Created cgroup (/sys/fs/cgroup/.+)"
EXTENSION_PID_ADDED_PATTERN = re.compile(r".*Added PID (\d+) to cgroup[s]* (/sys/fs/cgroup/.+)")
CGROUP_TRACKED_PATTERN = re.compile(r'Started tracking cgroup ([^\s]+)\s+\[(?P<path>[^\s]+)\]')

#
# It is OK for these processes to show up in the Agent's cgroup
#
WHITELISTED_AGENT_REGEXES = [
    #
    # The monitor thread uses these periodically:
    #
    re.compile(r"/sbin/dhclient\s.+/run/dhclient.*/var/lib/dhcp/dhclient.*/var/lib/dhcp/dhclient.*"),
    re.compile(r".*iptables --version.*"),
    re.compile(r".*iptables (-w)? -t security.*"),
    #
    # The agent starts extensions using systemd-run; the actual extension command will be on a different process.
    #
    re.compile(r".*systemd-run --unit=Microsoft.Azure.Diagnostics.LinuxDiagnostic_3.* "
               r"--scope --slice=azure-vmextensions.slice /var/lib/waagent/Microsoft.Azure.Diagnostics.LinuxDiagnostic-3.*/diagnostic.py "
               r"-enable.*"),
    #
    # The agent can start a new shell process.
    #
    re.compile(r"^\[sh\]$")
]


def exit_if_cgroups_not_supported():
    print("===== Checking if distro supports cgroups =====")

    __distro__ = get_distro()
    base_fs_exists = os.path.exists(BASE_CGROUP)

    if not base_fs_exists:
        print("\tDistro {0} does not support cgroups -- exiting".format(__distro__))
        sys.exit(1)
    else:
        print('\tDistro {0} supports cgroups\n'.format(__distro__))


def run_get_output(cmd, print_std_out=False):
    # Returns a list of stdout lines without \n at the end of the line.
    output = subprocess.check_output(cmd,
                                     stderr=subprocess.STDOUT,
                                     shell=True)
    output = str(output,
                  encoding='utf-8',
                  errors="backslashreplace")

    if print_std_out:
        print(output)

    return output.split("\n")


def is_systemd_distro():
    try:
        return run_get_output('cat /proc/1/comm')[0].strip() == 'systemd'
    except Exception:
        return False


def print_cgroups():
    print("====== Currently mounted cgroups ======")
    for m in run_get_output('mount'):
        if 'type cgroup' in m:
            print('\t{0}'.format(m))
    print("")


def print_processes():
    print("====== Currently running processes ======")
    processes = run_get_output("ps aux --forest")
    for process in processes:
        print("\t{0}".format(process))
    print("")


def print_service_status(service_status):
    # Make sure to replace non-ascii characters since DCR logs anything that goes to stdout and will fail if
    # there are non-ascii characters such as the ones showing up in `systemctl status {service_name}`.
    for line in service_status:
        print("\t" + line.encode("ascii", "replace").decode().replace("\n", ""))
    print("")


def get_parent_pid(pid):
    try:
        with open("/proc/{0}/stat".format(pid), "r") as fh:
            raw = fh.readline()
            ppid = raw.split(" ")[3]
            return ppid
    except Exception:
        return None


def get_pid_by_cmdline(pattern):
    agent_pid = -1

    for dirname in os.listdir('/proc'):
        if dirname == 'curproc':
            continue

        try:
            with open('/proc/{0}/cmdline'.format(dirname), mode='r') as fd:
                ps_cmd = fd.read()
                if re.match(pattern, ps_cmd):
                    agent_pid = dirname
                    break
        except Exception:
            pass

    return agent_pid


def get_cmdline_by_pid(pid):
    try:
        with open('/proc/{0}/cmdline'.format(pid), mode='r') as process_fd:
            return process_fd.read()
    except Exception:
        return None


def get_process_cgroups(pid):
    with open('/proc/{0}/cgroup'.format(pid), mode='r') as fd:
        return fd.read().split('\n')[:-1]


def get_agent_cgroup_mount_path():
    # TODO: change the service name based on distro (SUSE is waagent, for example)
    if is_systemd_distro():
        return os.path.join('/', 'azure.slice', AGENT_SERVICE_NAME)
    else:
        return os.path.join('/', AGENT_SERVICE_NAME)


def check_cgroup_for_agent_process(name, pid):
    process_cgroups = get_process_cgroups(pid)
    expected_cgroup_path = get_agent_cgroup_mount_path()

    print('\tretrieved cgroups for {0}:'.format(name))
    for cgroup in process_cgroups:
        print("\t\t{0}".format(cgroup))
    print("")

    for controller in CONTROLLERS:
        for cgroup in process_cgroups:
            # This is what the lines in /proc/PID/cgroup look like:
            # 4:memory:/system.slice/walinuxagent.service
            # 7:memory:/WALinuxAgent/Microsoft.EnterpriseCloud.Monitoring.OmsAgentForLinux
            # We are interested in extracting the controller and mount path
            mounted_controller = cgroup.split(':')[1].split(',')
            mounted_path = cgroup.split(':')[2]
            if controller in mounted_controller:
                if mounted_path != expected_cgroup_path:
                    raise Exception("Expected {0} cgroup to be mounted under {1}, "
                                    "but it's mounted under {2}".format(name, expected_cgroup_path, mounted_path))

    print("\t{0}'s PID is {1}, cgroup mount path is {2}".format(name, pid, expected_cgroup_path))
    print("\tverified {0}'s /proc/cgroup is expected!\n".format(name))


def check_pids_in_agent_cgroup(agent_cgroup_procs, daemon_pid, agent_pid):
    with open(agent_cgroup_procs, "r") as agent_fd:
        content = agent_fd.read()
        print("\tcontent of {0}:\n{1}".format(agent_cgroup_procs, content))

        pids = content.split('\n')[:-1]

        if daemon_pid not in pids:
            raise Exception("Daemon PID {0} not found in expected cgroup {1}!".format(daemon_pid, agent_cgroup_procs))

        if agent_pid not in pids:
            raise Exception("Agent PID {0} not found in expected cgroup {1}!".format(agent_pid, agent_cgroup_procs))

        for pid in pids:
            if pid == daemon_pid or pid == agent_pid:
                continue
            else:
                # There is an unexpected PID in the cgroup, check what process it is
                cmd = get_cmdline_by_pid(pid)
                ppid = get_parent_pid(pid)
                whitelisted = is_whitelisted(cmd)

                # If the process is whitelisted and a child of the agent, allow it. The process could have terminated
                # in the meantime, but we allow it if it's whitelisted.
                if whitelisted and (ppid is None or ppid == agent_pid or ppid == daemon_pid):
                    print("\tFound whitelisted process in agent cgroup:\n\t{0} {1}\n"
                          "\tparent process {2}".format(pid, cmd, ppid))
                    continue

                raise Exception("Found unexpected process in the agent cgroup:\n\t{0} {1}\n"
                                "\tparent process {2}".format(pid, cmd, ppid))

    return True


def is_whitelisted(cmd):
    matches = [re.match(r, cmd) is not None for r in WHITELISTED_AGENT_REGEXES]
    return any(matches)


def parse_processes_from_systemctl_status(service_status):
    processes_start_pattern = re.compile(r".*CGroup:\s+.*")
    processes_end_pattern = re.compile(r"^$")

    processes_start_index = -1
    processes_end_index = -1

    for line in service_status:
        if re.match(processes_start_pattern, line):
            processes_start_index = service_status.index(line)
        if re.match(processes_end_pattern, line):
            processes_end_index = service_status.index(line)
            break

    processes_raw = service_status[processes_start_index+1:processes_end_index]

    # Remove non-ascii characters and extra whitespace
    cleaned = list(map(lambda x: ''.join([i if ord(i) < 128 else '' for i in x]).strip(), processes_raw))

    # Return a list of tuples [(PID1, cmdline1), (PID2, cmdline2)]
    processes = list(map(lambda x: (x.split(" ")[0], ' '.join(x.split(" ")[1:])), cleaned))

    return processes


def verify_agent_cgroup_assigned_correctly_systemd(service_status):
    print_service_status(service_status)

    is_active = False
    is_active_pattern = re.compile(r".*Active:\s+active.*")

    for line in service_status:
        if re.match(is_active_pattern, line):
            is_active = True

    if not is_active:
        raise Exception('walinuxagent service was not active')

    print("\tVerified the agent service status is correct!\n")


def verify_agent_cgroup_assigned_correctly_filesystem():
    print("===== Verifying the daemon and the agent are assigned to the same correct cgroup using filesystem =====")

    # Find out daemon and agent PIDs by looking at currently running processes
    daemon_pid = get_pid_by_cmdline(DAEMON_CMDLINE_PATTERN)
    agent_pid = get_pid_by_cmdline(AGENT_CMDLINE_PATTERN)

    if daemon_pid == -1:
        raise Exception('daemon PID not found!')

    if agent_pid == -1:
        raise Exception('agent PID not found!')

    # Ensure both the daemon and the agent are assigned to the (same) expected cgroup
    check_cgroup_for_agent_process("daemon", daemon_pid)
    check_cgroup_for_agent_process("agent", agent_pid)

    # Ensure the daemon/agent cgroup doesn't have any other processes there
    for controller in CONTROLLERS:
        # Mount path is /system.slice/walinuxagent.service or
        # /WALinuxAgent/WALinuxAgent, so remove the first "/" to correctly build path
        agent_cgroup_mount_path = get_agent_cgroup_mount_path()[1:]
        agent_cgroup_path = os.path.join(BASE_CGROUP, controller, agent_cgroup_mount_path)
        agent_cgroup_procs = os.path.join(agent_cgroup_path, 'cgroup.procs')

        # Check if the processes in the agent cgroup are expected. We expect to see the daemon and extension handler
        # processes. Sometimes, we might observe more than one extension handler process. This is short-lived and
        # happens because, in Linux, the process doubles before forking. Therefore, check twice with a bit of delay
        # in between to see if it goes away. Still raise an exception if this happens so we can keep track of it.
        check_pids_in_agent_cgroup(agent_cgroup_procs, daemon_pid, agent_pid)

        print('\tVerified the daemon and agent are assigned to the same correct cgroup {0}'.format(agent_cgroup_path))
        print("")


def verify_agent_cgroup_assigned_correctly():
    if is_systemd_distro():
        print("===== Verifying the daemon and the agent are assigned to the same correct cgroup using systemd =====")
        output = run_get_output("systemctl status walinuxagent")
        verify_agent_cgroup_assigned_correctly_systemd(output)
    else:
        verify_agent_cgroup_assigned_correctly_filesystem()

