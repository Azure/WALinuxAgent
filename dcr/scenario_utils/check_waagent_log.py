import re

from dcr.scenario_utils.agent_log_parser import AGENT_LOG_FILE, parse_agent_log_file
from dcr.scenario_utils.cgroups_helpers import is_systemd_distro
from dcr.scenario_utils.distro import get_distro


def check_waagent_log_for_errors(waagent_log=AGENT_LOG_FILE, ignore=None):
    # Returns any ERROR messages from the log except transient ones.
    # Currently, the only transient one is /proc/net/route not being set up if it's being reported before
    # provisioning was completed. In that case, we ignore that error message.

    no_routes_error = None
    provisioning_complete = False

    distro = "".join(get_distro())
    systemd_enabled = is_systemd_distro()

    error_tags = ['ERROR', 'Exception', 'Traceback', 'WARNING', '[CGW]']

    #
    # NOTES:
    #     * 'message' is matched using re.search; be sure to escape any regex metacharacters
    #     * 'if' receives as parameter an AgentLogRecord
    #
    ignore_list = [
        # This is a known issue (https://github.com/Azure/WALinuxAgent/pull/2016)
        # Please remove this message from ignored once this task is completed
        # - https://msazure.visualstudio.com/One/_workitems/edit/8733946
        {
            'message': r"need a bytes-like object, NoneType found"
        },
        # This warning is expected on CentOS/RedHat 7.8 and Redhat 7.6
        {
            'message': r"Move rules file 70-persistent-net.rules to /var/lib/waagent/70-persistent-net.rules",
            'if': lambda log_line: re.match(r"((centos7\.8)|(redhat7\.8)|(redhat7\.6)|(redhat8\.2))\D*", distro,
                                            flags=re.IGNORECASE) is not None and log_line.level == "WARNING" and
                                   log_line.who == "ExtHandler" and log_line.thread in ("", "EnvHandler")
        },
        # This warning is expected on SUSE 12
        {
            'message': r"WARNING EnvHandler ExtHandler Move rules file 75-persistent-net-generator.rules to /var/lib/waagent/75-persistent-net-generator.rules",
            'if': lambda _: re.match(r"((sles15\.2)|suse12)\D*", distro, flags=re.IGNORECASE) is not None
        },
        # This warning is expected on when WireServer gives us the incomplete goalstate without roleinstance data
        # raise IncompleteGoalStateError("Fetched goal state without a RoleInstance [incarnation {inc}]".format(inc=self.incarnation))
        {
            'message': r"\[IncompleteGoalStateError\] Fetched goal state without a RoleInstance",
        },
        # The following message is expected to log an error if systemd is not enabled on it
        {
            'message': r"Did not detect Systemd, unable to set wa(|linux)agent-network-setup.service",
            'if': lambda _: not systemd_enabled
        },
        # ResourceGone can happen if we are fetching one of the URIs in the goal state and a new goal state arrives
        {
            'message': r"Fetching the goal state failed: \[ResourceGoneError\] \[HTTP Failed\] \[410: Gone\] (|b')The page you requested was removed\.(|')",
            'if': lambda log_line: log_line.level == "WARNING"
        },
        # Download warnings (manifest and zips).
        #
        # Examples:
        #     2021-03-31T03:48:35.216494Z WARNING ExtHandler ExtHandler Fetch failed: [HttpError] [HTTP Failed] GET https://zrdfepirv2cbn04prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqA_useast2euap_manifest.xml -- IOError ('The read operation timed out',) -- 1 attempts made
        #     2021-03-31T06:54:29.655861Z WARNING ExtHandler ExtHandler Fetch failed: [HttpError] [HTTP Retry] GET http://168.63.129.16:32526/extensionArtifact -- Status Code 502 -- 1 attempts made
        #     2021-03-31T06:43:17.806663Z WARNING ExtHandler ExtHandler Download failed, switching to host plugin
        {
            'message': r"(Fetch failed: \[HttpError\] .+ GET .+ -- [0-9]+ attempts made)|(Download failed, switching to host plugin)",
            'if': lambda log_line: log_line.level == "WARNING" and log_line.who == "ExtHandler" and log_line.thread == "ExtHandler"
        },
        # Sometimes it takes the Daemon some time to identify primary interface and the route to Wireserver,
        # ignoring those errors if they come from the Daemon.
        {
            'message': r"(No route exists to \d+\.\d+\.\d+\.\d+|"
                       r"Could not determine primary interface, please ensure \/proc\/net\/route is correct|"
                       r"Contents of \/proc\/net\/route:|Primary interface examination will retry silently|"
                       r"\/proc\/net\/route contains no routes)",
            'if': lambda log_line: log_line.who == "Daemon"
        },
        # Journalctl in Debian 8.11 does not have the --utc option by default.
        # Ignoring this error for Deb 8 as its not a blocker and since Deb 8 is old and not widely used
        {
            'message': r"journalctl: unrecognized option '--utc'",
            'if': lambda log_line: re.match(r"(debian8\.11)\D*", distro, flags=re.IGNORECASE) is not None and log_line.level == "WARNING"
        },
        # 2021-07-09T01:46:53.307959Z INFO MonitorHandler ExtHandler [CGW] Disabling resource usage monitoring. Reason: Check on cgroups failed:
        # [CGroupsException] The agent's cgroup includes unexpected processes: ['[PID: 2367] UNKNOWN']
        {
            'message': r"The agent's cgroup includes unexpected processes: \[('\[PID:\s?\d+\]\s*UNKNOWN'(,\s*)?)+\]"
        },
        # Probably the agent should log this as INFO, but for now it is a warning
        # e.g.
        # 2021-07-29T04:40:17.190879Z WARNING EnvHandler ExtHandler Dhcp client is not running.
        {
            'message': r"WARNING EnvHandler ExtHandler Dhcp client is not running."
        },
    ]

    if ignore is not None:
        ignore_list.extend(ignore)

    def is_error(log_line):
        return any(err in log_line.text for err in error_tags)

    def can_be_ignored(log_line):
        return any(re.search(msg['message'], log_line.text) is not None and ('if' not in msg or msg['if'](log_line)) for msg in ignore_list)

    errors = []

    for agent_log_line in parse_agent_log_file(waagent_log):
        if is_error(agent_log_line) and not can_be_ignored(agent_log_line):
            # Handle "/proc/net/route contains no routes" as a special case since it can take time for the
            # primary interface to come up and we don't want to report transient errors as actual errors
            if "/proc/net/route contains no routes" in agent_log_line.text:
                no_routes_error = agent_log_line.text
                provisioning_complete = False
            else:
                errors.append(agent_log_line.text)

        if "Provisioning complete" in agent_log_line.text:
            provisioning_complete = True

    # Keep the "no routes found" as a genuine error message if it was never corrected
    if no_routes_error is not None and not provisioning_complete:
        errors.append(no_routes_error)

    if len(errors) > 0:
        # print('waagent.log contains the following ERROR(s):')
        # for item in errors:
        #     print(item.rstrip())
        raise Exception("waagent.log contains the following ERROR(s): {0}".format('\n '.join(errors)))

    print(f"No errors/warnings found in {waagent_log}")


def is_data_in_waagent_log(data):
    """
    This function looks for the specified test data string in the WALinuxAgent logs and returns if found or not.
    :param data: The string to look for in the agent logs
    :raises: Exception if data string not found
    """
    for agent_log_line in parse_agent_log_file():
        if data in agent_log_line.text:
            print("Found data: {0} in line: {1}".format(data, agent_log_line.text))
            return

    raise AssertionError("waagent.log file did not have the data string: {0}".format(data))

