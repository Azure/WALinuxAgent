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

    #
    # NOTES:
    #     * 'message' is matched using re.search; be sure to escape any regex metacharacters
    #     * 'if' receives as parameter an AgentLogRecord
    #
    ignore_list = [
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
        {
            'message': r"\[ProtocolError\] Fetched goal state without a RoleInstance",
        },
        # The following message is expected to log an error if systemd is not enabled on it
        {
            'message': r"Did not detect Systemd, unable to set wa(|linux)agent-network-setup.service",
            'if': lambda _: not systemd_enabled
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
            'if': lambda log_line: re.match(r"(debian8\.11)\D*", distro,
                                            flags=re.IGNORECASE) is not None and log_line.level == "WARNING"
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
        # 2021-12-20T07:46:23.020197Z INFO ExtHandler ExtHandler [CGW] The agent's process is not within a memory cgroup
        {
            'message': r"The agent's process is not within a memory cgroup",
            'if': lambda log_line: re.match(r"((centos7\.8)|(centos7\.9)|(redhat7\.8)|(redhat8\.2))\D*", distro,
                                            flags=re.IGNORECASE)
        },
        #
        # 2022-01-20T06:52:21.515447Z WARNING Daemon Daemon Fetch failed: [HttpError] [HTTP Failed] GET https://dcrgajhx62.blob.core.windows.net/$system/edprpwqbj6.5c2ddb5b-d6c3-4d73-9468-54419ca87a97.vmSettings -- IOError timed out -- 6 attempts made
        #
        # The daemon does not need the artifacts profile blob, but the request is done as part of protocol initialization. This timeout can be ignored, if the issue persist the log would include additional instances.
        #
        {
            'message': r"\[HTTP Failed\] GET https://.*\.vmSettings -- IOError timed out",
            'if': lambda log_line: log_line.level == "WARNING" and log_line.who == "Daemon"
        },
        #
        # 2022-02-09T04:50:37.384810Z ERROR ExtHandler ExtHandler Error fetching the goal state: [ProtocolError] GET vmSettings [correlation ID: 2bed9b62-188e-4668-b1a8-87c35cfa4927 eTag: 7031887032544600793]: [Internal error in HostGAPlugin] [HTTP Failed] [502: Bad Gateway] b'{  "errorCode": "VMArtifactsProfileBlobContentNotFound",  "message": "VM artifacts profile blob has no content in it.",  "details": ""}'
        #
        # Fetching the goal state may catch the HostGAPlugin in the process of computing the vmSettings. This can be ignored, if the issue persist the log would include additional instances.
        #
        {
            'message': r"\[ProtocolError\] GET vmSettings.*VMArtifactsProfileBlobContentNotFound",
            'if': lambda log_line: log_line.level == "ERROR"
        },
        #
        # 2021-12-29T06:50:49.904601Z ERROR ExtHandler ExtHandler Error fetching the goal state: [ProtocolError] Error fetching goal state Inner error: [ResourceGoneError] [HTTP Failed] [410: Gone] The page you requested was removed.
        # 2022-03-21T02:44:03.770017Z ERROR ExtHandler ExtHandler Error fetching the goal state: [ProtocolError] Error fetching goal state Inner error: [ResourceGoneError] Resource is gone
        # 2022-02-16T04:46:50.477315Z WARNING Daemon Daemon Fetching the goal state failed: [ResourceGoneError] [HTTP Failed] [410: Gone] b'<?xml version="1.0" encoding="utf-8"?>\n<Error xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n    <Code>ResourceNotAvailable</Code>\n    <Message>The resource requested is no longer available. Please refresh your cache.</Message>\n    <Details></Details>\n</Error>'
        #
        # ResourceGone can happen if we are fetching one of the URIs in the goal state and a new goal state arrives
        {
            'message': r"(?s)(Fetching the goal state failed|Error fetching goal state|Error fetching the goal state).*(\[ResourceGoneError\]|\[410: Gone\]|Resource is gone)",
            'if': lambda log_line: log_line.level in ("WARNING", "ERROR")
        },
        #
        # 2022-03-08T03:03:23.036161Z WARNING ExtHandler ExtHandler Fetch failed from [http://168.63.129.16:32526/extensionArtifact]: [HTTP Failed] [400: Bad Request] b''
        # 2022-03-08T03:03:23.042008Z WARNING ExtHandler ExtHandler Fetch failed: [ProtocolError] Fetch failed from [http://168.63.129.16:32526/extensionArtifact]: [HTTP Failed] [400: Bad Request] b''
        #
        # Warning downloading extension manifest. If the issue persists, this would cause errors elsewhere so safe to ignore
        {
            'message': r"\[http://168.63.129.16:32526/extensionArtifact\]: \[HTTP Failed\] \[400: Bad Request\]",
            'if': lambda log_line: log_line.level == "WARNING"
        },
        #
        # 2022-03-08T03:03:23.036161Z WARNING ExtHandler ExtHandler Fetch failed from [http://168.63.129.16:32526/extensionArtifact]: [HTTP Failed] [400: Bad Request] b''
        # 2022-03-08T03:03:23.042008Z WARNING ExtHandler ExtHandler Fetch failed: [ProtocolError] Fetch failed from [http://168.63.129.16:32526/extensionArtifact]: [HTTP Failed] [400: Bad Request] b''
        #
        # Warning downloading extension manifest. If the issue persists, this would cause errors elsewhere so safe to ignore
        {
            'message': r"\[http://168.63.129.16:32526/extensionArtifact\]: \[HTTP Failed\] \[400: Bad Request\]",
            'if': lambda log_line: log_line.level == "WARNING"
        },
        #
        # 2022-03-29T05:52:10.089958Z WARNING ExtHandler ExtHandler An error occurred while retrieving the goal state: [ProtocolError] GET vmSettings [correlation ID: da106cf5-83a0-44ec-9484-d0e9223847ab eTag: 9856274988128027586]: Timeout
        #
        # Ignore warnings about timeouts in vmSettings; if the condition persists, an error will occur elsewhere.
        #
        {
            'message': r"GET vmSettings \[[^]]+\]: Timeout",
            'if': lambda log_line: log_line.level == "WARNING"
        },
        # 2022-03-09T20:04:33.745721Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Monitor.AzureMonitorLinuxAgent, op=Install, message=[ExtensionOperationError] \
        #   Non-zero exit code: 51, /var/lib/waagent/Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.15.3/./shim.sh -install
        #
        # This is a known issue where AMA does not support Mariner 2.0. Please remove when support is
        # added in the next AMA release (1.16.x).
        {
            'message': r"Event: name=Microsoft.Azure.Monitor.AzureMonitorLinuxAgent, op=Install, message=\[ExtensionOperationError\] Non-zero exit code: 51",
            'if': lambda log_line: "Mariner2.0" in distro and log_line.level == "ERROR" and log_line.who == "ExtHandler"
        },
        # 2022-03-18T00:13:37.063540Z INFO ExtHandler ExtHandler [CGW] The daemon's PID was added to a legacy cgroup; will not monitor resource usage.
        #
        # Agent disables cgroups in older versions of the daemon (2.2.31-2.2.40).This is known issue and ignoring.
        {
            'message': r"The daemon's PID was added to a legacy cgroup; will not monitor resource usage"
        }
    ]

    if ignore is not None:
        ignore_list.extend(ignore)

    def can_be_ignored(log_line):
        return any(re.search(msg['message'], log_line.text) is not None and ('if' not in msg or msg['if'](log_line)) for msg in ignore_list)

    errors = []

    for agent_log_line in parse_agent_log_file(waagent_log):
        if agent_log_line.is_error and not can_be_ignored(agent_log_line):
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

