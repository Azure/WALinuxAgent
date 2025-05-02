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

import os
import re

from datetime import datetime
from pathlib import Path
from typing import Any, AnyStr, Dict, Iterable, List, Match

from azurelinuxagent.common.future import UTC, datetime_min_utc
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION


class AgentLogRecord:
    """
    Represents an entry in the Agent's log (note that entries can span multiple lines in the log)

    Sample message:
        2023-03-13T15:44:04.906673Z INFO ExtHandler ExtHandler Azure Linux Agent (Goal State Agent version 9.9.9.9)
    """
    text: str     # Full text of the record
    when: str     # Timestamp (as text)
    level: str    # Level (INFO, ERROR, etc)
    thread: str   # Thread name (e.g. 'Daemon', 'ExtHandler')
    prefix: str   # Prefix (e.g. 'Daemon', 'ExtHandler', <extension_name>)
    message: str  # Message

    @staticmethod
    def from_match(match: Match[AnyStr]):
        """Builds a record from a regex match"""
        record = AgentLogRecord()
        record.text = match.string
        record.when = match.group("when")
        record.level = match.group("level")
        record.thread = match.group("thread")
        record.prefix = match.group("prefix")
        record.message = match.group("message")
        return record

    @staticmethod
    def from_dictionary(dictionary: Dict[str, str]):
        """Deserializes from a dict"""
        record = AgentLogRecord()
        record.text = dictionary["text"]
        record.when = dictionary["when"]
        record.level = dictionary["level"]
        record.thread = dictionary["thread"]
        record.prefix = dictionary["prefix"]
        record.message = dictionary["message"]
        return record

    @property
    def timestamp(self) -> datetime:
        # Extension logs may follow different timestamp formats
        # 2023/07/10 20:50:13.459260
        ext_timestamp_regex_1 = r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}[.\d]+"
        # 2023/07/10 20:50:13
        ext_timestamp_regex_2 = r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}"

        if re.match(ext_timestamp_regex_1, self.when):
            return datetime.strptime(self.when, u'%Y/%m/%d %H:%M:%S.%f').replace(tzinfo=UTC)
        elif re.match(ext_timestamp_regex_2, self.when):
            return datetime.strptime(self.when, u'%Y/%m/%d %H:%M:%S').replace(tzinfo=UTC)
        # Logs from agent follow this format: 2023-07-10T20:50:13.038599Z
        return datetime.strptime(self.when, u'%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=UTC)

    def __str__(self):
        return self.text


class AgentLog(object):
    """
    Provides facilities to parse and/or extract errors from the agent's log.
    """
    def __init__(self, path: Path = Path('/var/log/waagent.log')):
        self._path: Path = path
        self._counter_table: Dict[str, int] = {}

    def get_errors(self) -> List[AgentLogRecord]:
        """
        Returns any ERRORs or WARNINGs in the agent log.

        The function filters out known/uninteresting errors, which are kept in the 'ignore_list' variable.
        """
        #
        # Items in this list are known errors and they are ignored.
        #
        #     * 'message' - A regular expression matched using re.search; be sure to escape any regex metacharacters. A positive match indicates
        #                   that the error should be ignored
        #     * 'if' - A lambda that takes as parameter an AgentLogRecord representing an error and returns true if the error should be ignored
        #
        ignore_rules = [
            #
            # 2023-06-28T09:31:38.903835Z WARNING EnvHandler ExtHandler Move rules file 75-persistent-net-generator.rules to /var/lib/waagent/75-persistent-net-generator.rules
            #  The environment thread performs this operation periodically
            #
            {
                'message': r"Move rules file (70|75)-persistent.*.rules to /var/lib/waagent/(70|75)-persistent.*.rules",
                'if': lambda r: r.level == "WARNING"
            },
            #
            # Probably the agent should log this as INFO, but for now it is a warning
            # e.g.
            # 2021-07-29T04:40:17.190879Z WARNING EnvHandler ExtHandler Dhcp client is not running.
            # old agents logs don't have a prefix of thread and/or logger names.
            {
                'message': r"Dhcp client is not running.",
                'if': lambda r: r.level == "WARNING"
            },
            # Known bug fixed in the current agent, but still present in older daemons
            #
            {
                'message': r"\[CGroupsException\].*Error: join\(\) argument must be str, bytes, or os.PathLike object, not 'NoneType'",
                'if': lambda r: r.level == "WARNING" and r.prefix == "Daemon"
            },
            # This warning is expected on when WireServer gives us the incomplete goalstate without roleinstance data
            {
                'message': r"\[ProtocolError\] Fetched goal state without a RoleInstance",
            },
            #
            # Download warnings (manifest and zips).
            #
            # Examples:
            #     2021-03-31T03:48:35.216494Z WARNING ExtHandler ExtHandler Fetch failed: [HttpError] [HTTP Failed] GET https://zrdfepirv2cbn04prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqA_useast2euap_manifest.xml -- IOError ('The read operation timed out',) -- 1 attempts made
            #     2021-03-31T06:54:29.655861Z WARNING ExtHandler ExtHandler Fetch failed: [HttpError] [HTTP Retry] GET http://168.63.129.16:32526/extensionArtifact -- Status Code 502 -- 1 attempts made
            #     2021-03-31T06:43:17.806663Z WARNING ExtHandler ExtHandler Download failed, switching to host plugin
            {
                'message': r"(Fetch failed: \[HttpError\] .+ GET .+ -- [0-9]+ attempts made)|(Download failed, switching to host plugin)",
                'if': lambda r: r.level == "WARNING" and r.prefix == "ExtHandler" and r.thread == "ExtHandler"
            },
            # 2021-07-09T01:46:53.307959Z INFO MonitorHandler ExtHandler [CGW] Disabling resource usage monitoring. Reason: Check on cgroups failed:
            # [CGroupsException] The agent's cgroup includes unexpected processes: ['[PID: 2367] UNKNOWN']
            {
                'message': r"The agent's cgroup includes unexpected processes: \[('\[PID:\s?\d+\]\s*UNKNOWN'(,\s*)?)+\]"
            },
            # 2021-12-20T07:46:23.020197Z INFO ExtHandler ExtHandler [CGW] The agent's process is not within a memory cgroup
            # Ignoring this since memory cgroup(MemoryAccounting) not enabled.
            {
                'message': r"The agent's process is not within a memory cgroup",
                'if': lambda r: re.match(r"(((centos|redhat)7\.[48])|(redhat7\.6)|(redhat8\.2))\D*", DISTRO_NAME, flags=re.IGNORECASE)
            },
            #
            # We log these when the controllers not mounted at root in v2 machines, expected warn.
            #
            # 2025-03-07T09:14:37.792300Z INFO ExtHandler ExtHandler [CGW] cpu controller is not enabled; will not track
            {
                'message': r"\[CGW\]\s*(cpu|memory) controller is not enabled",
                'if': lambda r: (DISTRO_NAME == 'ubuntu' and DISTRO_VERSION >= '22.00') or (DISTRO_NAME == 'azurelinux' and DISTRO_VERSION >= '3.0') or (DISTRO_NAME == 'rhel' and DISTRO_VERSION >= '9.0')
            },
            #
            #
            # Old daemons can produce this message
            #
            #    2023-05-24T18:04:27.467009Z WARNING Daemon Daemon Could not mount cgroups: [Errno 1] Operation not permitted: '/sys/fs/cgroup/cpu,cpuacct' -> '/sys/fs/cgroup/cpu'
            #
            {
                'message': r"Could not mount cgroups: \[Errno 1\] Operation not permitted",
                'if': lambda r: r.prefix == 'Daemon'
            },
            #
            # The daemon does not need the artifacts profile blob, but the request is done as part of protocol initialization. This timeout can be ignored, if the issue persist the log would include additional instances.
            #
            # 2022-01-20T06:52:21.515447Z WARNING Daemon Daemon Fetch failed: [HttpError] [HTTP Failed] GET https://dcrgajhx62.blob.core.windows.net/$system/edprpwqbj6.5c2ddb5b-d6c3-4d73-9468-54419ca87a97.vmSettings -- IOError timed out -- 6 attempts made
            #
            {
                'message': r"\[HTTP Failed\] GET https://.*\.vmSettings -- IOError timed out",
                'if': lambda r: r.level == "WARNING" and r.prefix == "Daemon"
            },
            #
            # 2022-02-09T04:50:37.384810Z ERROR ExtHandler ExtHandler Error fetching the goal state: [ProtocolError] GET vmSettings [correlation ID: 2bed9b62-188e-4668-b1a8-87c35cfa4927 eTag: 7031887032544600793]: [Internal error in HostGAPlugin] [HTTP Failed] [502: Bad Gateway] b'{  "errorCode": "VMArtifactsProfileBlobContentNotFound",  "message": "VM artifacts profile blob has no content in it.",  "details": ""}'
            #
            # Fetching the goal state may catch the HostGAPlugin in the process of computing the vmSettings. This can be ignored, if the issue persist the log would include other errors as well.
            #
            {
                'message': r"\[ProtocolError\] GET vmSettings.*VMArtifactsProfileBlobContentNotFound",
                'if': lambda r: r.level == "ERROR"
            },
            #
            # 2022-11-01T02:45:55.513692Z ERROR ExtHandler ExtHandler Error fetching the goal state: [ProtocolError] GET vmSettings [correlation ID: 616873cc-be87-41b6-83b7-ef3a76370628 eTag: 3693655388249891516]: [Internal error in HostGAPlugin] [HTTP Failed] [502: Bad Gateway] {  "errorCode": "InternalError",  "message": "The server encountered an internal error. Please retry the request.",  "details": ""}
            #
            # Fetching the goal state may catch the HostGAPlugin in the process of computing the vmSettings. This can be ignored, if the issue persist the log would include other errors as well.
            #
            {
                'message': r"\[ProtocolError\] GET vmSettings.*Please retry the request",
                'if': lambda r: r.level == "ERROR"
            },
            #
            # 2022-08-16T01:50:10.759502Z ERROR ExtHandler ExtHandler Error fetching the goal state: [ProtocolError] GET vmSettings [correlation ID: e162f7c3-8d0c-4a9b-a987-8f9ec0699dae eTag: 9757461589808963322]: Timeout
            #
            # Fetching the goal state may hit timeouts in the HostGAPlugin's vmSettings. This can be ignored, if the issue persist the log would include other errors as well.
            #
            {
                'message': r"\[ProtocolError\] GET vmSettings.*Timeout",
                'if': lambda r: r.level == "ERROR"
            },
            #
            # 2021-12-29T06:50:49.904601Z ERROR ExtHandler ExtHandler Error fetching the goal state: [ProtocolError] Error fetching goal state Inner error: [ResourceGoneError] [HTTP Failed] [410: Gone] The page you requested was removed.
            # 2022-03-21T02:44:03.770017Z ERROR ExtHandler ExtHandler Error fetching the goal state: [ProtocolError] Error fetching goal state Inner error: [ResourceGoneError] Resource is gone
            # 2022-02-16T04:46:50.477315Z WARNING Daemon Daemon Fetching the goal state failed: [ResourceGoneError] [HTTP Failed] [410: Gone] b'<?xml version="1.0" encoding="utf-8"?>\n<Error xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n    <Code>ResourceNotAvailable</Code>\n    <Message>The resource requested is no longer available. Please refresh your cache.</Message>\n    <Details></Details>\n</Error>'
            #
            # ResourceGone can happen if we are fetching one of the URIs in the goal state and a new goal state arrives
            {
                'message': r"(?s)(Fetching the goal state failed|Error fetching goal state|Error fetching the goal state).*(\[ResourceGoneError\]|\[410: Gone\]|Resource is gone)",
                'if': lambda r: r.level in ("WARNING", "ERROR")
            },
            #
            # 2022-12-02T05:45:51.771876Z ERROR ExtHandler ExtHandler Error fetching the goal state: [ProtocolError] [Wireserver Exception] [HttpError] [HTTP Failed] GET http://168.63.129.16/machine/ -- IOError [Errno 104] Connection reset by peer -- 6 attempts made
            #
            {
                'message': r"\[HttpError\] \[HTTP Failed\] GET http://168.63.129.16/machine/ -- IOError \[Errno 104\] Connection reset by peer",
                'if': lambda r: r.level in ("WARNING", "ERROR")
            },
            #
            # 2022-03-08T03:03:23.036161Z WARNING ExtHandler ExtHandler Fetch failed from [http://168.63.129.16:32526/extensionArtifact]: [HTTP Failed] [400: Bad Request] b''
            # 2022-03-08T03:03:23.042008Z WARNING ExtHandler ExtHandler Fetch failed: [ProtocolError] Fetch failed from [http://168.63.129.16:32526/extensionArtifact]: [HTTP Failed] [400: Bad Request] b''
            #
            # Warning downloading extension manifest. If the issue persists, this would cause errors elsewhere so safe to ignore
            {
                'message': r"\[http://168.63.129.16:32526/extensionArtifact\]: \[HTTP Failed\] \[400: Bad Request\]",
                'if': lambda r: r.level == "WARNING"
            },
            #
            # 2022-03-29T05:52:10.089958Z WARNING ExtHandler ExtHandler An error occurred while retrieving the goal state: [ProtocolError] GET vmSettings [correlation ID: da106cf5-83a0-44ec-9484-d0e9223847ab eTag: 9856274988128027586]: Timeout
            #
            # Ignore warnings about timeouts in vmSettings; if the condition persists, an error will occur elsewhere.
            #
            {
                'message': r"GET vmSettings \[[^]]+\]: Timeout",
                'if': lambda r: r.level == "WARNING"
            },
            #
            # 2022-09-30T02:48:33.134649Z WARNING MonitorHandler ExtHandler Error in SendHostPluginHeartbeat: [HttpError] [HTTP Failed] GET http://168.63.129.16:32526/health -- IOError timed out -- 1 attempts made --- [NOTE: Will not log the same error for the next hour]
            #
            # Ignore timeouts in the HGAP's health API... those are tracked in the HGAP dashboard so no need to worry about them on test runs
            #
            {
                'message': r"SendHostPluginHeartbeat:.*GET http://168.63.129.16:32526/health.*timed out",
                'if': lambda r: r.level == "WARNING"
            },
            #
            # 2022-09-30T03:09:25.013398Z WARNING MonitorHandler ExtHandler Error in SendHostPluginHeartbeat: [ResourceGoneError] [HTTP Failed] [410: Gone]
            #
            # ResourceGone should not happen very often, since the monitor thread already refreshes the goal state before sending the HostGAPlugin heartbeat. Errors can still happen, though, since the goal state
            # can change in-between the time at which the monitor thread refreshes and the time at which it sends the heartbeat. Ignore these warnings unless there are 2 or more of them.
            #
            {
                'message': r"SendHostPluginHeartbeat:.*ResourceGoneError.*410",
                'if': lambda r: r.level == "WARNING" and self._increment_counter("SendHostPluginHeartbeat-ResourceGoneError-410") < 2  # ignore unless there are 2 or more instances
            },
            #
            # 2023-01-18T02:58:25.589492Z ERROR SendTelemetryHandler ExtHandler Event: name=WALinuxAgent, op=ReportEventErrors, message=DroppedEventsCount: 1
            # Reasons (first 5 errors): [ProtocolError] [Wireserver Exception] [ProtocolError] [Wireserver Failed] URI http://168.63.129.16/machine?comp=telemetrydata  [HTTP Failed] Status Code 400: Traceback (most recent call last):
            #
            {
                'message': r"(?s)\[ProtocolError\].*http:\/\/168.63.129.16\/machine\?comp=telemetrydata.*Status Code 400",
                'if': lambda r: r.thread == 'SendTelemetryHandler' and self._increment_counter("SendTelemetryHandler-telemetrydata-Status Code 400") < 2  # ignore unless there are 2 or more instances
            },
            #
            # 2023-07-26T22:05:42.841692Z ERROR SendTelemetryHandler ExtHandler Event: name=WALinuxAgent, op=ReportEventErrors, message=DroppedEventsCount: 1
            # Reasons (first 5 errors): [ProtocolError] Failed to send events:[ResourceGoneError] [HTTP Failed] [410: Gone] b'<?xml version="1.0" encoding="utf-8"?>\n<Error xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n    <Code>ResourceNotAvailable</Code>\n    <Message>The resource requested is no longer available. Please refresh your cache.</Message>\n    <Details></Details>\n</Error>': Traceback (most recent call last):
            #
            {
                'message': r"(?s)\[ProtocolError\].*Failed to send events.*\[410: Gone\]",
                'if': lambda r: r.thread == 'SendTelemetryHandler' and self._increment_counter("SendTelemetryHandler-telemetrydata-Status Code 410") < 2  # ignore unless there are 2 or more instances
            },
            #
            # Ignore these errors in flatcar:
            #
            #    1)  2023-03-16T14:30:33.091427Z ERROR Daemon Daemon Failed to mount resource disk [ResourceDiskError] unable to detect disk topology
            #    2)  2023-03-16T14:30:33.091708Z ERROR Daemon Daemon Event: name=WALinuxAgent, op=ActivateResourceDisk, message=[ResourceDiskError] unable to detect disk topology, duration=0
            #    3)  2023-03-16T14:30:34.660976Z WARNING ExtHandler ExtHandler Fetch failed: [HttpError] HTTPS is unavailable and required
            #    4)  2023-03-16T14:30:34.800112Z ERROR ExtHandler ExtHandler Unable to setup the persistent firewall rules: [Errno 30] Read-only file system: '/lib/systemd/system/waagent-network-setup.service'
            #
            # 1, 2) under investigation
            # 3) There seems to be a configuration issue in flatcar that prevents python from using HTTPS when trying to reach storage. This does not produce any actual errors, since the agent fallbacks to the HGAP.
            # 4) Remove this when bug 17523033 is fixed.
            #
            {
                'message': r"(Failed to mount resource disk)|(unable to detect disk topology)",
                'if': lambda r: r.prefix == 'Daemon' and DISTRO_NAME == 'flatcar'
            },
            {
                'message': r"(HTTPS is unavailable and required)|(Unable to setup the persistent firewall rules.*Read-only file system)",
                'if': lambda r: DISTRO_NAME == 'flatcar'
            },
            #
            # AzureSecurityLinuxAgent fails to install on a few distros (e.g. Debian 11)
            #
            #     2023-03-16T14:29:48.798415Z ERROR ExtHandler ExtHandler Event: name=Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent, op=Install, message=[ExtensionOperationError] Non-zero exit code: 56, /var/lib/waagent/Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent-2.21.115/handler.sh install
            #
            {
                'message': r"Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent.*op=Install.*Non-zero exit code: 56,",
            },
            #
            # Ignore LogCollector failure to fetch vmSettings if it recovers
            #
            #     2023-08-27T08:13:42.520557Z WARNING MainThread LogCollector Fetch failed: [HttpError] [HTTP Failed] GET https://md-hdd-tkst3125n3x0.blob.core.chinacloudapi.cn/$system/lisa-WALinuxAgent-20230827-080144-029-e0-n0.cb9a406f-584b-4702-98bb-41a3ad5e334f.vmSettings -- IOError timed out -- 6 attempts made
            #
            {
                'message': r"Fetch failed:.*GET.*vmSettings.*timed out",
                'if': lambda r: r.prefix == 'LogCollector' and self.agent_log_contains("LogCollector Log collection successfully completed", after_timestamp=r.timestamp)
            },
            #
            # In tests, we use both autoupdate flags to install test agent with different value and changing it depending on the scenario. So, we can ignore this warning.
            #
            # 2024-01-30T22:22:37.299911Z WARNING ExtHandler ExtHandler AutoUpdate.Enabled property is **Deprecated** now but it's set to different value from AutoUpdate.UpdateToLatestVersion. Please consider removing it if added by mistake
            {
                'message': r"AutoUpdate.Enabled property is \*\*Deprecated\*\* now but it's set to different value from AutoUpdate.UpdateToLatestVersion",
                'if': lambda r: r.prefix == 'ExtHandler' and r.thread == 'ExtHandler'
            },
            #
            # Some distros are running older agents, which do not add the DNS rule
            #
            # 2024-08-02T21:44:44.330727Z WARNING ExtHandler ExtHandler The firewall rules for Azure Fabric are not setup correctly (the environment thread will fix it): The following rules are missing: ['ACCEPT DNS']
            # 2024-08-08T22:05:26.561896Z WARNING EnvHandler ExtHandler The firewall is not configured correctly. The following rules are missing: ['ACCEPT DNS']. Will reset it.
            # 2024-09-16T15:50:12.473500Z WARNING ExtHandler ExtHandler The permanent firewall rules for Azure Fabric are not setup correctly (The following rules are missing: ['ACCEPT DNS']), will reset them.
            # 2024-12-27T19:42:03.895387Z WARNING ExtHandler ExtHandler The permanent firewall rules for Azure Fabric are not setup correctly (The following rules are missing: ['ACCEPT DNS'] due to: ['']), will reset them.
            # 2024-12-27T19:38:14.093727Z WARNING EnvHandler ExtHandler The firewall is not configured correctly. The following rules are missing: ['ACCEPT DNS'] due to: ['iptables: Bad rule (does a matching rule exist in that chain?).\n']. Will reset it.
            {
                'message': r"(The firewall rules for Azure Fabric are not setup correctly \(the environment thread will fix it\): The following rules are missing: \['ACCEPT DNS'\])"
                           "|"
                           r"(The firewall is not configured correctly. The following rules are missing: \['ACCEPT DNS'\].* Will reset it.)"
                           "|"
                           r"The permanent firewall rules for Azure Fabric are not setup correctly \(The following rules are missing: \['ACCEPT DNS'\]\).* will reset them.",
                'if': lambda r: r.level == "WARNING"
            },
            # TODO: The Daemon has not been updated on Azure Linux 3; remove this message when it is.
            #
            # 2024-08-05T14:36:48.004865Z WARNING Daemon Daemon Unable to load distro implementation for azurelinux. Using default distro implementation instead.
            #
            {
                'message': r"Unable to load distro implementation for azurelinux. Using default distro implementation instead.",
                'if': lambda r: DISTRO_NAME == 'azurelinux' and r.prefix == 'Daemon' and r.level == 'WARNING'
            },
            #
            # TODO: The OMS extension does not support Azure Linux 3; remove this message when it does.
            #
            # 2024-08-12T17:40:48.375193Z ERROR ExtHandler ExtHandler Event: name=Microsoft.EnterpriseCloud.Monitoring.OmsAgentForLinux, op=Install, message=[ExtensionOperationError] Non-zero exit code: 51, /var/lib/waagent/Microsoft.EnterpriseCloud.Monitoring.OmsAgentForLinux-1.19.0/omsagent_shim.sh -install
            #
            {
                'message': r"name=Microsoft\.EnterpriseCloud\.Monitoring\.OmsAgentForLinux.+Non-zero exit code: 51",
                'if': lambda r: DISTRO_NAME == 'azurelinux' and DISTRO_VERSION == '3.0'
            },

            # Ubuntu 16 has an issue representing no quota as infinity, instead it outputs weird values. https://github.com/systemd/systemd/issues/5965, so ignoring in ubuntu 16
            # 2024-11-26T00:07:38.716162Z INFO ExtHandler ExtHandler [CGW] Error parsing current CPUQuotaPerSecUSec: could not convert string to float: '584542y 2w 2d 20h 1min 49.549568'
            # 2025-04-08T09:02:47.491505Z INFO ExtHandler ExtHandler [CGW] Error parsing current CPUQuotaPerSecUSec: invalid literal for float(): 584542y 2w 2d 20h 1min 49.549568
            {'message': r"Error parsing current CPUQuotaPerSecUSec: (could not convert string to float|invalid literal for float)",
             'if': lambda r: re.match(r"((ubuntu16\.04)|(centos7\.9))\D*", "{0}{1}".format(DISTRO_NAME, DISTRO_VERSION), flags=re.IGNORECASE)
            },
            #
            # GuestConfiguration produces a lot of errors in test runs due to issues in the extension. Some samples:
            #
            # 2024-12-08T06:28:34.480675Z ERROR ExtHandler ExtHandler Event: name=Microsoft.GuestConfiguration.ConfigurationforLinux, op=Install, message=[ExtensionOperationError] Non-zero exit code: 126, /var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationforLinux-1.26.79/bin/guest-configuration-shim install
            # [stdout]
            # Linux distribution version is 9.0.
            # Linux distribution is Red Hat.
            # + /var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationforLinux-1.26.79/bin/guest-configuration-extension install
            # /var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationforLinux-1.26.79/bin/guest-configuration-shim: line 211: /var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationforLinux-1.26.79/bin/guest-configuration-extension: cannot execute binary file: Exec format error
            # [stderr]
            #
            # 2024-12-26T06:35:24.233438Z ERROR ExtHandler ExtHandler Event: name=Microsoft.GuestConfiguration.ConfigurationforLinux, op=Install, message=[ExtensionOperationError] Non-zero exit code: 51, /var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationforLinux-1.26.79/bin/guest-configuration-shim install
            # [stdout]
            # Linux distribution version is 4081.2.1.
            # [stderr]
            # [2024-12-26T06:35:22+0000]: Unexpected Linux distribution. Expected Linux distributions include only Ubuntu, Red Hat, SUSE, CentOS, Debian or Mariner.
            #
            # 2025-01-07T11:32:28.121056Z ERROR ExtHandler ExtHandler Event: name=Microsoft.GuestConfiguration.ConfigurationforLinux, op=Install, message=[ExtensionOperationError] Non-zero exit code: 1, /var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationforLinux-1.26.79/bin/guest-configuration-shim install
            # [stdout]
            # Linux distribution version is 12.5.
            # Linux distribution is SUSE.
            # /var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationforLinux-1.26.79/bin/guest-configuration-extension install
            # /var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationforLinux-1.26.79/bin/guest-configuration-shim: line 211:
            # /var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationforLinux-1.26.79/bin/guest-configuration-extension: Text file busy
            # [stderr]
            #
            # Also, enable not always completes before the new goal state is received
            #
            # 2025-01-07T13:33:25.636847Z WARNING ExtHandler ExtHandler A new goal state was received, but not all the extensions in the previous goal state have completed:
            # [('Microsoft.Azure.Extensions.CustomScript', 'success'), ('Microsoft.GuestConfiguration.ConfigurationforLinux', 'transitioning'), ('RunCommandHandler', 'success')]
            #
            {
                'message': r"(?s)name=Microsoft.GuestConfiguration.ConfigurationforLinux.*op=Install.*Non-zero exit code: (1.*Text file busy|51.*Unexpected Linux distribution|126.*Exec format error)",
            },
            {
                'message': r"A new goal state was received, but not all the extensions in the previous goal state have completed.*'Microsoft.GuestConfiguration.ConfigurationforLinux',\s+u?'transitioning'",
            },
            #
            # Below systemd errors are transient and will not block extension execution
            #
            # 2025-01-05T09:38:44.046292Z INFO ExtHandler ExtHandler [CGW] Failed to set the extension azure-vmextensions-Microsoft.CPlat.Core.RunCommandHandlerLinux.slice slice and quotas:
            # 'systemctl show azure-vmextensions-Microsoft.CPlat.Core.RunCommandHandlerLinux.slice --property CPUAccounting' failed: 1 (Failed to get properties: Message recipient disconnected from message bus without replying)
            #
            # 2025-01-06T09:32:42.594033Z INFO ExtHandler ExtHandler [CGW] Failed to set the extension azure-vmextensions-Microsoft.Azure.Extensions.CustomScript.slice slice and quotas:
            # 'systemctl show azure-vmextensions-Microsoft.Azure.Extensions.CustomScript.slice --property CPUAccounting' failed: 1 (Failed to get properties: Connection reset by peer)
            #
            # 2025-03-12T08:48:02.186772Z INFO ExtHandler ExtHandler [CGW] Error parsing current CPUQuotaPerSecUSec: 'systemctl show azure-vmextensions-Microsoft.Azure.Extensions.Edp.GATestExtGo.slice --property CPUQuotaPerSecUSec' failed: 1 (Failed to get properties: Connection reset by peer)
            # 2025-03-31T08:46:39.253900Z INFO ExtHandler ExtHandler [CGW] Failed to set the extension azure-vmextensions-Microsoft.Azure.Extensions.CustomScript.slice slice and quotas: Can't set properties ['CPUQuota='] of azure-vmextensions-Microsoft.Azure.Extensions.CustomScript.slice: 'systemctl set-property azure-vmextensions-Microsoft.Azure.Extensions.CustomScript.slice CPUQuota= --runtime' failed: 1 (Failed to set unit properties on azure-vmextensions-Microsoft.Azure.Extensions.CustomScript.slice: Message recipient disconnected from message bus without replying)
            # 2025-04-28T12:27:25.311806Z INFO ExtHandler ExtHandler [CGW] Failed to set the extension azure-vmextensions-Microsoft.CPlat.Core.RunCommandHandlerLinux.slice slice and quotas: 'systemctl show azure-vmextensions-Microsoft.CPlat.Core.RunCommandHandlerLinux.slice --property CPUAccounting' failed: 1 (Failed to get properties: Remote peer disconnected)
            # 2025-04-27T12:28:14.585253Z INFO ExtHandler ExtHandler [CGW] Error parsing current CPUQuotaPerSecUSec: 'systemctl show azure-vmextensions-Microsoft.CPlat.Core.RunCommandHandlerLinux.RunCommandHandler.slice --property CPUQuotaPerSecUSec' failed: 1 (Failed to get properties: Transport endpoint is not connected)
            {
                'message': r"(Failed to set the extension|Error parsing).*systemctl (show|set-property).*failed: 1.*(Message recipient disconnected from message bus without replying|Connection reset by peer|Remote peer disconnected|Transport endpoint is not connected)",
            },
            #
            # 2025-01-06T09:32:44.641948Z INFO ExtHandler ExtHandler [CGW] Disabling resource usage monitoring. Reason: Failed to start Microsoft.Azure.Extensions.CustomScript-2.1.10 using systemd-run, will try invoking the extension directly. Error: [SystemdRunError] Systemd process exited with code 1 and output [stdout]
            #
            #
            # [stderr]
            # Failed to start transient scope unit: Message recipient disconnected from message bus without replying
            #
            # Microsoft.CPlat.Core.RunCommandHandlerLinux.RunCommandHandler-1.3.15 using systemd-run, will try invoking the extension directly. Error: [SystemdRunError] Systemd process exited with code 1 and output [stdout]
            #
            #
            # [stderr]
            # Failed to start transient scope unit: Transport endpoint is not connected
            {
                'message': r"(?s)Disabling resource usage monitoring. Reason: Failed to start.*using systemd-run, will try invoking the extension directly. Error: \[SystemdRunError\].*Failed to start transient scope unit: (Message recipient disconnected from message bus without replying|Connection reset by peer|Remote peer disconnected|Transport endpoint is not connected)",
            },
            #
            # If agent is not mounted at the expected path, we log this message in v2 machines. This is not an error.
            # 2025-03-03T09:19:03.145557Z INFO ExtHandler ExtHandler [CGW] The walinuxagent.service cgroup is not mounted at the expected path; will not track. Actual cgroup path:[/sys/fs/cgroup/system.slice/walinuxagent.service] Expected:[/sys/fs/cgroup/azure.slice/walinuxagent.service]
            # 2025-03-12T22:03:04.095141Z INFO ExtHandler ExtHandler [CGW] The cpu,cpuacct controller is not mounted at the expected path for the walinuxagent.service cgroup; will not track. Actual cgroup path:[/sys/fs/cgroup/cpu,cpuacct/system.slice/walinuxagent.service] Expected:[/sys/fs/cgroup/cpu,cpuacct/azure.slice/walinuxagent.service]
            #
            {
                'message': r"(The walinuxagent.service cgroup is not mounted at the expected path|controller is not mounted at the expected path for the walinuxagent.service cgroup); will not track. Actual cgroup path:\[.*\] Expected:\[.*\]",
            },
        ]

        def is_error(r: AgentLogRecord) -> bool:
            return r.level in ('ERROR', 'WARNING') or any(err in r.text for err in ['Exception', 'Traceback', '[CGW]'])

        errors = []
        primary_interface_error = None
        provisioning_complete = False

        for record in self.read():
            if is_error(record) and not self.matches_ignore_rule(record, ignore_rules):
                # Handle "/proc/net/route contains no routes" and "/proc/net/route is missing headers" as a special case
                # since it can take time for the primary interface to come up, and we don't want to report transient
                # errors as actual errors. The last of these errors in the log will be reported
                if "/proc/net/route contains no routes" in record.text or "/proc/net/route is missing headers" in record.text and record.prefix == "Daemon":
                    primary_interface_error = record
                    provisioning_complete = False
                else:
                    errors.append(record)

            if "Provisioning complete" in record.text and record.prefix == "Daemon":
                provisioning_complete = True

        # Keep the "no routes found" as a genuine error message if it was never corrected
        if primary_interface_error is not None and not provisioning_complete:
            errors.append(primary_interface_error)

        return errors

    def agent_log_contains(self, data: str, after_timestamp: datetime = datetime_min_utc):
        """
        This function looks for the specified test data string in the WALinuxAgent logs and returns if found or not.
        :param data: The string to look for in the agent logs
        :param after_timestamp: A timestamp
        appears after this timestamp
        :return: True if test data string found in the agent log after after_timestamp and False if not.
       """
        for record in self.read():
            if data in record.text and record.timestamp > after_timestamp:
                return True
        return False

    @staticmethod
    def _is_systemd():
        # Taken from azurelinuxagent/common/osutil/systemd.py; repeated here because it is available only on agents >= 2.3
        return os.path.exists("/run/systemd/system/")

    def _increment_counter(self, counter_name) -> int:
        """
        Keeps a table of counters indexed by the given 'counter_name'. Each call to the function
        increments the value of that counter and returns the new value.
        """
        count = self._counter_table.get(counter_name)
        count = 1 if count is None else count + 1
        self._counter_table[counter_name] = count
        return count

    @staticmethod
    def matches_ignore_rule(record: AgentLogRecord, ignore_rules: List[Dict[str, Any]]) -> bool:
        """
        Returns True if the given 'record' matches any of the 'ignore_rules'
        """
        return any(re.search(rule['message'], record.message) is not None and ('if' not in rule or rule['if'](record)) for rule in ignore_rules)

    # The format of the log has changed over time and the current log may include records from different sources. Most records are single-line, but some of them
    # can span across multiple lines. We will assume records always start with a line similar to the examples below; any other lines will be assumed to be part
    # of the record that is being currently parsed.
    #
    #     Newer Agent: 2019-11-27T22:22:48.123985Z VERBOSE ExtHandler ExtHandler Report vm agent status
    #                  2021-03-30T19:45:33.793213Z INFO ExtHandler [Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent-2.14.64] Target handler state: enabled [incarnation 3]
    #
    #     2.2.46: the date time was changed to ISO-8601 format but the thread name was not added.
    #          2021-05-28T01:17:40.683072Z INFO ExtHandler Wire server endpoint:168.63.129.16
    #          2021-05-28T01:17:40.683823Z WARNING ExtHandler Move rules file 70-persistent-net.rules to /var/lib/waagent/70-persistent-net.rules
    #          2021-05-28T01:17:40.767600Z INFO ExtHandler Successfully added Azure fabric firewall rules
    #
    #     Older Agent: 2021/03/30 19:35:35.971742 INFO Daemon Azure Linux Agent Version:2.2.45
    #
    #     Oldest Agent: 2023/06/07 08:04:35.336313 WARNING Disabling guest agent in accordance with ovf-env.xml
    #
    #     Extension: 2021/03/30 19:45:31 Azure Monitoring Agent for Linux started to handle.
    #                2021/03/30 19:45:31 [Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.7.0] cwd is /var/lib/waagent/Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.7.0
    #
    _NEWER_AGENT_RECORD = re.compile(r'(?P<when>[\d-]+T[\d:.]+Z)\s(?P<level>VERBOSE|INFO|WARNING|ERROR)\s(?P<thread>\S+)\s(?P<prefix>(Daemon)|(ExtHandler)|(LogCollector)|(\[\S+\]))\s(?P<message>.*)')
    _2_2_46_AGENT_RECORD = re.compile(r'(?P<when>[\d-]+T[\d:.]+Z)\s(?P<level>VERBOSE|INFO|WARNING|ERROR)\s(?P<thread>)(?P<prefix>Daemon|ExtHandler|\[\S+\])\s(?P<message>.*)')
    _OLDER_AGENT_RECORD = re.compile(r'(?P<when>[\d/]+\s[\d:.]+)\s(?P<level>VERBOSE|INFO|WARNING|ERROR)\s(?P<thread>)(?P<prefix>Daemon|ExtHandler)\s(?P<message>.*)')
    _OLDEST_AGENT_RECORD = re.compile(r'(?P<when>[\d/]+\s[\d:.]+)\s(?P<level>VERBOSE|INFO|WARNING|ERROR)\s(?P<thread>)(?P<prefix>)(?P<message>.*)')
    _EXTENSION_RECORD = re.compile(r'(?P<when>[\d/]+\s[\d:.]+)\s(?P<level>)(?P<thread>)((?P<prefix>\[[^\]]+\])\s)?(?P<message>.*)')

    def read(self) -> Iterable[AgentLogRecord]:
        """
        Generator function that returns each of the entries in the agent log parsed as AgentLogRecords.

        The function can be used following this pattern:

            for record in read_agent_log():
                 ... do something...

        """
        if not self._path.exists():
            raise IOError('{0} does not exist'.format(self._path))

        def match_record():
            for regex in [self._NEWER_AGENT_RECORD, self._2_2_46_AGENT_RECORD, self._OLDER_AGENT_RECORD, self._OLDEST_AGENT_RECORD]:
                m = regex.match(line)
                if m is not None:
                    return m
            # The extension regex also matches the old agent records, so it needs to be last
            return self._EXTENSION_RECORD.match(line)

        def complete_record():
            record.text = record.text.rstrip()  # the text includes \n
            if extra_lines != "":
                record.text = record.text + "\n" + extra_lines.rstrip()
                record.message = record.message + "\n" + extra_lines.rstrip()
            return record

        with self._path.open() as file_:
            record = None
            extra_lines = ""

            line = file_.readline()
            while line != "":  # while not EOF
                match = match_record()
                if match is not None:
                    if record is not None:
                        yield complete_record()
                    record = AgentLogRecord.from_match(match)
                    extra_lines = ""
                else:
                    extra_lines = extra_lines + line
                line = file_.readline()

            if record is not None:
                yield complete_record()
