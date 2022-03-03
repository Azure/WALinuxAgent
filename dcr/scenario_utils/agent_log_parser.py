from __future__ import print_function

import os
import re
from datetime import datetime

AGENT_LOG_FILE = '/var/log/waagent.log'

# Example:
#     ProcessExtensionsGoalState completed [etag_2824367392948713696 4073 ms]
GOAL_STATE_COMPLETED = r"ProcessExtensionsGoalState completed\s\[(?P<id>[a-z_\d]+)\s(?P<duration>\d+)\sms\]"

# The format of the log has changed over time and the current log may include records from different sources. Most records are single-line, but some of them
# can span across multiple lines. We will assume records always start with a line similar to the examples below; any other lines will be assumed to be part
# of the record that is being currently parsed.
#
#     Newer Agent: 2019-11-27T22:22:48.123985Z VERBOSE ExtHandler ExtHandler Report vm agent status
#                  2021-03-30T19:45:33.793213Z INFO ExtHandler [Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent-2.14.64] Target handler state: enabled [incarnation 3]
#
#     Older Agent: 2021/03/30 19:35:35.971742 INFO Daemon Azure Linux Agent Version:2.2.45
#
#     Extension: 2021/03/30 19:45:31 Azure Monitoring Agent for Linux started to handle.
#                2021/03/30 19:45:31 [Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.7.0] cwd is /var/lib/waagent/Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.7.0
#
_NEW_AGENT_RECORD = re.compile(r'(?P<when>[0-9-]+T[0-9:.]+Z)\s(?P<level>VERBOSE|INFO|WARNING|ERROR)\s(?P<thread>\S+)\s(?P<who>(Daemon)|(ExtHandler)|(\[\S+\]))\s(?P<message>.*)')
_OLD_AGENT_RECORD = re.compile(r'(?P<when>[0-9/]+\s[0-9:.]+)\s(?P<level>VERBOSE|INFO|WARNING|ERROR)\s(?P<thread>)(?P<who>\S*)\s(?P<message>.*)')
_EXTENSION_RECORD = re.compile(r'(?P<when>[0-9/]+\s[0-9:.]+)\s(?P<level>)(?P<thread>)((?P<who>\[[^\]]+\])\s)?(?P<message>.*)')

# In 2.2.46, the date time was changed to ISO-8601 format but thread name was not added. This regex takes care of that
# Sample:   2021-05-28T01:17:40.683072Z INFO ExtHandler Wire server endpoint:168.63.129.16
#           2021-05-28T01:17:40.683823Z WARNING ExtHandler Move rules file 70-persistent-net.rules to /var/lib/waagent/70-persistent-net.rules
#           2021-05-28T01:17:40.767600Z INFO ExtHandler Successfully added Azure fabric firewall rules
_46_AGENT_RECORD = re.compile(r'(?P<when>[0-9-]+T[0-9:.]+Z)\s(?P<level>VERBOSE|INFO|WARNING|ERROR)\s(?P<thread>)(?P<who>Daemon|ExtHandler|\[\S+\])\s(?P<message>.*)')


class AgentLogRecord:
    __ERROR_TAGS = ['Exception', 'Traceback', '[CGW]']

    def __init__(self, match):
        self.text = match.string
        self.when = match.group("when")
        self.level = match.group("level")
        self.thread = match.group("thread")
        self.who = match.group("who")
        self.message = match.group("message")

    def get_timestamp(self):
        return datetime.strptime(self.when, u'%Y-%m-%dT%H:%M:%S.%fZ')

    @property
    def is_error(self):
        return self.level in ('ERROR', 'WARNING') or any(err in self.text for err in self.__ERROR_TAGS)


def parse_agent_log_file(waagent_log_path=AGENT_LOG_FILE):
    if not os.path.exists(waagent_log_path):
        raise IOError('{0} is not found'.format(waagent_log_path))

    def match_record():
        for regex in [_NEW_AGENT_RECORD, _46_AGENT_RECORD, _OLD_AGENT_RECORD]:
            m = regex.match(line)
            if m is not None:
                return m
        # The extension regex also matches the old agent records so it needs to be last
        return _EXTENSION_RECORD.match(line)

    def complete_record():
        if extra_lines != "":
            # note that message does not include a trailing "\n" (but text does)
            record.text = record.text + extra_lines
            record.message = record.message + "\n" + extra_lines.rstrip()
        return record

    with open(waagent_log_path) as file_:
        record = None
        extra_lines = ""

        line = file_.readline()
        while line != "":  # while not EOF
            match = match_record()
            if match is not None:
                if record is not None:
                    yield complete_record()
                record = AgentLogRecord(match)
                extra_lines = ""
            else:
                extra_lines = extra_lines + line
            line = file_.readline()

        if record is not None:
            yield complete_record()
