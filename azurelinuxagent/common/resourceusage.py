# Copyright 2019 Microsoft Corporation
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

import os

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logger import EVERY_SIX_HOURS
from azurelinuxagent.common.utils import fileutil


PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')
PROC_STATM_FILENAME_FORMAT = "/proc/{0}/statm"
PROC_CMDLINE_FILENAME_FORMAT = "/proc/{0}/cmdline"
PROC_COMM_FILENAME_FORMAT = "/proc/{0}/comm"
PROC_STATUS_FILENAME_FORMAT = "/proc/{0}/status"


class ResourceUsage(object): 
    pass


class MemoryResourceUsage(ResourceUsage): 
    @staticmethod
    def get_memory_usage_from_proc_statm(process_id):
        proc_pid_rss = 0
        try:
            proc_pid_rss = MemoryResourceUsage._get_proc_rss(process_id)
        except Exception as e:
            if isinstance(e, (IOError, OSError)):
                raise
            logger.periodic_info(EVERY_SIX_HOURS, "[PERIODIC] Could not get the /prod/{0}/statm data due to {1}", process_id, ustr(e))
            raise ProcessInfoException("Could not get the /proc/{0}/statm due to {1}".format(process_id, ustr(e)))
        return proc_pid_rss

    @staticmethod
    def _get_proc_rss(process_id):
        """
        /proc/<pid>/statm fields: columns are (in pages):

        total program size|
        resident set size|
        shared pages|
        text (code) |
        data/stack |
        library |
        dirty pages |

        Here an example:
        root@vm:/# cat /proc/1392/statm
        17637 5316 2125 938 0 3332 0

        :return: resident set size in bytes.
        """
        pid_statm = fileutil.read_file(PROC_STATM_FILENAME_FORMAT.format(process_id)).split()
        pid_rss = int(pid_statm[1])  # Index 1 is RSS.

        return pid_rss * PAGE_SIZE


class ProcessInfo(object):
    @staticmethod
    def get_proc_name(process_id):
        proc_pid_rss = ProcessInfo._get_proc_comm(process_id)
        return proc_pid_rss

    @staticmethod
    def get_proc_cmdline(process_id):
        proc_pid_rss = ProcessInfo._get_proc_cmdline(process_id)
        return proc_pid_rss

    @classmethod
    def _get_proc_cmdline(cls, process_id):
        """
        /proc/<pid>/cmdline returns cmdline arguments passed to the Linux kernel. The returned string is delimited with
        the \0 character and needs to be replaced with some other character to make it readable.

        Here an example:
        root@vm:/# cat /proc/1392/cmdline
        python--targettest_resourceusage.py
        root@vm:/# cat /proc/1392/cmdline | tr "\0" " "
        python --target test_resourceusage.py

        :return: command line passed to the process string.
        """
        cmdline_file_name = PROC_CMDLINE_FILENAME_FORMAT.format(process_id)
        try:
            pid_cmdline = fileutil.read_file(cmdline_file_name).replace("\0", " ").strip()
        except Exception as e:
            if isinstance(e, (IOError, OSError)):
                raise
            raise ProcessInfoException("Could not get contents from {0}".format(cmdline_file_name), e)

        return pid_cmdline

    @classmethod
    def _get_proc_comm(cls, process_id):
        """
        /proc/<pid>/comm This file exposes the process's comm value-that is, the command name associated with the
        process. Strings longer than TASK_COMM_LEN (16) characters are silently truncated.

        Here an example:
        root@vm:/# cat /proc/1392/comm
        python

        :return: process name
        """
        comm_file_name = PROC_COMM_FILENAME_FORMAT.format(process_id)
        try:
            pid_comm = fileutil.read_file(comm_file_name).strip()
            pid_comm_str = str(pid_comm)
        except Exception as e:
            if isinstance(e, (IOError, OSError)):
                raise
            raise ProcessInfoException("Could not get contents from {0}".format(comm_file_name), e)

        return pid_comm_str


class ProcessInfoException(AgentError):
    """
    Exception to classify any issues when we get any issues related to fetching ProcessInfo (cmdline, comm, etc.).
    """

    def __init__(self, msg=None, inner=None):
        super(ProcessInfoException, self).__init__(msg, inner)
