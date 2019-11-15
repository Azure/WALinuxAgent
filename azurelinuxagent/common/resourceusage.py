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
from resource import RUSAGE_SELF, getrusage

from azurelinuxagent.common import logger
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logger import EVERY_SIX_HOURS
from azurelinuxagent.common.utils import fileutil


PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')
PROC_STATM_FILENAME_FORMAT = "/proc/{0}/statm"


class ResourceUsage(object):
    pass


class MemoryResourceUsage(ResourceUsage):
    @staticmethod
    def get_memory_usage_from_proc_statm(process_id):
        proc_pid_rss = 0
        try:
            proc_pid_rss = MemoryResourceUsage._get_proc_rss(process_id)
        except Exception as e:
            logger.periodic_info(EVERY_SIX_HOURS, "[PERIODIC] Could not get the /prod/{0}/statm data due to {1}",
                                 process_id, ustr(e))

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
        try:
            pid_statm = fileutil.read_file(PROC_STATM_FILENAME_FORMAT.format(process_id)).split()
            pid_rss = int(pid_statm[1])  # Index 1 is RSS.
        except Exception:
            raise

        return pid_rss * PAGE_SIZE
