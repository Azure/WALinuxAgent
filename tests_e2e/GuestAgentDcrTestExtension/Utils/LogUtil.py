# Logging utilities 
#
# Copyright 2014 Microsoft Corporation
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


import os
import os.path
import string
import sys

OutputSize = 4 * 1024


def tail(log_file, output_size = OutputSize):
    pos = min(output_size, os.path.getsize(log_file))
    with open(log_file, "r") as log:
        log.seek(0, os.SEEK_END)
        log.seek(log.tell() - pos, os.SEEK_SET)
        buf = log.read(output_size)
        buf = filter(lambda x: x in string.printable, buf)

        # encoding works different for between interpreter version, we are keeping separate implementation to ensure
        # backward compatibility
        if sys.version_info[0] == 3:
            buf = ''.join(list(buf)).encode('ascii', 'ignore').decode("ascii", "ignore")
        elif sys.version_info[0] == 2:
            buf = buf.decode("ascii", "ignore")

        return buf


def get_formatted_log(summary, stdout, stderr):
    msg_format = ("{0}\n"
                  "---stdout---\n"
                  "{1}\n"
                  "---errout---\n"
                  "{2}\n")
    return msg_format.format(summary, stdout, stderr)