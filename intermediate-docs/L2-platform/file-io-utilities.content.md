# Compose Content for: L2-platform/file-io-utilities.md

Total files: 1

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/utils/fileutil.py.KNOWN_IOERRORS`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.read_file`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.read_file.filepath`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.read_file.asbin`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.read_file.remove_bom`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.read_file.encoding`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.remove_bom`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.write_file`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.write_file.filepath`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.write_file.contents`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.write_file.asbin`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.write_file.encoding`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.write_file.append`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.append_file`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.append_file.filepath`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.append_file.contents`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.append_file.asbin`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.append_file.encoding`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.base_name`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.base_name.path`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.get_line_startingwith`
- `%REPO%/azurelinuxagent/common/utils/fileutil.py.

### Source excerpt

````
# Microsoft Azure Linux Agent
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
# Requires Python 2.6+ and Openssl 1.0+
#

"""
File operation util functions
"""

import errno as errno
import glob
import os
import pwd
import re
import shutil

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.textutil as textutil

from azurelinuxagent.common.future import ustr

KNOWN_IOERRORS = [
    errno.EIO,          # I/O error
    errno.ENOMEM,       # Out of memory
    errno.ENFILE,       # File table overflow
    errno.EMFILE,       # Too many open files
    errno.ENOSPC,       # Out of space
    errno.ENAMETOOLONG, # Name too long
    errno.ELOOP,        # Too many symbolic links encountered
    121                 # Remote I/O error (errno.EREMOTEIO -- not present in all Python 2.7+)
]


def read_file(filepath, asbin=False, remove_bom=False, encoding='utf-8'):
    """
    Read and return contents of 'filepath'.
    """
    mode = 'rb'
    with open(filepath, mode) as in_file:
        data = in_file.read()
        if data is None:
            return None

        if asbin:
            return data

        if remove_bom:
            # remove bom on bytes data before it is converted into string.
            data = textutil.remove_bom(data)
        data = ustr(data, encoding=encoding)
        return data


def write_file(filepath, contents, asbin=False, encoding='utf-8', append=False):
    """
    Write 'contents' to 'filepath'.
    """
    mode = "ab" if append else "wb"
    data = contents
    if not asbin:
        data = contents.encode(encoding)
    with open(filepath, mode) as out_file:
        out_file.write(
````

---
