# Compose Content for: L2-platform/archive-operations.md

Total files: 1

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/utils/archive.py.ARCHIVE_DIRECTORY_NAME`
- `%REPO%/azurelinuxagent/common/utils/archive.py._PLACEHOLDER_FILE_NAME`
- `%REPO%/azurelinuxagent/common/utils/archive.py._MAX_ARCHIVED_STATES`
- `%REPO%/azurelinuxagent/common/utils/archive.py._CACHE_PATTERNS`
- `%REPO%/azurelinuxagent/common/utils/archive.py._ARCHIVE_BASE_PATTERN`
- `%REPO%/azurelinuxagent/common/utils/archive.py._ARCHIVE_PATTERNS_DIRECTORY`
- `%REPO%/azurelinuxagent/common/utils/archive.py._ARCHIVE_PATTERNS_ZIP`
- `%REPO%/azurelinuxagent/common/utils/archive.py._GOAL_STATE_FILE_NAME`
- `%REPO%/azurelinuxagent/common/utils/archive.py._VM_SETTINGS_FILE_NAME`
- `%REPO%/azurelinuxagent/common/utils/archive.py._CERTIFICATES_FILE_NAME`
- `%REPO%/azurelinuxagent/common/utils/archive.py._HOSTING_ENV_FILE_NAME`
- `%REPO%/azurelinuxagent/common/utils/archive.py._REMOTE_ACCESS_FILE_NAME`
- `%REPO%/azurelinuxagent/common/utils/archive.py._EXT_CONF_FILE_NAME`
- `%REPO%/azurelinuxagent/common/utils/archive.py._MANIFEST_FILE_NAME`
- `%REPO%/azurelinuxagent/common/utils/archive.py.AGENT_STATUS_FILE`
- `%REPO%/azurelinuxagent/common/utils/archive.py.SHARED_CONF_FILE_NAME`
- `%REPO%/azurelinuxagent/common/utils/archive.py.State`
- `%REPO%/azurelinuxagent/common/utils/archive.py.State.__init__`
- `%REPO%/azurelinuxagent/common/utils/archive.py.State.__init__.self`
- `%REPO%/azurelinuxagent/common/utils/archive.py.State.__init__.path`
- `%REPO%/azurelinuxagent/common/utils/archive.py.State.__init__.ti

### Source excerpt

````
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import errno
import glob
import os
import re
import shutil
import zipfile

from azurelinuxagent.common import conf
from azurelinuxagent.common import logger
from azurelinuxagent.common.utils import fileutil

# pylint: disable=W0105

"""
archive.py

The module supports the archiving of guest agent state. Guest
agent state is flushed whenever there is a incarnation change.
The flush is archived periodically (once a day).

The process works as follows whenever a new incarnation arrives.

 1. Flush - move all state files to a new directory under
 .../history/timestamp/.
 2. Archive - enumerate all directories under .../history/timestamp
 and create a .zip file named timestamp.zip.  Delete the archive
 directory
 3. Purge - glob the list .zip files, sort by timestamp in descending
 order, keep the first 50 results, and delete the rest.

... is the directory where the agent's state resides, by default this
is /var/lib/waagent.

The timestamp is an ISO8601 formatted value.
"""
# pylint: enable=W0105

ARCHIVE_DIRECTORY_NAME = 'history'

# TODO: See comment in GoalStateHistory._save_placeholder and remove this code when no longer needed
_PLACEHOLDER_FILE_NAME = 'GoalState.1.xml'
# END TODO

_MAX_ARCHIVED_STATES = 50

_CACHE_PATTERNS = [
    #
    # Note that SharedConfig.xml is not included here; this file is used by other components (Azsec and Singularity/HPC Infiniband)
    #
    re.compile(r"^VmSettings\.\d+\.json$"),
    re.compile(r"^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(xml)$", re.IGNORECASE),
    re.compile(r"^HostingEnvironmentConfig\.xml$", re.IGNORECASE),
    re.compile(r"^RemoteAccess\.xml$", re.IGNORECASE),
    re.compile(r"^waagent_status\.\d+\.json$"),
]

#
# Legacy names
#   2018-04-06T08:21:37.142697
#   2018-04-06T08:21:37.142697.zip
#   2018-04-06T08:21:37.142697_incarnation_N
#   2018-04-06T08:21:37.142697_incarnation_N.zip
#   2018-04-06T08:21:37.142697_N-M
#   2018-04-06T08:21:37.142697_N-M.zip
#
# Current names
#
#   2018-04-06T08-21-37__N-M
#   2
````

---
