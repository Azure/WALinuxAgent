# Compose Content for: L2-platform/shell-command-validation.md

Total files: 3

---

## setup.py

### Structural symbols

- `TimeoutExpired`
- `check_output`
- `check_output.popenargs`
- `check_output.kwargs`
- `CalledProcessError`
- `CalledProcessError.__init__`
- `CalledProcessError.__init__.self`
- `CalledProcessError.__init__.returncode`
- `CalledProcessError.__init__.cmd`
- `CalledProcessError.__init__.output`
- `CalledProcessError.__str__`
- `CalledProcessError.__str__.self`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.has_command`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.has_command.cmd`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run.cmd`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run.chk_err`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run.expected_errors`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output.cmd`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output.chk_err`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output.log_cmd`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_get_output.expected_errors`
- `%REPO%/azurelinuxagent/common/logger.py.verbose`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py._popen`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py._on_command_completed`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.__encode_command_output`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/common/logger.py.error`
- `%REP

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
import os
import subprocess
import sys
import tempfile
import threading

if sys.version_info[0] == 2:
    # TimeoutExpired was introduced on Python 3; define a dummy class for Python 2
    class TimeoutExpired(Exception):
        pass
else:
    from subprocess import TimeoutExpired

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr


if not hasattr(subprocess, 'check_output'):
    def check_output(*popenargs, **kwargs):
        r"""Backport from subprocess module from python 2.7"""
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, '
                             'it will be overridden.')
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise subprocess.CalledProcessError(retcode, cmd, output=output)
        return output


    # Exception classes used by this module.
    class CalledProcessError(Exception):
        def __init__(self, returncode, cmd, output=None):  # pylint: disable=W0231
            self.returncode = returncode
            self.cmd = cmd
            self.output = output

        def __str__(self):
            return ("Command '{0}' returned non-zero exit status {1}"
                    "").format(self.cmd, self.returncode)


    subprocess.check_output = check_output

````

---

## setup.py

### Structural symbols

N/A

### Source excerpt

````
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


````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/utils/shellutil.py.run_command`
- `%REPO%/azurelinuxagent/common/utils/shellutil.py.CommandError`
- `%REPO%/azurelinuxagent/common/exception.py.AgentError`
- `%REPO%/azurelinuxagent/ga/signing_certificate_util.py.get_microsoft_signing_certificate_path`
- `%REPO%/azurelinuxagent/common/utils/flexible_version.py.FlexibleVersion`
- `%REPO%/azurelinuxagent/common/future.py.datetime_min_utc`
- `%REPO%/azurelinuxagent/common/event.py.add_event`
- `%REPO%/azurelinuxagent/common/event.py.WALAEventOperation`
- `%REPO%/azurelinuxagent/common/event.py.elapsed_milliseconds`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_VERSION`
- `%REPO%/azurelinuxagent/common/version.py.AGENT_NAME`
- `%REPO%/azurelinuxagent/ga/signature_validation_util.py._PACKAGE_VALIDATION_STATE_FILE`
- `%REPO%/azurelinuxagent/ga/signature_validation_util.py._MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION`
- `%REPO%/azurelinuxagent/ga/signature_validation_util.py.PackageValidationError`
- `%REPO%/azurelinuxagent/ga/signature_validation_util.py.PackageValidationError.__init__`
- `%REPO%/azurelinuxagent/ga/signature_validation_util.py.PackageValidationError.__init__.self`
- `%REPO%/azurelinuxagent/ga/signature_validation_util.py.PackageValidationError.__init__.msg`
- `%REPO%/azurelinuxagent/ga/signature_validation_util.py.PackageValidationError.__init__.inner`
- `%REPO%/azurelinuxagent/ga/signature_validation_util.py.PackageValidationError.__init__.code`
- `%REPO%/azurelinuxagent/ga/signatur

### Source excerpt

````
# Windows Azure Linux Agent
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
import base64
import datetime
import os
import re
import uuid

from azurelinuxagent.common import conf
from azurelinuxagent.common.utils.shellutil import run_command, CommandError
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common import logger
from azurelinuxagent.ga.signing_certificate_util import get_microsoft_signing_certificate_path
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.future import ustr, UTC, datetime_min_utc
from azurelinuxagent.common.event import add_event, WALAEventOperation, elapsed_milliseconds
from azurelinuxagent.common.version import AGENT_VERSION, AGENT_NAME, AGENT_SIGNING_INFO_NAME
from azurelinuxagent.ga.cgroupconfigurator import CGroupConfigurator, PKG_SIGNATURE_VALIDATION_CPU_QUOTA, PKG_SIGNATURE_VALIDATION_SLICE_NAME, PKG_SIGNATURE_VALIDATION_CGROUPS_UNIT_NAME, DisableCgroups
from azurelinuxagent.common.osutil.systemd import is_systemd_run_failure
from azurelinuxagent.ga.confidential_vm_info import ConfidentialVMInfo


# Signature validation requires OpenSSL version 1.1.0 or later. The 'no_check_time' flag used for the 'openssl cms -verify'
# command is not supported on older versions.
_MIN_OPENSSL_VERSION_FOR_SIG_VALIDATION = FlexibleVersion("1.1.0")

# Track the time when the agent module is first loaded. This is used to implement an initial delay period before validating signature.
# TODO: This is a temporary performance workaround for telemetry release; remove for production release.
_agent_star
````

---
