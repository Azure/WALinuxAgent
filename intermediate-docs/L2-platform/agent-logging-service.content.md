# Compose Content for: L2-platform/agent-logging-service.md

Total files: 2

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/utils/textutil.py.redact_sas_token`
- `%REPO%/azurelinuxagent/common/logger.py.EVERY_DAY`
- `%REPO%/azurelinuxagent/common/logger.py.EVERY_HALF_DAY`
- `%REPO%/azurelinuxagent/common/logger.py.EVERY_SIX_HOURS`
- `%REPO%/azurelinuxagent/common/logger.py.EVERY_HOUR`
- `%REPO%/azurelinuxagent/common/logger.py.EVERY_HALF_HOUR`
- `%REPO%/azurelinuxagent/common/logger.py.EVERY_FIFTEEN_MINUTES`
- `%REPO%/azurelinuxagent/common/logger.py.EVERY_MINUTE`
- `%REPO%/azurelinuxagent/common/logger.py.Logger`
- `%REPO%/azurelinuxagent/common/logger.py.Logger.__init__`
- `%REPO%/azurelinuxagent/common/logger.py.Logger.__init__.self`
- `%REPO%/azurelinuxagent/common/logger.py.Logger.__init__.logger`
- `%REPO%/azurelinuxagent/common/logger.py.Logger.__init__.prefix`
- `%REPO%/azurelinuxagent/common/logger.py.Logger.reset_periodic`
- `%REPO%/azurelinuxagent/common/logger.py.Logger.reset_periodic.self`
- `%REPO%/azurelinuxagent/common/logger.py.Logger.set_prefix`
- `%REPO%/azurelinuxagent/common/logger.py.Logger.set_prefix.self`
- `%REPO%/azurelinuxagent/common/logger.py.Logger.set_prefix.prefix`
- `%REPO%/azurelinuxagent/common/logger.py.Logger._is_period_elapsed`
- `%REPO%/azurelinuxagent/common/logger.py.Logger._is_period_elapsed.self`
- `%REPO%/azurelinuxagent/common/logger.py.Logger._is_period_elapsed.delta`
- `%REPO%/azurelinuxagent/common/logger.py.Logger._is_period_elapsed.h`
- `%REPO%/azurelinuxagent/common/logger.py.Logger._periodic`
- `%REPO%/azurelinuxa

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
# Requires Python 2.6+ and openssl_bin 1.0+
#
"""
Log utils
"""
import sys
from datetime import datetime, timedelta
from threading import current_thread

from azurelinuxagent.common.future import ustr, UTC
from azurelinuxagent.common.utils import timeutil
from azurelinuxagent.common.utils.textutil import redact_sas_token

EVERY_DAY = timedelta(days=1)
EVERY_HALF_DAY = timedelta(hours=12)
EVERY_SIX_HOURS = timedelta(hours=6)
EVERY_HOUR = timedelta(hours=1)
EVERY_HALF_HOUR = timedelta(minutes=30)
EVERY_FIFTEEN_MINUTES = timedelta(minutes=15)
EVERY_MINUTE = timedelta(minutes=1)


class Logger(object):
    """
    Logger class
    """
    def __init__(self, logger=None, prefix=None):
        self.appenders = []
        self.logger = self if logger is None else logger
        self.periodic_messages = {}
        self.prefix = prefix
        self.silent = False

    def reset_periodic(self):
        self.logger.periodic_messages = {}

    def set_prefix(self, prefix):
        self.prefix = prefix

    def _is_period_elapsed(self, delta, h):
        return h not in self.logger.periodic_messages or \
            (self.logger.periodic_messages[h] + delta) <= datetime.now(UTC)

    def _periodic(self, delta, log_level_op, msg_format, *args):
        h = hash(msg_format)
        if self._is_period_elapsed(delta, h):
            log_level_op(msg_format, *args)
            self.logger.periodic_messages[h] = datetime.now(UTC)

    def periodic_info(self, delta, msg_format, *args):
        self._periodic(delta, self.info, msg_format, *args)

    def periodic_verbose(self, delta, msg_format, *args):

````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/pa/provision/cloudinitdetect.py._cloud_init_is_enabled_systemd`
- `%REPO%/azurelinuxagent/common/logger.py.info`
- `%REPO%/azurelinuxagent/pa/provision/cloudinitdetect.py._cloud_init_is_enabled_service`
- `%REPO%/azurelinuxagent/pa/provision/cloudinitdetect.py.cloud_init_is_enabled`

### Source excerpt

````
"""Module for detecting the existence of cloud-init"""

import subprocess
import azurelinuxagent.common.logger as logger

def _cloud_init_is_enabled_systemd():
    """
    Determine whether or not cloud-init is enabled on a systemd machine.

    Args:
        None

    Returns:
        bool: True if cloud-init is enabled, False if otherwise.
    """

    try:
        systemctl_output = subprocess.check_output([
            'systemctl',
            'is-enabled',
            'cloud-init-local.service'
        ], stderr=subprocess.STDOUT).decode('utf-8').replace('\n', '')

        unit_is_enabled = systemctl_output == 'enabled'
    # pylint: disable=broad-except
    except Exception as exc:
        logger.info('Unable to get cloud-init enabled status from systemctl: {0}'.format(exc))
        unit_is_enabled = False

    return unit_is_enabled

def _cloud_init_is_enabled_service():
    """
    Determine whether or not cloud-init is enabled on a non-systemd machine.

    Args:
        None

    Returns:
        bool: True if cloud-init is enabled, False if otherwise.
    """

    for service_name in ['cloud-init', 'cloudinit']:
        try:
            subprocess.check_output([
                'service',
                service_name,
                'status'
            ], stderr=subprocess.STDOUT)
            return True
        # pylint: disable=broad-except
        except Exception as exc:
            logger.info('Tried service "{0}", unable to get enabled status: {1}'.format(service_name, exc))

    return False

def cloud_init_is_enabled():
    """
    Determine whether or not cloud-init is enabled.

    Args:
        None

    Returns:
        bool: True if cloud-init is enabled, False if otherwise.
    """

    unit_is_enabled = _cloud_init_is_enabled_systemd() or _cloud_init_is_enabled_service()
    logger.info('cloud-init is enabled: {0}'.format(unit_is_enabled))

    return unit_is_enabled

````

---
