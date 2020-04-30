# Copyright 2020 Microsoft Corporation
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

import datetime

from azurelinuxagent.common import logger
from azurelinuxagent.common.future import ustr


class PeriodicOperation(object):
    _LOG_WARNING_PERIOD = datetime.timedelta(minutes=60)

    def __init__(self, name, operation, period):
        self._name = name
        self._operation = operation
        self._period = period
        self._last_run = None
        self._last_log_warning = None

    def run(self):
        try:
            if self._last_run is None or datetime.datetime.utcnow() >= self._last_run + self._period:
                try:
                    self._operation()
                finally:
                    self._last_run = datetime.datetime.utcnow()
        except Exception as e:
            if self._last_log_warning is None or datetime.datetime.utcnow() >= self._last_log_warning + self._LOG_WARNING_PERIOD:
                logger.warn("Failed to {0}: {1}", self._name, ustr(e))
                self._last_log_warning = datetime.datetime.utcnow()

