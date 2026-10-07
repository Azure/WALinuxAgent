# Compose Content for: L1-conceptual/periodic-operation-runner.md

Total files: 1

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation._LOG_WARNING_PERIOD`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation.__init__`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation.__init__.self`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation.__init__.period`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation.run`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation.run.self`
- `%REPO%/azurelinuxagent/common/logger.py.verbose`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation._operation`
- `%REPO%/azurelinuxagent/common/logger.py.warn`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation.next_run_time`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation.next_run_time.self`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation._operation.self`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation.sleep_until_next_operation`
- `%REPO%/azurelinuxagent/ga/periodic_operation.py.PeriodicOperation.sleep_until_next_operation.operations`

### Source excerpt

````
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
import time

from azurelinuxagent.common import logger
from azurelinuxagent.common.future import ustr, UTC


class PeriodicOperation(object):
    '''
    Instances of PeriodicOperation are tasks that are executed only after the given
    time period has elapsed.

    NOTE: the run() method catches any exceptions raised by the operation and logs them as warnings.
    '''

    # To prevent flooding the log with error messages we report failures at most every hour
    _LOG_WARNING_PERIOD = datetime.timedelta(minutes=60)

    def __init__(self, period):
        self._name = self.__class__.__name__
        self._period = period if isinstance(period, datetime.timedelta) else datetime.timedelta(seconds=period)
        self._next_run_time = datetime.datetime.now(UTC)
        self._last_warning = None
        self._last_warning_time = None

    def run(self):
        try:
            if self._next_run_time <= datetime.datetime.now(UTC):
                try:
                    logger.verbose("Executing {0}...", self._name)
                    self._operation()
                finally:
                    self._next_run_time = datetime.datetime.now(UTC) + self._period
        except Exception as e:
            warning = "Error in {0}: {1} --- [NOTE: Will not log the same error for the next hour]".format(self._name, ustr(e))
            if warning != self._last_warning or self._last_warning_time is None or datetime.datetime.now(UTC) >= self._last_warning_time + self._LOG_WARNING_PERIOD:
                logger.warn(warning)

````

---
