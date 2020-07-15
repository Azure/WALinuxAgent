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
from azurelinuxagent.common.future import ustr


class PeriodicOperation(object):
    '''
    Instances of PeriodicOperation are tasks that are executed only after the given
    time period has elapsed.

    NOTE: the run() method catches any exceptions raised by the operation and logs them as warnings.
    '''

    # To prevent flooding the log with error messages we report failures at most every hour
    _LOG_WARNING_PERIOD = datetime.timedelta(minutes=60)

    def __init__(self, name, operation, period):
        self._name = name
        self._operation = operation
        self._period = period if isinstance(period, datetime.timedelta) else datetime.timedelta(seconds=period)
        self._next_run_time = datetime.datetime.utcnow()
        self._last_warning = None
        self._last_warning_time = None

    def run(self):
        try:
            if self._next_run_time <= datetime.datetime.utcnow():
                try:
                    self._operation()
                finally:
                    self._next_run_time = datetime.datetime.utcnow() + self._period
        except Exception as e:
            warning = "Failed to {0}: {1} --- [NOTE: Will not log the same error for the next hour]".format(self._name, ustr(e))
            if warning != self._last_warning or self._last_warning_time is None or datetime.datetime.utcnow() >= self._last_warning_time + self._LOG_WARNING_PERIOD:
                logger.warn(warning)
                self._last_warning_time = datetime.datetime.utcnow()
                self._last_warning = warning

    def next_run_time(self):
        return self._next_run_time

    @staticmethod
    def sleep_until_next_operation(operations):
        """
        Takes a list of operations, finds the operation that should be executed next (that with the closest next_run_time)
        and sleeps until it is time to execute that operation.
        """
        next_operation_time = min([op.next_run_time() for op in operations])

        sleep_timedelta = next_operation_time - datetime.datetime.utcnow()
        # timedelta.total_seconds() is not available on Python 2.6, do the computation manually
        sleep_seconds = ((sleep_timedelta.days * 24 * 3600 + sleep_timedelta.seconds) * 10.0 ** 6 + sleep_timedelta.microseconds) / 10.0 ** 6

        if sleep_seconds > 0:
            time.sleep(sleep_seconds)

