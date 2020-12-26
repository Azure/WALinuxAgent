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
from azurelinuxagent.ga.monitor import PeriodicOperation
from tests.tools import AgentTestCase, patch, PropertyMock


class TestPeriodicOperation(AgentTestCase):
    def test_it_should_take_a_timedelta_as_period(self):
        def operation():
            operation.run_time = datetime.datetime.utcnow()
        operation.run_time = None

        op = PeriodicOperation("test_operation", operation, period=datetime.timedelta(hours=1))
        op.run()

        expected = operation.run_time + datetime.timedelta(hours=1)
        difference = op.next_run_time() - expected
        self.assertTrue(difference < datetime.timedelta(seconds=1),
            "The next run time exceeds the expected value by more than 1 second: {0} vs {1}".format(op.next_run_time(), expected))

    def test_it_should_take_a_number_of_seconds_as_period(self):
        def operation():
            operation.run_time = datetime.datetime.utcnow()
        operation.run_time = None

        op = PeriodicOperation("test_operation", operation, period=3600)
        op.run()

        expected = operation.run_time + datetime.timedelta(hours=1)
        difference = op.next_run_time() - expected
        self.assertTrue(difference < datetime.timedelta(seconds=1),
            "The next run time exceeds the expected value by more than 1 second: {0} vs {1}".format(op.next_run_time(), expected))

    def test_it_should_be_invoked_when_run_is_called_first_time(self):
        def operation():
            operation.invoked = True
        operation.invoked = False

        PeriodicOperation("test_operation", operation, period=datetime.timedelta(hours=1)).run()

        self.assertTrue(operation.invoked, "The operation was not invoked")

    def test_it_should_not_be_invoked_if_the_period_has_not_elapsed(self):
        def operation():
            operation.invoked_count += 1
        operation.invoked_count = 0

        pop = PeriodicOperation("test_operation", operation, period=datetime.timedelta(hours=1))
        for _ in range(5):
            pop.run()

        # the first run() invoked the operation, so the count is 1
        self.assertEqual(operation.invoked_count, 1, "The operation was invoked before the period elapsed")

    def test_it_should_be_invoked_if_the_period_has_elapsed(self):
        def operation():
            operation.invoked_count += 1
        operation.invoked_count = 0

        pop = PeriodicOperation("test_operation", operation, period=datetime.timedelta(milliseconds=1))
        for _ in range(5):
            pop.run()
            time.sleep(0.001)

        self.assertEqual(operation.invoked_count, 5, "The operation was not invoked after the period elapsed")

    @staticmethod
    def _operation_with_failure():
        raise Exception("A test exception")

    @staticmethod
    def _get_number_of_warnings(warn_patcher, message="A test exception"):
        return len([args for args, _ in warn_patcher.call_args_list if any(message in a for a in args)])

    def test_it_should_log_a_warning_if_the_operation_fails(self):
        with patch("azurelinuxagent.common.logger.warn") as warn_patcher:
            PeriodicOperation("test_operation", self._operation_with_failure, period=datetime.timedelta(hours=1)).run()

        self.assertEqual(self._get_number_of_warnings(warn_patcher), 1, "The error in the operation was should have been reported exactly once")

    def test_it_should_not_log_multiple_warnings_when_the_period_has_not_elapsed(self):
        with patch("azurelinuxagent.common.logger.warn") as warn_patcher:
            pop = PeriodicOperation("test_operation", self._operation_with_failure, period=datetime.timedelta(hours=1))
            for _ in range(5):
                pop.run()

        self.assertEqual(self._get_number_of_warnings(warn_patcher), 1, "The error in the operation was should have been reported exactly once")

    def test_it_should_not_log_multiple_warnings_when_the_period_has_elapsed(self):
        with patch("azurelinuxagent.common.logger.warn") as warn_patcher:
            with patch("azurelinuxagent.ga.periodic_operation.PeriodicOperation._LOG_WARNING_PERIOD", new_callable=PropertyMock, return_value=datetime.timedelta(milliseconds=1)):
                pop = PeriodicOperation("test_operation", self._operation_with_failure, period=datetime.timedelta(milliseconds=1))
                for _ in range(5):
                    pop.run()
                    time.sleep(0.001)

            self.assertEqual(self._get_number_of_warnings(warn_patcher), 5, "The error in the operation was not reported the expected number of times")

    def test_it_should_log_warnings_if_they_are_different(self):
        with patch("azurelinuxagent.common.logger.warn") as warn_patcher:
            for i in range(2):
                def operation():
                    raise Exception("WARNING {0}".format(i))  # pylint: disable=cell-var-from-loop

                pop = PeriodicOperation("test_operation", operation, period=datetime.timedelta(hours=1))
                for _ in range(5):
                    pop.run()

            self.assertEqual(self._get_number_of_warnings(warn_patcher, "WARNING 0"), 1, "The first error should have been reported exactly 1 time")
            self.assertEqual(self._get_number_of_warnings(warn_patcher, "WARNING 1"), 1, "The second error should have been reported exactly 1 time")

    def test_sleep_until_next_operation_should_wait_for_the_closest_operation(self):
        operations = [
            PeriodicOperation("one", lambda: None, period=datetime.timedelta(seconds=60)),
            PeriodicOperation("one", lambda: None, period=datetime.timedelta(hours=1)),
            PeriodicOperation("one", lambda: None, period=datetime.timedelta(seconds=10)),  # closest operation
            PeriodicOperation("one", lambda: None, period=datetime.timedelta(minutes=11)),
            PeriodicOperation("one", lambda: None, period=datetime.timedelta(days=1))
        ]
        for op in operations:
            op.run()

        def mock_sleep(seconds):
            mock_sleep.seconds = seconds
        mock_sleep.seconds = 0

        with patch("azurelinuxagent.ga.periodic_operation.time.sleep", side_effect=mock_sleep):
            PeriodicOperation.sleep_until_next_operation(operations)
            self.assertAlmostEqual(mock_sleep.seconds, 10, 0, "did not sleep for the expected time")


