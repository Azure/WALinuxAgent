# Copyright 2016 Microsoft Corporation
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

import json
import os
import tempfile
from datetime import datetime

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.event import add_log_event, TELEMETRY_LOG_EVENT_ID, TELEMETRY_LOG_PROVIDER_ID, EventLogger, \
    __event_logger__
from azurelinuxagent.common.utils import fileutil
from tests.tools import AgentTestCase, patch, MagicMock

_MSG_INFO = "This is our test info logging message {0} {1}"
_MSG_WARN = "This is our test warn logging message {0} {1}"
_MSG_ERROR = "This is our test error logging message {0} {1}"
_MSG_VERBOSE = "This is our test verbose logging message {0} {1}"
_DATA = ["arg1", "arg2"]


class TestLogger(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        self.lib_dir = tempfile.mkdtemp()
        self.event_dir = os.path.join(self.lib_dir, "events")
        fileutil.mkdir(self.event_dir)

        self.log_file = tempfile.mkstemp(prefix="logfile-")[1]

        logger.reset_periodic()

    def tearDown(self):
        AgentTestCase.tearDown(self)
        logger.reset_periodic()
        fileutil.rm_dirs(self.event_dir)

    @patch('azurelinuxagent.common.logger.Logger.verbose')
    @patch('azurelinuxagent.common.logger.Logger.warn')
    @patch('azurelinuxagent.common.logger.Logger.error')
    @patch('azurelinuxagent.common.logger.Logger.info')
    def test_periodic_emits_if_not_previously_sent(self, mock_info, mock_error, mock_warn, mock_verbose):
        logger.periodic_info(logger.EVERY_DAY, _MSG_INFO, logger.LogLevel.INFO, *_DATA)
        self.assertEqual(1, mock_info.call_count)

        logger.periodic_error(logger.EVERY_DAY, _MSG_ERROR, logger.LogLevel.ERROR, *_DATA)
        self.assertEqual(1, mock_error.call_count)

        logger.periodic_warn(logger.EVERY_DAY, _MSG_WARN, logger.LogLevel.WARNING, *_DATA)
        self.assertEqual(1, mock_warn.call_count)

        logger.periodic_verbose(logger.EVERY_DAY, _MSG_VERBOSE, logger.LogLevel.VERBOSE, *_DATA)
        self.assertEqual(1, mock_verbose.call_count)

    @patch('azurelinuxagent.common.logger.Logger.verbose')
    @patch('azurelinuxagent.common.logger.Logger.warn')
    @patch('azurelinuxagent.common.logger.Logger.error')
    @patch('azurelinuxagent.common.logger.Logger.info')
    def test_periodic_does_not_emit_if_previously_sent(self, mock_info, mock_error, mock_warn, mock_verbose):
        # The count does not increase from 1 - the first time it sends the data.
        logger.periodic_info(logger.EVERY_DAY, _MSG_INFO, *_DATA)
        self.assertIn(hash(_MSG_INFO), logger.DEFAULT_LOGGER.periodic_messages)
        self.assertEqual(1, mock_info.call_count)

        logger.periodic_info(logger.EVERY_DAY, _MSG_INFO, *_DATA)
        self.assertIn(hash(_MSG_INFO), logger.DEFAULT_LOGGER.periodic_messages)
        self.assertEqual(1, mock_info.call_count)

        logger.periodic_warn(logger.EVERY_DAY, _MSG_WARN, *_DATA)
        self.assertIn(hash(_MSG_WARN), logger.DEFAULT_LOGGER.periodic_messages)
        self.assertEqual(1, mock_warn.call_count)

        logger.periodic_warn(logger.EVERY_DAY, _MSG_WARN, *_DATA)
        self.assertIn(hash(_MSG_WARN), logger.DEFAULT_LOGGER.periodic_messages)
        self.assertEqual(1, mock_warn.call_count)

        logger.periodic_error(logger.EVERY_DAY, _MSG_ERROR, *_DATA)
        self.assertIn(hash(_MSG_ERROR), logger.DEFAULT_LOGGER.periodic_messages)
        self.assertEqual(1, mock_error.call_count)

        logger.periodic_error(logger.EVERY_DAY, _MSG_ERROR, *_DATA)
        self.assertIn(hash(_MSG_ERROR), logger.DEFAULT_LOGGER.periodic_messages)
        self.assertEqual(1, mock_error.call_count)

        logger.periodic_verbose(logger.EVERY_DAY, _MSG_VERBOSE, *_DATA)
        self.assertIn(hash(_MSG_VERBOSE), logger.DEFAULT_LOGGER.periodic_messages)
        self.assertEqual(1, mock_verbose.call_count)

        logger.periodic_verbose(logger.EVERY_DAY, _MSG_VERBOSE, *_DATA)
        self.assertIn(hash(_MSG_VERBOSE), logger.DEFAULT_LOGGER.periodic_messages)
        self.assertEqual(1, mock_verbose.call_count)

        self.assertEqual(4, len(logger.DEFAULT_LOGGER.periodic_messages))

    @patch('azurelinuxagent.common.logger.Logger.verbose')
    @patch('azurelinuxagent.common.logger.Logger.warn')
    @patch('azurelinuxagent.common.logger.Logger.error')
    @patch('azurelinuxagent.common.logger.Logger.info')
    def test_periodic_emits_after_elapsed_delta(self, mock_info, mock_error, mock_warn, mock_verbose):
        logger.periodic_info(logger.EVERY_DAY, _MSG_INFO, *_DATA)
        self.assertEqual(1, mock_info.call_count)

        logger.periodic_info(logger.EVERY_DAY, _MSG_INFO, *_DATA)
        self.assertEqual(1, mock_info.call_count)

        logger.DEFAULT_LOGGER.periodic_messages[hash(_MSG_INFO)] = datetime.now() - \
                                                                   logger.EVERY_DAY - logger.EVERY_HOUR
        logger.periodic_info(logger.EVERY_DAY, _MSG_INFO, *_DATA)
        self.assertEqual(2, mock_info.call_count)

        logger.periodic_warn(logger.EVERY_DAY, _MSG_WARN, *_DATA)
        self.assertEqual(1, mock_warn.call_count)
        logger.periodic_warn(logger.EVERY_DAY, _MSG_WARN, *_DATA)
        self.assertEqual(1, mock_warn.call_count)

        logger.DEFAULT_LOGGER.periodic_messages[hash(_MSG_WARN)] = datetime.now() - \
                                                                   logger.EVERY_DAY - logger.EVERY_HOUR
        logger.periodic_warn(logger.EVERY_DAY, _MSG_WARN, *_DATA)
        self.assertEqual(2, mock_info.call_count)

        logger.periodic_error(logger.EVERY_DAY, _MSG_ERROR, *_DATA)
        self.assertEqual(1, mock_error.call_count)
        logger.periodic_error(logger.EVERY_DAY, _MSG_ERROR, *_DATA)
        self.assertEqual(1, mock_error.call_count)

        logger.DEFAULT_LOGGER.periodic_messages[hash(_MSG_ERROR)] = datetime.now() - \
                                                                    logger.EVERY_DAY - logger.EVERY_HOUR
        logger.periodic_error(logger.EVERY_DAY, _MSG_ERROR, *_DATA)
        self.assertEqual(2, mock_info.call_count)

        logger.periodic_verbose(logger.EVERY_DAY, _MSG_VERBOSE, *_DATA)
        self.assertEqual(1, mock_verbose.call_count)
        logger.periodic_verbose(logger.EVERY_DAY, _MSG_VERBOSE, *_DATA)
        self.assertEqual(1, mock_verbose.call_count)

        logger.DEFAULT_LOGGER.periodic_messages[hash(_MSG_VERBOSE)] = datetime.now() - \
                                                                      logger.EVERY_DAY - logger.EVERY_HOUR
        logger.periodic_verbose(logger.EVERY_DAY, _MSG_VERBOSE, *_DATA)
        self.assertEqual(2, mock_info.call_count)

    @patch('azurelinuxagent.common.logger.Logger.verbose')
    @patch('azurelinuxagent.common.logger.Logger.warn')
    @patch('azurelinuxagent.common.logger.Logger.error')
    @patch('azurelinuxagent.common.logger.Logger.info')
    def test_periodic_forwards_message_and_args(self, mock_info, mock_error, mock_warn, mock_verbose):
        logger.periodic_info(logger.EVERY_DAY, _MSG_INFO, *_DATA)
        mock_info.assert_called_once_with(_MSG_INFO, *_DATA)

        logger.periodic_error(logger.EVERY_DAY, _MSG_ERROR, *_DATA)
        mock_error.assert_called_once_with(_MSG_ERROR, *_DATA)

        logger.periodic_warn(logger.EVERY_DAY, _MSG_WARN, *_DATA)
        mock_warn.assert_called_once_with(_MSG_WARN, *_DATA)

        logger.periodic_verbose(logger.EVERY_DAY, _MSG_VERBOSE, *_DATA)
        mock_verbose.assert_called_once_with(_MSG_VERBOSE, *_DATA)

    def test_telemetry_logger(self):
        mock = MagicMock()
        appender = logger.TelemetryAppender(logger.LogLevel.WARNING, mock)

        appender.write(logger.LogLevel.WARNING, "--unit-test-WARNING--")
        mock.assert_called_with(logger.LogLevel.WARNING, "--unit-test-WARNING--")
        mock.reset_mock()

        appender.write(logger.LogLevel.ERROR, "--unit-test-ERROR--")
        mock.assert_called_with(logger.LogLevel.ERROR, "--unit-test-ERROR--")
        mock.reset_mock()

        appender.write(logger.LogLevel.INFO, "--unit-test-INFO--")
        mock.assert_not_called()
        mock.reset_mock()

        for i in range(5):
            appender.write(logger.LogLevel.ERROR, "--unit-test-ERROR--")
            appender.write(logger.LogLevel.INFO, "--unit-test-INFO--")

        self.assertEquals(5, mock.call_count)  # Only ERROR should be called.

    @patch("azurelinuxagent.common.event.send_logs_to_telemetry", return_value=True)
    @patch('azurelinuxagent.common.event.EventLogger.save_event')
    def test_telemetry_logger_sending_correct_fields(self, mock_save, patch_conf_get_logs_to_telemetry):
        appender = logger.TelemetryAppender(logger.LogLevel.WARNING, add_log_event)
        appender.write(logger.LogLevel.WARNING, 'Cgroup controller "memory" is not mounted. '
                                                'Failed to create a cgroup for extension '
                                                'Microsoft.OSTCExtensions.DummyExtension-1.2.3.4')

        self.assertEqual(1, mock_save.call_count)
        telemetry_json = json.loads(mock_save.call_args[0][0])

        self.assertEqual(TELEMETRY_LOG_PROVIDER_ID, telemetry_json['providerId'])
        self.assertEqual(TELEMETRY_LOG_EVENT_ID, telemetry_json['eventId'])

        self.assertEqual(12, len(telemetry_json['parameters']))
        for x in telemetry_json['parameters']:
            if x['name'] == 'EventName':
                self.assertEqual(x['value'], 'Log')
            elif x['name'] == 'CapabilityUsed':
                self.assertEqual(x['value'], 'WARNING')
            elif x['name'] == 'Context1':
                self.assertEqual(x['value'], 'Cgroup controller "memory" is not mounted. '
                                             'Failed to create a cgroup for extension '
                                             'Microsoft.OSTCExtensions.DummyExtension-1.2.3.4')
            elif x['name'] == 'Context2':
                self.assertEqual(x['value'], '')
            elif x['name'] == 'Context3':
                self.assertEqual(x['value'], '')

    @patch('azurelinuxagent.common.event.EventLogger.save_event')
    def test_telemetry_logger_not_on_by_default(self, mock_save):
        appender = logger.TelemetryAppender(logger.LogLevel.WARNING, add_log_event)
        appender.write(logger.LogLevel.WARNING, 'Cgroup controller "memory" is not mounted. '
                                                'Failed to create a cgroup for extension '
                                                'Microsoft.OSTCExtensions.DummyExtension-1.2.3.4')
        self.assertEqual(0, mock_save.call_count)

    @patch("azurelinuxagent.common.event.send_logs_to_telemetry", return_value=True)
    @patch('azurelinuxagent.common.logger.Logger.error')
    @patch('azurelinuxagent.common.logger.Logger.warn')
    def test_telemetry_logger_verify_not_logging_errors_warnings(self, mock_warn, mock_error, *args):
        appender = logger.TelemetryAppender(logger.LogLevel.WARNING, add_log_event)

        with patch('azurelinuxagent.common.event.EventLogger.save_event') as mock_save:
            appender.write(logger.LogLevel.WARNING, 'Cgroup controller "memory" is not mounted. '
                                                    'Microsoft.OSTCExtensions.DummyExtension-1.2.3.4')
            self.assertEqual(1, mock_save.call_count)
            self.assertEqual(0, mock_warn.call_count)
            self.assertEqual(0, mock_error.call_count)

        # Writing 2000 events should generate only one more log event due to too many files. #1035 was caused due to
        # too many files being written in an error condition (earlier code would write 1000 files in this case).
        for _ in range(2000):
            appender.write(logger.LogLevel.WARNING, 'Cgroup controller "memory" is not mounted. '
                                                    'Microsoft.OSTCExtensions.DummyExtension-1.2.3.4')

        self.assertEqual(1, mock_warn.call_count)
        self.assertEqual(0, mock_error.call_count)

    @patch("azurelinuxagent.common.event.send_logs_to_telemetry", return_value=True)
    def test_telemetry_logger_verify_maximum_recursion_depths_doesnt_happen(self, *_):
        logger.add_logger_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, path="/dev/null")
        logger.add_logger_appender(logger.AppenderType.TELEMETRY, logger.LogLevel.WARNING, path=add_log_event)

        # Calling logger.warn 1000 times would cause the telemetry appender to writing 1000 events into the events dir.
        for _ in range(1000):
            logger.warn('Test Log - Warning')

        exception_caught = False

        # #1035 was caused due to too many files being written in an error condition. Adding one more here would break
        # the camels back earlier. This should be resolved now.
        try:
            for _ in range(1000):
                logger.warn('Test Log - Warning')
        except RuntimeError:
            exception_caught = True

        self.assertFalse(exception_caught, msg="Caught a Runtime Error")

    @patch("azurelinuxagent.common.event.send_logs_to_telemetry", return_value=True)
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_telemetry_logger_verifying_all_logs_get_written(self, mock_lib_dir, *_):
        mock_lib_dir.return_value = self.lib_dir
        __event_logger__.event_dir = self.event_dir
        no_of_log_statements = 1100

        logger.add_logger_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, path=self.log_file)
        logger.add_logger_appender(logger.AppenderType.TELEMETRY, logger.LogLevel.WARNING, path=add_log_event)
        exception_caught = False

        # Calling logger.warn 1100 times would cause the telemetry appender to writing 1000 events into the events dir,
        # and then drop the remaining 100 events. It sould not generate the RuntimeError
        try:
            for i in range(0, no_of_log_statements):
                logger.warn('Test Log - {0} - 1 - Warning'.format(i))
        except RuntimeError:
            exception_caught = True

        self.assertFalse(exception_caught, msg="Caught a Runtime Error")
        self.assertEqual(1000, len(os.listdir(__event_logger__.event_dir)))

        try:
            with open(self.log_file) as logfile:
                logcontent = logfile.readlines()

                # Checking the last log entry.
                # Subtracting 1 as range is exclusive of the upper bound
                self.assertIn("WARNING Test Log - {0} - 1 - Warning".format(no_of_log_statements - 1), logcontent[-1])
        except Exception as e:
            self.assertFalse(True, "The log file looks like it isn't correctly setup for this test. Take a look. {0}".format(e))
