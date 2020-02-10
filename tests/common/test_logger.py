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
from datetime import datetime, timedelta

from azurelinuxagent.common.event import __event_logger__, add_log_event, MAX_NUMBER_OF_EVENTS, TELEMETRY_LOG_EVENT_ID,\
    TELEMETRY_LOG_PROVIDER_ID
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.utils import fileutil
from tests.tools import AgentTestCase, MagicMock, patch, skip_if_predicate_true

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
        logger.DEFAULT_LOGGER.appenders *= 0
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

    def test_logger_should_log_in_utc(self):
        file_name = "test.log"
        file_path = os.path.join(self.tmp_dir, file_name)
        test_logger = logger.Logger()
        test_logger.add_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, path=file_path)

        before_write_utc = datetime.utcnow()
        test_logger.info("The time should be in UTC")

        with open(file_path, "r") as log_file:
            log = log_file.read()
            try:
                time_in_file = datetime.strptime(log.split(logger.LogLevel.STRINGS[logger.LogLevel.INFO])[0].strip()
                                                 , u'%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                self.fail("Ensure timestamp follows ISO-8601 format + 'Z' for UTC")

            # If the time difference is > 5secs, there's a high probability that the time_in_file is in different TZ
            self.assertTrue((time_in_file-before_write_utc) <= timedelta(seconds=5))

    @patch("azurelinuxagent.common.logger.datetime")
    def test_logger_should_log_micro_seconds(self, mock_dt):
        # datetime.isoformat() skips ms if ms=0, this test ensures that ms is always set

        file_name = "test.log"
        file_path = os.path.join(self.tmp_dir, file_name)
        test_logger = logger.Logger()
        test_logger.add_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, path=file_path)

        ts_with_no_ms = datetime.utcnow().replace(microsecond=0)
        mock_dt.utcnow = MagicMock(return_value=ts_with_no_ms)

        test_logger.info("The time should contain milli-seconds")

        with open(file_path, "r") as log_file:
            log = log_file.read()
            try:
                time_in_file = datetime.strptime(log.split(logger.LogLevel.STRINGS[logger.LogLevel.INFO])[0].strip()
                                                 , u'%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                self.fail("Ensure timestamp follows ISO-8601 format and has micro seconds in it")

            self.assertEqual(ts_with_no_ms, time_in_file, "Timestamps dont match")

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

        self.assertEqual(5, mock.call_count)  # Only ERROR should be called.

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

    @patch("azurelinuxagent.common.logger.StdoutAppender.write")
    @patch("azurelinuxagent.common.logger.TelemetryAppender.write")
    @patch("azurelinuxagent.common.logger.ConsoleAppender.write")
    @patch("azurelinuxagent.common.logger.FileAppender.write")
    def test_add_appender(self, mock_file_write, mock_console_write, mock_telem_write, mock_stdout_write):
        lg = logger.Logger(logger.DEFAULT_LOGGER, "TestLogger1")

        lg.add_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, path=self.log_file)
        lg.add_appender(logger.AppenderType.TELEMETRY, logger.LogLevel.WARNING, path=add_log_event)
        lg.add_appender(logger.AppenderType.CONSOLE, logger.LogLevel.WARNING, path="/dev/null")
        lg.add_appender(logger.AppenderType.STDOUT, logger.LogLevel.WARNING, path=None)

        counter = 0
        for appender in lg.appenders:
            if isinstance(appender, logger.FileAppender):
                counter += 1
            elif isinstance(appender, logger.TelemetryAppender):
                counter += 1
            elif isinstance(appender, logger.ConsoleAppender):
                counter += 1
            elif isinstance(appender, logger.StdoutAppender):
                counter += 1

        # All 4 appenders should have been included.
        self.assertEqual(4, counter)

        # The write for all the loggers will get called, but the levels are honored in the individual write method
        # itself. Each appender has its own test to validate the writing of the log message for different levels.
        # For Reference: tests.common.test_logger.TestAppender

        lg.warn("Test Log")
        self.assertEqual(1, mock_file_write.call_count)
        self.assertEqual(1, mock_console_write.call_count)
        self.assertEqual(1, mock_telem_write.call_count)
        self.assertEqual(1, mock_stdout_write.call_count)

        lg.info("Test Log")
        self.assertEqual(2, mock_file_write.call_count)
        self.assertEqual(2, mock_console_write.call_count)
        self.assertEqual(2, mock_telem_write.call_count)
        self.assertEqual(2, mock_stdout_write.call_count)

        lg.error("Test Log")
        self.assertEqual(3, mock_file_write.call_count)
        self.assertEqual(3, mock_console_write.call_count)
        self.assertEqual(3, mock_telem_write.call_count)
        self.assertEqual(3, mock_stdout_write.call_count)

    @patch("azurelinuxagent.common.logger.StdoutAppender.write")
    @patch("azurelinuxagent.common.logger.TelemetryAppender.write")
    @patch("azurelinuxagent.common.logger.ConsoleAppender.write")
    @patch("azurelinuxagent.common.logger.FileAppender.write")
    def test_set_prefix(self, mock_file_write, mock_console_write, mock_telem_write, mock_stdout_write):
        lg = logger.Logger(logger.DEFAULT_LOGGER)
        prefix = "YoloLogger"

        lg.set_prefix(prefix)
        self.assertEquals(lg.prefix, prefix)

        lg.add_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, path=self.log_file)
        lg.add_appender(logger.AppenderType.TELEMETRY, logger.LogLevel.WARNING, path=add_log_event)
        lg.add_appender(logger.AppenderType.CONSOLE, logger.LogLevel.WARNING, path="/dev/null")
        lg.add_appender(logger.AppenderType.STDOUT, logger.LogLevel.WARNING, path=None)

        lg.error("Test Log")

        self.assertIn(prefix, mock_file_write.call_args[0][1])
        self.assertIn(prefix, mock_console_write.call_args[0][1])
        self.assertIn(prefix, mock_telem_write.call_args[0][1])
        self.assertIn(prefix, mock_stdout_write.call_args[0][1])

    @patch("azurelinuxagent.common.logger.StdoutAppender.write")
    @patch("azurelinuxagent.common.logger.TelemetryAppender.write")
    @patch("azurelinuxagent.common.logger.ConsoleAppender.write")
    @patch("azurelinuxagent.common.logger.FileAppender.write")
    def test_nested_logger(self, mock_file_write, mock_console_write, mock_telem_write, mock_stdout_write):
        """
        The purpose of this test is to see if the logger gets correctly created when passed it another logger and also
        if the appender correctly gets the messages logged. This is how the ExtHandlerInstance logger works.

        I initialize the default logger(logger), then create a new logger(lg) from it, and then log using logger & lg.
        See if both logs are flowing through or not.
        """

        parent_prefix = "ParentLogger"
        child_prefix = "ChildLogger"

        logger.add_logger_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, path=self.log_file)
        logger.add_logger_appender(logger.AppenderType.TELEMETRY, logger.LogLevel.WARNING, path=add_log_event)
        logger.add_logger_appender(logger.AppenderType.CONSOLE, logger.LogLevel.WARNING, path="/dev/null")
        logger.add_logger_appender(logger.AppenderType.STDOUT, logger.LogLevel.WARNING)
        logger.set_prefix(parent_prefix)

        lg = logger.Logger(logger.DEFAULT_LOGGER, child_prefix)

        lg.error("Test Log")
        self.assertEqual(1, mock_file_write.call_count)
        self.assertEqual(1, mock_console_write.call_count)
        self.assertEqual(1, mock_telem_write.call_count)
        self.assertEqual(1, mock_stdout_write.call_count)

        self.assertIn(child_prefix, mock_file_write.call_args[0][1])
        self.assertIn(child_prefix, mock_console_write.call_args[0][1])
        self.assertIn(child_prefix, mock_telem_write.call_args[0][1])
        self.assertIn(child_prefix, mock_stdout_write.call_args[0][1])

        logger.error("Test Log")
        self.assertEqual(2, mock_file_write.call_count)
        self.assertEqual(2, mock_console_write.call_count)
        self.assertEqual(2, mock_telem_write.call_count)
        self.assertEqual(2, mock_stdout_write.call_count)

        self.assertIn(parent_prefix, mock_file_write.call_args[0][1])
        self.assertIn(parent_prefix, mock_console_write.call_args[0][1])
        self.assertIn(parent_prefix, mock_telem_write.call_args[0][1])
        self.assertIn(parent_prefix, mock_stdout_write.call_args[0][1])

    @patch("azurelinuxagent.common.event.send_logs_to_telemetry", return_value=True)
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_telemetry_logger_add_log_event(self, mock_lib_dir, *_):
        mock_lib_dir.return_value = self.lib_dir
        __event_logger__.event_dir = self.event_dir
        prefix = "YoloLogger"

        logger.add_logger_appender(logger.AppenderType.TELEMETRY, logger.LogLevel.WARNING, path=add_log_event)
        logger.set_prefix(prefix)

        logger.warn('Test Log - Warning')

        event_files = os.listdir(__event_logger__.event_dir)
        self.assertEqual(1, len(event_files))

        log_file_event = os.path.join(__event_logger__.event_dir, event_files[0])
        try:
            with open(log_file_event) as logfile:
                logcontent = logfile.read()
                # Checking the contents of the event file.
                self.assertIn("Test Log - Warning", logcontent)
        except Exception as e:
            self.assertFalse(True, "The log file looks like it isn't correctly setup for this test. Take a look. "
                                   "{0}".format(e))

    @skip_if_predicate_true(lambda: True, "Enable this test when SEND_LOGS_TO_TELEMETRY is enabled")
    @patch("azurelinuxagent.common.logger.StdoutAppender.write")
    @patch("azurelinuxagent.common.logger.ConsoleAppender.write")
    @patch("azurelinuxagent.common.event.send_logs_to_telemetry", return_value=True)
    def test_telemetry_logger_verify_maximum_recursion_depths_doesnt_happen(self, *_):
        logger.add_logger_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, path="/dev/null")
        logger.add_logger_appender(logger.AppenderType.TELEMETRY, logger.LogLevel.WARNING, path=add_log_event)

        for i in range(MAX_NUMBER_OF_EVENTS):
            logger.warn('Test Log - {0} - 1 - Warning'.format(i))

        exception_caught = False

        # #1035 was caused due to too many files being written in an error condition. Adding even one more here broke
        # the camels back earlier - It would go into an infinite recursion as telemetry would call log, which in turn
        # would call telemetry, and so on.
        # The description of the fix is given in the comments @ azurelinuxagent.common.logger.Logger#log.write_log.
        try:
            for i in range(10):
                logger.warn('Test Log - {0} - 2 - Warning'.format(i))
        except RuntimeError:
            exception_caught = True

        self.assertFalse(exception_caught, msg="Caught a Runtime Error. This should not have been raised.")

    @skip_if_predicate_true(lambda: True, "Enable this test when SEND_LOGS_TO_TELEMETRY is enabled")
    @patch("azurelinuxagent.common.logger.StdoutAppender.write")
    @patch("azurelinuxagent.common.logger.ConsoleAppender.write")
    @patch("azurelinuxagent.common.event.send_logs_to_telemetry", return_value=True)
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_telemetry_logger_check_all_file_logs_written_when_events_gt_MAX_NUMBER_OF_EVENTS(self, mock_lib_dir, *_):
        mock_lib_dir.return_value = self.lib_dir
        __event_logger__.event_dir = self.event_dir
        no_of_log_statements = MAX_NUMBER_OF_EVENTS + 100
        exception_caught = False
        prefix = "YoloLogger"

        logger.add_logger_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, path=self.log_file)
        logger.add_logger_appender(logger.AppenderType.TELEMETRY, logger.LogLevel.WARNING, path=add_log_event)
        logger.set_prefix(prefix)

        # Calling logger.warn no_of_log_statements times would cause the telemetry appender to writing
        # 1000 events into the events dir, and then drop the remaining events. It should not generate the RuntimeError
        try:
            for i in range(0, no_of_log_statements):
                logger.warn('Test Log - {0} - 1 - Warning'.format(i))
        except RuntimeError:
            exception_caught = True

        self.assertFalse(exception_caught, msg="Caught a Runtime Error. This should not have been raised.")
        self.assertEqual(MAX_NUMBER_OF_EVENTS, len(os.listdir(__event_logger__.event_dir)))

        try:
            with open(self.log_file) as logfile:
                logcontent = logfile.readlines()

                # Checking the last log entry.
                # Subtracting 1 as range is exclusive of the upper bound
                self.assertIn("WARNING {1} Test Log - {0} - 1 - Warning".format(no_of_log_statements - 1, prefix),
                              logcontent[-1])

                # Checking the 1001st log entry. We know that 1001st entry would generate a PERIODIC message of too many
                # events, which should be captured in the log file as well.
                self.assertRegex(logcontent[1001], r"(.*WARNING\s*{0}\s*\[PERIODIC\]\s*Too many files under:.*{1}, "
                                                   r"current count\:\s*\d+,\s*removing oldest\s*.*)".format(prefix,
                                                                                                            self.event_dir))
        except Exception as e:
            self.assertFalse(True, "The log file looks like it isn't correctly setup for this test. "
                                   "Take a look. {0}".format(e))


class TestAppender(AgentTestCase):
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
        logger.DEFAULT_LOGGER.appenders *= 0

    @patch("azurelinuxagent.common.event.send_logs_to_telemetry", return_value=True)
    @patch("azurelinuxagent.common.logger.sys.stdout.write")
    @patch("azurelinuxagent.common.event.EventLogger.add_log_event")
    def test_no_appenders_added(self, mock_add_log_event, mock_sys_stdout, *_):
        # Validating no logs are written in any appender

        logger.verbose("test-verbose")
        logger.info("test-info")
        logger.warn("test-warn")
        logger.error("test-error")

        # Validating Console and File logs
        with open(self.log_file) as logfile:
            logcontent = logfile.readlines()
            self.assertEqual(0, len(logcontent))

        # Validating telemetry call
        self.assertEqual(0, mock_add_log_event.call_count)
        # Validating stdout call
        self.assertEqual(0, mock_sys_stdout.call_count)

    def test_console_appender(self):
        logger.add_logger_appender(logger.AppenderType.CONSOLE, logger.LogLevel.WARNING, path=self.log_file)

        logger.verbose("test-verbose")
        with open(self.log_file) as logfile:
            logcontent = logfile.readlines()
            # Levels are honored and Verbose should not be written.
            self.assertEqual(0, len(logcontent))

        logger.info("test-info")
        with open(self.log_file) as logfile:
            logcontent = logfile.readlines()
            # Levels are honored and Info should not be written.
            self.assertEqual(0, len(logcontent))

        # As console has a mode of w, it'll always only have 1 line only.
        logger.warn("test-warn")
        with open(self.log_file) as logfile:
            logcontent = logfile.readlines()
            self.assertEqual(1, len(logcontent))
            self.assertRegex(logcontent[0], r"(.*WARNING\s*test-warn.*)")

        logger.error("test-error")
        with open(self.log_file) as logfile:
            logcontent = logfile.readlines()
            # Levels are honored and Info, Verbose should not be written.
            self.assertEqual(1, len(logcontent))
            self.assertRegex(logcontent[0], r"(.*ERROR\s*test-error.*)")

    def test_file_appender(self):
        logger.add_logger_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, path=self.log_file)
        logger.verbose("test-verbose")
        logger.info("test-info")
        logger.warn("test-warn")
        logger.error("test-error")

        with open(self.log_file) as logfile:
            logcontent = logfile.readlines()
            # Levels are honored and Verbose should not be written.
            self.assertEqual(3, len(logcontent))
            self.assertRegex(logcontent[0], r"(.*INFO\s*test-info.*)")
            self.assertRegex(logcontent[1], r"(.*WARNING\s*test-warn.*)")
            self.assertRegex(logcontent[2], r"(.*ERROR\s*test-error.*)")

    @patch("azurelinuxagent.common.event.send_logs_to_telemetry", return_value=True)
    @patch("azurelinuxagent.common.event.EventLogger.add_log_event")
    def test_telemetry_appender(self, mock_add_log_event, *_):
        logger.add_logger_appender(logger.AppenderType.TELEMETRY, logger.LogLevel.WARNING, path=add_log_event)
        logger.verbose("test-verbose")
        logger.info("test-info")
        logger.warn("test-warn")
        logger.error("test-error")

        self.assertEqual(2, mock_add_log_event.call_count)

    @patch("azurelinuxagent.common.logger.sys.stdout.write")
    def test_stdout_appender(self, mock_sys_stdout):
        logger.add_logger_appender(logger.AppenderType.STDOUT, logger.LogLevel.ERROR)
        logger.verbose("test-verbose")
        logger.info("test-info")
        logger.warn("test-warn")
        logger.error("test-error")

        # Validating only test-error gets logged and not others.
        self.assertEqual(1, mock_sys_stdout.call_count)
