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
from datetime import datetime

from mock import patch, MagicMock

from azurelinuxagent.common import logger
from azurelinuxagent.common.event import add_log_event
from tests.tools import AgentTestCase

_MSG_INFO = "This is our test info logging message {0} {1}"
_MSG_WARN = "This is our test warn logging message {0} {1}"
_MSG_ERROR = "This is our test error logging message {0} {1}"
_MSG_VERBOSE = "This is our test verbose logging message {0} {1}"
_DATA = ["arg1", "arg2"]


class TestLogger(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        logger.reset_periodic()

    def tearDown(self):
        AgentTestCase.tearDown(self)
        logger.reset_periodic()

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
        appender.write(logger.LogLevel.WARNING, "--unit-test--")

        mock.assert_called_once_with(logger.LogLevel.WARNING, "--unit-test--")

    @patch('azurelinuxagent.common.event.EventLogger.save_event')
    def test_telemetry_logger1(self, mock_save):
        appender = logger.TelemetryAppender(logger.LogLevel.WARNING, add_log_event)
        appender.write(logger.LogLevel.WARNING, "--unit-test--")

        self.assertEqual(1, mock_save.call_count)
        telemetry_json = json.loads(mock_save.call_args[0][0])

        self.assertEqual('FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F', telemetry_json['providerId'])
        self.assertEqual(7, telemetry_json['eventId'])

        self.assertEqual(12, len(telemetry_json['parameters']))
        for x in telemetry_json['parameters']:
            if x['name'] == 'EventName':
                self.assertEqual(x['value'], 'Log')

            elif x['name'] == 'CapabilityUsed':
                self.assertEqual(x['value'], 'WARNING')

            elif x['name'] == 'Context1':
                self.assertEqual(x['value'], '--unit-test--')

            elif x['name'] == 'Context2':
                self.assertEqual(x['value'], '')

            elif x['name'] == 'Context3':
                self.assertEqual(x['value'], '')
