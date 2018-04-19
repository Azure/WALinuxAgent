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

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.event import add_log_event
from azurelinuxagent.common.version import CURRENT_AGENT, CURRENT_VERSION

from tests.tools import *

_MSG = "This is our test logging message {0} {1}"
_DATA = ["arg1", "arg2"]


class TestLogger(AgentTestCase):
    @patch('azurelinuxagent.common.logger.Logger.info')
    def test_periodic_emits_if_not_previously_sent(self, mock_info):
        logger.reset_periodic()

        logger.periodic(logger.EVERY_DAY, _MSG, *_DATA)
        self.assertEqual(1, mock_info.call_count)

    @patch('azurelinuxagent.common.logger.Logger.info')
    def test_periodic_does_not_emit_if_previously_sent(self, mock_info):
        logger.reset_periodic()

        logger.periodic(logger.EVERY_DAY, _MSG, *_DATA)
        self.assertEqual(1, mock_info.call_count)

        logger.periodic(logger.EVERY_DAY, _MSG, *_DATA)
        self.assertEqual(1, mock_info.call_count)

    @patch('azurelinuxagent.common.logger.Logger.info')
    def test_periodic_emits_after_elapsed_delta(self, mock_info):
        logger.reset_periodic()

        logger.periodic(logger.EVERY_DAY, _MSG, *_DATA)
        self.assertEqual(1, mock_info.call_count)

        logger.periodic(logger.EVERY_DAY, _MSG, *_DATA)
        self.assertEqual(1, mock_info.call_count)

        logger.DEFAULT_LOGGER.periodic_messages[hash(_MSG)] = \
            datetime.now() - logger.EVERY_DAY - logger.EVERY_HOUR
        logger.periodic(logger.EVERY_DAY, _MSG, *_DATA)
        self.assertEqual(2, mock_info.call_count)

    @patch('azurelinuxagent.common.logger.Logger.info')
    def test_periodic_forwards_message_and_args(self, mock_info):
        logger.reset_periodic()

        logger.periodic(logger.EVERY_DAY, _MSG, *_DATA)
        mock_info.assert_called_once_with(_MSG, *_DATA)

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

        self.assertEqual(5, len(telemetry_json['parameters']))
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
