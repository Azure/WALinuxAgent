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
# Requires Python 2.4+ and Openssl 1.0+
#

from datetime import datetime

import azurelinuxagent.common.logger as logger

from tests.tools import *

_MSG = "This is our test logging message {0} {1}"
_DATA = ["arg1", "arg2"]

class TestLogger(AgentTestCase):

    @patch('azurelinuxagent.common.logger.Logger.info')
    def test_periodic_emits_if_not_previously_sent(self, mock_info):
        logger.reset_periodic()

        logger.periodic(logger.EVERY_DAY, _MSG, *_DATA)
        mock_info.assert_called_once()

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
