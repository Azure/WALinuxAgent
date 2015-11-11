# -*- coding: utf-8 -*-
# Copyright 2014 Microsoft Corporation
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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx

import tests.env
import tests.tools as tools
import uuid
import unittest
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text

class TestLogger(unittest.TestCase):

    def test_no_appender(self):
        #The logger won't throw exception even if no appender.
        _logger = logger.Logger()
        _logger.verb("Assert no exception")
        _logger.info("Assert no exception")
        _logger.warn("Assert no exception")
        _logger.error("Assert no exception")
        
    def test_logger_format(self):
        _logger = logger.Logger()
        _logger.info("This is an exception {0}", Exception("Test"))
        _logger.info("This is an number {0}", 0)
        _logger.info("This is an boolean {0}", True)
        _logger.verb("{0}")
        _logger.verb("{0} {1}", 0, 1)
        _logger.info("{0} {1}", 0, 1)
        _logger.warn("{0} {1}", 0, 1)
        _logger.error("{0} {1}", 0, 1)
        _logger.add_appender(logger.AppenderType.STDOUT, 
                             logger.LogLevel.INFO, None)
        _logger.info(u"啊哈this is a utf-8 {0}", u'呵呵')

    def test_file_appender(self):
        _logger = logger.Logger()
        _logger.add_appender(logger.AppenderType.FILE,
                                  logger.LogLevel.INFO,
                                  '/tmp/testlog')

        msg = text(uuid.uuid4())
        _logger.info("Test logger: {0}", msg)
        self.assertTrue(tools.simple_file_grep('/tmp/testlog', msg))

        msg = text(uuid.uuid4())
        _logger.verb("Verbose should not be logged: {0}", msg)
        self.assertFalse(tools.simple_file_grep('/tmp/testlog', msg))


    def test_concole_appender(self):
        _logger = logger.Logger()
        _logger.add_appender(logger.AppenderType.CONSOLE,
                                  logger.LogLevel.VERBOSE,
                                  '/tmp/testlog')

        msg = text(uuid.uuid4())
        _logger.info("Test logger: {0}", msg)
        self.assertTrue(tools.simple_file_grep('/tmp/testlog', msg))

        msg = text(uuid.uuid4())
        _logger.verb("Test logger: {0}", msg)
        self.assertFalse(tools.simple_file_grep('/tmp/testlog', msg))


    def test_log_to_non_exists_dev(self):
        _logger = logger.Logger()
        _logger.add_appender(logger.AppenderType.CONSOLE,
                                  logger.LogLevel.INFO,
                                  '/dev/nonexists')
        _logger.info("something")

    def test_log_to_non_exists_file(self):
        _logger = logger.Logger()
        _logger.add_appender(logger.AppenderType.FILE,
                                  logger.LogLevel.INFO,
                                  '/tmp/nonexists')
        _logger.info("something")



if __name__ == '__main__':
    unittest.main()
