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

import unittest
from env import waagent


class TestWAAgentLogger(unittest.TestCase):
    
    def test_log_to_non_exists_dev(self):
        logger = waagent.Logger('/tmp/testlog', '/dev/nonexists')
        logger.Log("something")

    def test_log_to_non_exists_file(self):
        logger = waagent.Logger('/tmp/nonexists/testlog', '/tmp/testconsole')
        logger.Log("something")

    def test_log_unicode(self):
        logger = waagent.Logger('/tmp/testlog', '/tmp/testconsole')
        logger.Log(u"anything\u6211\u7231\u5201\u831C".encode("utf-8"))

if __name__ == '__main__':
    unittest.main()
