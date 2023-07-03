#!/usr/bin/env python
#
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

import unittest
import LogUtil as lu


class TestLogUtil(unittest.TestCase):    
    def test_tail(self):
        with open("/tmp/testtail", "w+") as F:
            F.write(u"abcdefghijklmnopqrstu\u6211vwxyz".encode("utf-8"))
        tail = lu.tail("/tmp/testtail", 2)
        self.assertEquals("yz", tail)

        tail = lu.tail("/tmp/testtail")
        self.assertEquals("abcdefghijklmnopqrstuvwxyz", tail)

if __name__ == '__main__':
    unittest.main()
